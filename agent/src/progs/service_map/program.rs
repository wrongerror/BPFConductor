use std::cmp::PartialEq;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Error;
use async_trait::async_trait;
use aya::maps::{HashMap as AyaHashMap, Map, MapData};
use bpfman_lib::directories::RTDIR_FS_MAPS;
use log::{debug, info};
use nix::libc::NOEXPR;
use prometheus_client::encoding::DescriptorEncoder;
use tokio::sync::{broadcast, oneshot};
use tokio::time;

use agent_api::v1::{BytecodeLocation, ProgramInfo};
use conn_tracer_common::{
    ConnectionKey, ConnectionStats, CONNECTION_ROLE_CLIENT, CONNECTION_ROLE_SERVER,
    CONNECTION_ROLE_UNKNOWN,
};

use crate::common::constants::METRICS_INTERVAL;
use crate::common::types::{ProgramState, ProgramType};
use crate::errors::ParseError;
use crate::managers::cache::{CacheManager, Workload};
use crate::progs::types::{Program, ShutdownSignal};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Connection {
    client: Arc<Workload>,
    server: Arc<Workload>,
    role: u32,
    server_port: u32,
}

type ConnectionMap = AyaHashMap<MapData, ConnectionKey, ConnectionStats>;

#[derive(Debug)]
struct Inner {
    name: String,
    program_type: ProgramType,
    program_state: ProgramState,
    metadata: HashMap<String, String>,
    current_conns_map: Option<Arc<Mutex<ConnectionMap>>>,
    past_conns_map: Arc<Mutex<HashMap<Connection, u64>>>,
    cache_mgr: Option<CacheManager>,
}

impl Inner {
    fn new() -> Self {
        Self {
            name: "service_map".to_string(),
            program_type: ProgramType::Builtin,
            program_state: ProgramState::Uninitialized,
            metadata: HashMap::new(),
            current_conns_map: None,
            past_conns_map: Arc::new(Mutex::new(HashMap::new())),
            cache_mgr: None,
        }
    }

    fn init(
        &mut self,
        cache_manager: CacheManager,
        maps: HashMap<String, u32>,
    ) -> Result<(), Error> {
        if self.program_state == ProgramState::Uninitialized {
            self.cache_mgr = Some(cache_manager);

            let map_name = "CONNECTIONS";
            let prog_id = maps.get(map_name).ok_or(anyhow::anyhow!(
                "No map named CONNECTIONS in the provided maps"
            ))?;
            let bpfman_maps = Path::new(RTDIR_FS_MAPS);
            if !bpfman_maps.exists() {
                return Err(anyhow::anyhow!("{} does not exist", RTDIR_FS_MAPS));
            }

            let map_pin_path = bpfman_maps.join(format!("{}/{}", prog_id, map_name));
            let map_data = MapData::from_pin(map_pin_path)
                .map_err(|_| anyhow::anyhow!("No maps named CONNECTIONS"))?;
            let tcp_conns_map: AyaHashMap<MapData, ConnectionKey, ConnectionStats> =
                Map::HashMap(map_data)
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Failed to convert map"))?;
            self.current_conns_map = Some(Arc::new(Mutex::new(tcp_conns_map)));
            self.program_state = ProgramState::Initialized;
        }

        Ok(())
    }

    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_state(&self) -> ProgramState {
        self.program_state.clone()
    }

    fn get_type(&self) -> ProgramType {
        self.program_type.clone()
    }

    fn get_metadata(&self) -> HashMap<String, String> {
        self.metadata.clone()
    }

    fn get_program_info(&self) -> Result<ProgramInfo, ParseError> {
        Ok(ProgramInfo {
            name: self.name.clone(),
            program_type: self.program_type.clone().try_into()?,
            state: self.program_state.clone().try_into()?,
            bytecode: None,
            metadata: self.metadata.clone(),
        })
    }

    fn set_metadata(&mut self, metadata: HashMap<String, String>) {
        self.metadata = metadata;
    }

    fn poll(&mut self) -> Result<HashMap<Connection, u64>, Error> {
        let mut keys_to_remove = Vec::new();
        let mut current_conns: HashMap<Connection, u64> = HashMap::new();

        {
            let current_conns_map = self.current_conns_map.clone().unwrap();
            let tcp_conns_map = current_conns_map.lock().unwrap();
            for item in tcp_conns_map.iter() {
                let (key, stats) = item?;
                if stats.is_active != 1 {
                    keys_to_remove.push(key);
                    continue;
                }
                if key.src_addr == key.dest_addr || self.is_loopback_address(key.dest_addr) {
                    continue;
                }
                if key.role == CONNECTION_ROLE_UNKNOWN {
                    continue;
                }

                if let Ok(connection) = self.build_connection(key) {
                    current_conns
                        .entry(connection.clone())
                        .and_modify(|e| *e += stats.bytes_sent)
                        .or_insert(stats.bytes_sent);
                }
            }

            let past_conns_map = self.past_conns_map.lock().unwrap();
            for (conn, bytes_sent) in past_conns_map.iter() {
                current_conns
                    .entry(conn.clone())
                    .and_modify(|e| *e += *bytes_sent)
                    .or_insert(*bytes_sent);
            }
        }

        for key in keys_to_remove {
            let _ = self.handle_inactive_connection(key);
        }

        Ok(current_conns)
    }

    fn resolve_ip(&self, ip: u32) -> Option<Arc<Workload>> {
        let ip_to_workload = self
            .cache_mgr
            .as_ref()
            .unwrap()
            .ip_to_workload
            .read()
            .unwrap();
        let ip_addr = Ipv4Addr::from(ip);
        let ip_string = ip_addr.to_string();
        ip_to_workload.get(&ip_string).map(|w| w.clone())
    }

    fn build_connection(&self, key: ConnectionKey) -> Result<Connection, Error> {
        let client_workload = self.resolve_ip(key.src_addr).ok_or(Error::msg(format!(
            "Unknown IP: {}",
            Ipv4Addr::from(key.src_addr)
        )))?;
        let server_workload = self.resolve_ip(key.dest_addr).ok_or(Error::msg(format!(
            "Unknown IP: {}",
            Ipv4Addr::from(key.dest_addr)
        )))?;

        let (client, server, port) = match key.role {
            CONNECTION_ROLE_CLIENT => (client_workload, server_workload, key.dest_port),
            CONNECTION_ROLE_SERVER => (server_workload, client_workload, key.src_port),
            _ => return Err(Error::msg("Unknown connection role")),
        };

        Ok(Connection {
            client,
            server,
            role: key.role,
            server_port: port,
        })
    }

    fn handle_inactive_connection(&mut self, key: ConnectionKey) -> Result<(), Error> {
        let tcp_conns_map = self.current_conns_map.clone().unwrap();
        let mut tcp_conns_map = tcp_conns_map.lock().unwrap();
        let throughput = match tcp_conns_map.get(&key, 0) {
            Ok(stats) => stats.bytes_sent,
            Err(_) => 0,
        };

        tcp_conns_map.remove(&key)?;

        let mut past_conns_map = self.past_conns_map.lock().unwrap();
        let connection = self.build_connection(key)?;
        past_conns_map
            .entry(connection)
            .and_modify(|e| *e += throughput)
            .or_insert(throughput);
        Ok(())
    }

    fn is_loopback_address(&self, addr: u32) -> bool {
        let ip_addr = Ipv4Addr::from(addr);
        ip_addr.is_loopback()
    }
}

#[derive(Debug)]
pub struct ServiceMap {
    inner: Arc<Mutex<Inner>>,
}

impl ServiceMap {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::new())),
        }
    }
}

#[async_trait]
impl Program for ServiceMap {
    fn init(&self, cache_manager: CacheManager, maps: HashMap<String, u32>) -> Result<(), Error> {
        let mut inner = self.inner.lock().unwrap();
        inner.init(cache_manager, maps)
    }
    async fn start(
        &self,
        mut shutdown_rx: broadcast::Receiver<ShutdownSignal>,
    ) -> Result<(), Error> {
        let mut interval = time::interval(Duration::from_secs(METRICS_INTERVAL));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let mut inner = self.inner.lock().unwrap();
                    if let Err(e) = inner.poll() {
                        debug!("Error polling: {:?}", e);
                    }
                }
                Ok(signal) = shutdown_rx.recv() => {
                match signal {
                    ShutdownSignal::All => {
                        info!("Shutting down all programs");
                        break;
                    },
                    ShutdownSignal::ProgramName(name) if name == self.get_name() => {
                        info!("Stopping program {}", self.get_name());
                        break;
                    },
                    _ => {}
                }
            },
            }
        }
        Ok(())
    }

    async fn stop(&self) -> Result<(), Error> {
        Ok(())
    }

    fn collect(&self, mut encoder: &DescriptorEncoder) -> Result<(), Error> {
        Ok(())
    }

    fn get_name(&self) -> String {
        let inner = self.inner.lock().unwrap();
        inner.get_name()
    }

    fn get_state(&self) -> ProgramState {
        let inner = self.inner.lock().unwrap();
        inner.get_state()
    }

    fn get_type(&self) -> ProgramType {
        let inner = self.inner.lock().unwrap();
        inner.get_type()
    }

    fn get_metadata(&self) -> HashMap<String, String> {
        let inner = self.inner.lock().unwrap();
        inner.get_metadata()
    }

    fn get_program_info(&self) -> Result<ProgramInfo, ParseError> {
        let inner = self.inner.lock().unwrap();
        inner.get_program_info()
    }

    fn set_metadata(&self, metadata: HashMap<String, String>) {
        let mut inner = self.inner.lock().unwrap();
        inner.set_metadata(metadata)
    }
}
