use std::cmp::PartialEq;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Error;
use async_trait::async_trait;
use aya::maps::{HashMap as AyaHashMap, Map, MapData};
use bpfman_lib::directories::RTDIR_FS_MAPS;
use log::debug;
use parking_lot::RwLock;
use prometheus_client::encoding::DescriptorEncoder;
use tokio::sync::broadcast;
use tokio::time;

use agent_api::v1::{BytecodeLocation, ProgramInfo};
use conn_tracer_common::{
    ConnectionKey, ConnectionStats, CONNECTION_ROLE_CLIENT, CONNECTION_ROLE_SERVER,
    CONNECTION_ROLE_UNKNOWN,
};

use crate::common::constants::DEFAULT_INTERVAL;
use crate::managers::cache::{CacheManager, Workload};
use crate::progs::types::{Program, ShutdownSignal};
use agent_api::{ParseError, ProgramState, ProgramType};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Connection {
    client: Arc<Workload>,
    server: Arc<Workload>,
    role: u32,
    server_port: u32,
}

#[derive(Debug)]
struct Inner {
    name: String,
    program_type: ProgramType,
    program_state: ProgramState,
    ebpf_maps: HashMap<String, u32>,
    metadata: HashMap<String, String>,
    current_conns_map: Option<AyaHashMap<MapData, ConnectionKey, ConnectionStats>>,
    past_conns_map: HashMap<Connection, u64>,
    cache_mgr: Option<CacheManager>,
}

impl Inner {
    fn new() -> Self {
        Self {
            name: "service_map".to_string(),
            program_type: ProgramType::Builtin,
            program_state: ProgramState::Uninitialized,
            ebpf_maps: HashMap::new(),
            metadata: HashMap::new(),
            current_conns_map: None,
            past_conns_map: HashMap::new(),
            cache_mgr: None,
        }
    }
}

#[derive(Debug)]
pub struct ServiceMap {
    inner: Arc<RwLock<Inner>>,
}

impl ServiceMap {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner::new())),
        }
    }

    async fn reset(&self) {
        let mut inner = self.inner.write();
        inner.program_state = ProgramState::Uninitialized;
        inner.current_conns_map = None;
        inner.past_conns_map.clear();
        inner.metadata.clear();
        inner.ebpf_maps.clear();
    }

    fn poll(&self) -> Result<HashMap<Connection, u64>, Error> {
        let inner = self.inner.read();
        let tcp_conns_map = inner
            .current_conns_map
            .as_ref()
            .ok_or(Error::msg("No current connections map"))?
            .clone();
        let past_conns_map = inner.past_conns_map.clone();
        let cache_mgr_ref = inner
            .cache_mgr
            .as_ref()
            .ok_or(Error::msg("No cache manager"))?
            .clone();

        let mut keys_to_remove = Vec::new();
        let mut current_conns: HashMap<Connection, u64> = HashMap::new();

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

            if let Ok(connection) = self.build_connection(key, &cache_mgr_ref) {
                current_conns
                    .entry(connection.clone())
                    .and_modify(|e| *e += stats.bytes_sent)
                    .or_insert(stats.bytes_sent);
            }
        }

        for (conn, bytes_sent) in past_conns_map.iter() {
            current_conns
                .entry(conn.clone())
                .and_modify(|e| *e += *bytes_sent)
                .or_insert(*bytes_sent);
        }

        // Release the read lock before removing inactive connections
        drop(inner);

        let mut inner = self.inner.write();
        for key in keys_to_remove {
            let _ = self.handle_inactive_connection(key, &mut inner, &cache_mgr_ref);
        }

        Ok(current_conns)
    }

    fn resolve_ip(&self, ip: u32, cache_mgr_ref: &CacheManager) -> Option<Arc<Workload>> {
        let ip_to_workload_lock = cache_mgr_ref.ip_to_workload.clone();
        let ip_to_workload = ip_to_workload_lock.read();
        let ip_addr = Ipv4Addr::from(ip);
        let ip_string = ip_addr.to_string();
        ip_to_workload.get(&ip_string).cloned()
    }

    fn build_connection(
        &self,
        key: ConnectionKey,
        cache_mgr_ref: &CacheManager,
    ) -> Result<Connection, Error> {
        let client_workload = self
            .resolve_ip(key.src_addr, cache_mgr_ref)
            .ok_or(Error::msg(format!(
                "Unknown IP: {}",
                Ipv4Addr::from(key.src_addr)
            )))?;
        let server_workload = self
            .resolve_ip(key.dest_addr, cache_mgr_ref)
            .ok_or(Error::msg(format!(
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

    fn handle_inactive_connection(
        &self,
        key: ConnectionKey,
        inner: &mut Inner,
        cache_mgr_ref: &CacheManager,
    ) -> Result<(), Error> {
        let throughput = match inner.current_conns_map.as_mut().unwrap().get(&key, 0) {
            Ok(stats) => stats.bytes_sent,
            Err(_) => 0,
        };
        inner.current_conns_map.as_mut().unwrap().remove(&key)?;
        let connection = self.build_connection(key, cache_mgr_ref)?;
        inner
            .past_conns_map
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

#[async_trait]
impl Program for ServiceMap {
    fn init(
        &self,
        metadata: HashMap<String, String>,
        cache_manager: CacheManager,
        maps: HashMap<String, u32>,
    ) -> Result<(), Error> {
        let mut inner = self.inner.write();
        inner.ebpf_maps = maps.clone();
        inner.metadata = metadata;
        inner.cache_mgr = Some(cache_manager);

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
        inner.current_conns_map = Some(tcp_conns_map);
        inner.program_state = ProgramState::Initialized;

        Ok(())
    }
    async fn start(
        &self,
        mut shutdown_rx: broadcast::Receiver<ShutdownSignal>,
    ) -> Result<(), Error> {
        self.set_state(ProgramState::Running);
        let metadata = self.get_metadata();
        let interval = metadata
            .get("interval")
            .and_then(|i| i.parse::<u64>().ok())
            .unwrap_or(DEFAULT_INTERVAL);
        let mut interval = time::interval(Duration::from_secs(interval));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = self.poll() {
                        debug!("Error polling: {:?}", e);
                        self.set_state(ProgramState::Failed);
                        return Err(e.into());
                    }
                }
                Ok(signal) = shutdown_rx.recv() => {
                    match signal {
                        ShutdownSignal::All => {
                            break;
                        },
                        ShutdownSignal::ProgramName(name) if name == self.get_name() => {
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
        self.reset().await;
        Ok(())
    }

    fn collect(&self, mut encoder: &DescriptorEncoder) -> Result<(), Error> {
        Ok(())
    }

    fn get_name(&self) -> String {
        let inner = self.inner.read();
        inner.name.clone()
    }

    fn get_state(&self) -> ProgramState {
        let inner = self.inner.read();
        inner.program_state.clone()
    }

    fn set_state(&self, state: ProgramState) {
        let mut inner = self.inner.write();
        inner.program_state = state
    }

    fn get_type(&self) -> ProgramType {
        let inner = self.inner.read();
        inner.program_type.clone()
    }

    fn get_metadata(&self) -> HashMap<String, String> {
        let inner = self.inner.read();
        inner.metadata.clone()
    }

    fn set_metadata(&self, metadata: HashMap<String, String>) {
        let mut inner = self.inner.write();
        inner.metadata = metadata;
    }

    fn get_program_info(&self) -> Result<ProgramInfo, ParseError> {
        Ok(ProgramInfo {
            name: self.get_name(),
            program_type: self.get_type().try_into()?,
            state: self.get_state().clone().try_into()?,
            bytecode: None,
            ebpf_maps: self.inner.read().ebpf_maps.clone(),
            metadata: self.get_metadata(),
        })
    }
}
