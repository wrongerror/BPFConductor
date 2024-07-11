use std::collections::HashMap;
use std::fmt;
use std::fmt::Debug;
use std::path::Path;
use std::sync::Arc;

use anyhow::Error;
use async_trait::async_trait;
use aya::maps::{AsyncPerfEventArray, Map, MapData};
use aya::util::online_cpus;
use bytes::BytesMut;
use lazy_static::lazy_static;
use log::{debug, info};
use parking_lot::RwLock;
use prometheus_client::encoding::DescriptorEncoder;
use tokio::sync::broadcast::Receiver;
use tokio::task;
use tokio::task::{JoinHandle, JoinSet};

use agent_api::{ProgramState, ProgramType};
use agent_api::v1::ProgramInfo;
use socket_tracer_common::{ConnStatsEvent, SocketControlEvent, SocketDataEvent};

use crate::common::constants::directories::RTDIR_FS_MAPS;
use crate::managers::cache::CacheManager;
use crate::progs::socket_tracer::utils::{convert_dst_to_socket_addr, convert_src_to_socket_addr};
use crate::progs::types::{Program, ProgramData, ShutdownSignal};

use super::tracker_manager::ConnTrackerManager;

pub(crate) struct Inner {
    data: ProgramData,
    cache_mgr: Option<CacheManager>,
    conn_mgr: Option<ConnTrackerManager>,
    ctrl_events: Option<AsyncPerfEventArray<MapData>>,
    data_events: Option<AsyncPerfEventArray<MapData>>,
    conn_events: Option<AsyncPerfEventArray<MapData>>,
}

lazy_static! {
    static ref CONN_TRACKER_MANAGER: ConnTrackerManager = ConnTrackerManager::new();
}

impl Inner {
    fn new(name: &str) -> Self {
        Self {
            data: ProgramData::new(name),
            cache_mgr: None,
            conn_mgr: None,
            ctrl_events: None,
            data_events: None,
            conn_events: None,
        }
    }
}

impl Debug for Inner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Inner").field("data", &self.data).finish()
    }
}

#[derive(Debug)]
pub struct SocketTracer {
    inner: Arc<RwLock<Inner>>,
}

impl SocketTracer {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner::new("socket_tracer"))),
        }
    }

    fn init_perf_event_array(
        &self,
        name: &str,
        prog_id: u32,
    ) -> anyhow::Result<AsyncPerfEventArray<MapData>> {
        let bpf_map_path = Path::new(RTDIR_FS_MAPS).join(format!("{}/{}", prog_id, name));
        let map_data = MapData::from_pin(bpf_map_path).map_err(|e| {
            anyhow::anyhow!("Failed to find map at path {:?}, error: {:?}", name, e)
        })?;
        let map: Map = Map::PerfEventArray(map_data)
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to convert map"))?;
        let perf_event: AsyncPerfEventArray<MapData> = AsyncPerfEventArray::try_from(map)?;

        Ok(perf_event)
    }

    fn handle_ctrl_event(event: &SocketControlEvent) {
        let local_addr = convert_src_to_socket_addr(&event);
        // if local_addr.is_none() {
        //     return;
        // }
        let remote_addr = convert_dst_to_socket_addr(&event);
        // if remote_addr.is_none() {
        //     return;
        // }
        info!(
            "SocketControlEvent: tgid {:?}, event type {:?}, sa_family: {:?}, local addr {:?}, remote addr {:?}, source func {:?}, read_bytes {:?}, write_bytes {:?}",
            event.id.uid.tgid,
            event.event_type,
            event.sa_family,
            local_addr,
            remote_addr,
            event.source_function,
            event.read_bytes,
            event.write_bytes
        );
        let tracker = CONN_TRACKER_MANAGER.get_or_create_conn_tracker(event.id);
        let _ = tracker.add_event(event);
    }

    fn handle_conn_stats_event(event: &ConnStatsEvent) {
        // info!("ConnStatsEvent: {:?}", event.id);
    }

    fn handle_data_event(event: &SocketDataEvent) {
        // info!("SocketDataEvent: {:?}", event.inner.id);
    }

    async fn process_event<T>(
        &self,
        perf_event: &mut AsyncPerfEventArray<MapData>,
        mut shutdown_rx: Receiver<ShutdownSignal>,
        handler: Arc<dyn Fn(&T) + Send + Sync>,
    ) -> anyhow::Result<Vec<JoinHandle<()>>>
    where
        T: 'static + Send,
    {
        let cpus = online_cpus().unwrap();
        let num_cpus = cpus.len();
        let mut join_handles = Vec::new();
        let name = self.get_name();

        for cpu in cpus {
            let mut buf = perf_event.open(cpu, None).unwrap();
            let handler = handler.clone();
            let mut shutdown_rx_per_cpu = shutdown_rx.resubscribe();

            let join_handle = task::spawn(async move {
                let mut buffers = (0..num_cpus)
                    .map(|_| BytesMut::with_capacity(9000))
                    .collect::<Vec<_>>();

                loop {
                    tokio::select! {
                        events = buf.read_events(&mut buffers) => {
                            let events = events.unwrap();
                            for i in 0..events.read {
                                let buf = &mut buffers[i];
                                let event = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const T) };
                                handler(&event);
                            }
                        }
                        Ok(signal) = shutdown_rx_per_cpu.recv() => {
                            match signal {
                                ShutdownSignal::All => {
                                    break
                                },
                                ShutdownSignal::ProgramName(name) if name == name => {
                                    break
                                },
                                _ => {}
                            }
                        }
                    }
                }
            });
            join_handles.push(join_handle);
        }

        Ok(join_handles)
    }

    pub async fn process_events(
        &self,
        shutdown_rx: Receiver<ShutdownSignal>,
    ) -> anyhow::Result<Vec<JoinHandle<()>>> {
        let mut join_handles = Vec::new();

        let ctrl_events = {
            let mut inner = self.inner.write();
            inner.ctrl_events.take()
        };

        if let Some(mut ctrl_events) = ctrl_events {
            let mut ctrl_handles = self
                .process_event(
                    &mut ctrl_events,
                    shutdown_rx.resubscribe(),
                    Arc::new(|e: &SocketControlEvent| {
                        SocketTracer::handle_ctrl_event(e);
                    }),
                )
                .await?;
            join_handles.append(&mut ctrl_handles);
        }

        let data_events = {
            let mut inner = self.inner.write();
            inner.data_events.take()
        };

        if let Some(mut data_events) = data_events {
            let mut data_handles = self
                .process_event(
                    &mut data_events,
                    shutdown_rx.resubscribe(),
                    Arc::new(|e: &SocketDataEvent| {
                        SocketTracer::handle_data_event(e);
                    }),
                )
                .await?;
            join_handles.append(&mut data_handles);
        }

        let conn_events = {
            let mut inner = self.inner.write();
            inner.conn_events.take()
        };

        if let Some(mut conn_events) = conn_events {
            let mut stat_handles = self
                .process_event(
                    &mut conn_events,
                    shutdown_rx.resubscribe(),
                    Arc::new(|e: &ConnStatsEvent| SocketTracer::handle_conn_stats_event(e)),
                )
                .await?;
            join_handles.append(&mut stat_handles);
        }

        Ok(join_handles)
    }
}

#[async_trait]
impl Program for SocketTracer {
    async fn init(
        &self,
        metadata: HashMap<String, String>,
        cache_manager: CacheManager,
        maps: HashMap<String, u32>,
    ) -> Result<(), Error> {
        let mut inner = self.inner.write();
        inner.data.metadata = metadata.clone();
        inner.data.ebpf_maps = maps.clone();
        inner.cache_mgr = Some(cache_manager);

        if let Some(prog_id) = maps.get("sk_ctrl_events") {
            inner.ctrl_events =
                Some(self.init_perf_event_array("sk_ctrl_events", prog_id.clone())?);
        }

        if let Some(prog_id) = maps.get("sk_data_events") {
            inner.data_events =
                Some(self.init_perf_event_array("sk_data_events", prog_id.clone())?);
        }

        if let Some(prog_id) = maps.get("conn_stat_events") {
            inner.conn_events =
                Some(self.init_perf_event_array("conn_stat_events", prog_id.clone())?);
        }

        Ok(())
    }

    async fn start(&self, mut shutdown_rx: Receiver<ShutdownSignal>) -> Result<(), Error> {
        let join_handles = self.process_events(shutdown_rx.resubscribe()).await?;

        let mut join_set = JoinSet::new();

        for handle in join_handles {
            join_set.spawn(handle);
        }

        loop {
            tokio::select! {
                _ = async {
                    while let Some(result) = join_set.join_next().await {
                        match result {
                            Ok(_) => debug!("Task completed successfully."),
                            Err(e) => debug!("Task failed: {:?}", e),
                        }
                    }
                } => { break }
            }
        }

        Ok(())
    }

    async fn stop(&self) -> Result<(), Error> {
        let mut inner = self.inner.write();
        inner.data.metadata.clear();
        inner.data.ebpf_maps.clear();
        inner.ctrl_events = None;
        inner.data_events = None;
        inner.conn_events = None;
        inner.cache_mgr = None;
        inner.conn_mgr = None;

        Ok(())
    }

    fn collect(&self, encoder: &mut DescriptorEncoder) -> Result<(), Error> {
        todo!()
    }

    fn get_name(&self) -> String {
        let inner = self.inner.read();
        inner.data.name.clone()
    }

    fn get_state(&self) -> ProgramState {
        let inner = self.inner.read();
        inner.data.program_state.clone()
    }

    fn set_state(&self, state: ProgramState) {
        let mut inner = self.inner.write();
        inner.data.program_state = state
    }

    fn get_type(&self) -> ProgramType {
        let inner = self.inner.read();
        inner.data.program_type.clone()
    }

    fn get_metadata(&self) -> HashMap<String, String> {
        let inner = self.inner.read();
        inner.data.metadata.clone()
    }

    fn set_metadata(&self, metadata: HashMap<String, String>) {
        let mut inner = self.inner.write();
        inner.data.metadata = metadata
    }

    fn get_program_info(&self) -> Result<ProgramInfo, Error> {
        let program_type: u32 = self.get_type().try_into()?;
        let state: u32 = self.get_state().clone().try_into()?;
        let ebpf_maps = self.inner.read().data.ebpf_maps.clone();
        Ok(ProgramInfo {
            name: self.get_name(),
            program_type,
            state,
            bytecode: None,
            ebpf_maps,
            metadata: self.get_metadata(),
        })
    }
}
