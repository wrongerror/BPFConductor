use std::collections::HashMap;
use std::fs::remove_file;
use std::path::Path;
use std::sync::Arc;

use bpfman_api::v1::bpfman_client::BpfmanClient;
use bpfman_lib::utils::set_file_permissions;
use log::{debug, error, info};
use tokio::net::UnixListener;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::{Channel, Server};
use tonic::{Request, Response, Status};

use agent_api::v1::agent_server::{Agent, AgentServer};
use agent_api::v1::{
    GetRequest, GetResponse, ListRequest, ListResponse, LoadRequest, LoadResponse,
    PullBytecodeRequest, PullBytecodeResponse, UnloadRequest, UnloadResponse,
};

use crate::common::constants::directories::SOCK_MODE;
use crate::common::constants::{PROG_TYPE_BUILTIN, PROG_TYPE_WASM};
use crate::config::Config;
use crate::managers::prog::ProgManager;

pub struct AgentService {
    pub config: Config,
    pub prog_manager: ProgManager,
    pub bpf_client: BpfmanClient<Channel>,
}

impl AgentService {
    pub(crate) fn new(
        config: Config,
        prog_manager: ProgManager,
        bpf_client: BpfmanClient<Channel>,
    ) -> Self {
        Self {
            config,
            prog_manager,
            bpf_client,
        }
    }

    async fn get_prog_ids_for_maps(
        &self,
        map_to_prog_name: HashMap<String, String>,
    ) -> Result<HashMap<String, u32>, anyhow::Error> {
        let req = Request::new(bpfman_api::v1::ListRequest {
            program_type: None,
            bpfman_programs_only: None,
            match_metadata: Default::default(),
        });
        let mut bpf_client = self.bpf_client.clone();
        let response = bpf_client.list(req).await?.into_inner();
        let loaded_ebpf_progs = response
            .results
            .iter()
            .filter_map(|prog| prog.kernel_info.as_ref())
            .map(|info| (info.name.clone(), info.id))
            .collect::<HashMap<String, u32>>();

        let mut map_to_prog_id = HashMap::new();
        for (map_name, prog_name) in map_to_prog_name {
            let prog_id = loaded_ebpf_progs.get(&prog_name).ok_or(anyhow::anyhow!(
                "Required eBPF program {} not loaded",
                prog_name
            ))?;
            map_to_prog_id.insert(map_name, *prog_id);
        }
        Ok(map_to_prog_id)
    }
}

#[tonic::async_trait]
impl Agent for AgentService {
    async fn load(&self, request: Request<LoadRequest>) -> Result<Response<LoadResponse>, Status> {
        let request = request.into_inner();

        let prog = match request.program_type {
            PROG_TYPE_BUILTIN => {
                let prog = self
                    .prog_manager
                    .registry_manager
                    .builtin
                    .get(request.name.clone())
                    .ok_or(Status::aborted("Program not found in registry"))?;
                prog
            }
            PROG_TYPE_WASM => {
                todo!("WASM programs are not supported yet")
            }
            _ => {
                return Err(Status::aborted("Invalid program type"));
            }
        };

        let map_to_prog_id = self
            .get_prog_ids_for_maps(request.ebpf_maps)
            .await
            .map_err(|e| Status::aborted(format!("Failed to get eBPF program IDs: {:?}", e)))?;

        prog.set_metadata(request.metadata.clone());
        prog.init(self.prog_manager.cache_manager.clone(), map_to_prog_id)
            .map_err(|e| Status::aborted(format!("Failed to init program: {:?}", e)))?;

        let p = Arc::clone(&prog);
        self.prog_manager
            .load(p)
            .await
            .map_err(|e| Status::aborted(format!("Failed to load program: {:?}", e)))?;

        let prog_info = prog
            .get_program_info()
            .map_err(|e| Status::aborted(format!("Failed to get program info: {:?}", e)))?;

        Ok(Response::new(LoadResponse {
            info: Some(prog_info),
        }))
    }

    async fn unload(
        &self,
        request: Request<UnloadRequest>,
    ) -> Result<Response<UnloadResponse>, Status> {
        todo!()
    }

    async fn list(&self, request: Request<ListRequest>) -> Result<Response<ListResponse>, Status> {
        todo!()
    }

    async fn pull_bytecode(
        &self,
        request: Request<PullBytecodeRequest>,
    ) -> Result<Response<PullBytecodeResponse>, Status> {
        todo!()
    }

    async fn get(&self, request: Request<GetRequest>) -> Result<Response<GetResponse>, Status> {
        todo!()
    }
}

pub async fn serve(
    path: &Path,
    service: AgentServer<AgentService>,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> anyhow::Result<JoinHandle<()>> {
    // Listen on Unix socket
    if path.exists() {
        // Attempt to remove the socket, since bind fails if it exists
        remove_file(path)?;
    }

    let uds = UnixListener::bind(path)?;
    let uds_stream = UnixListenerStream::new(uds);
    // Always set the file permissions of our listening socket.
    set_file_permissions(path, SOCK_MODE);

    let serve = Server::builder()
        .add_service(service)
        .serve_with_incoming_shutdown(uds_stream, async move {
            match shutdown_rx.recv().await {
                Ok(()) => debug!("Unix Socket: Received shutdown signal"),
                Err(e) => error!("Error receiving shutdown signal {:?}", e),
            };
        });
    let socket_path = path.to_path_buf();
    Ok(tokio::spawn(async move {
        info!("Listening on {}", socket_path.to_path_buf().display());
        if let Err(e) = serve.await {
            error!("Error = {e:?}");
        }
        info!(
            "Shutdown Unix Handler {}",
            socket_path.to_path_buf().display()
        );
    }))
}
