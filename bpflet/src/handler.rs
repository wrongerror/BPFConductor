use log::warn;
use bpflet_api::{
    v1::{
        attach_info::Info, bpflet_server::Bpflet, bytecode_location::Location, GetRequest, GetResponse, KprobeAttachInfo, ListRequest,
        ListResponse, LoadRequest, LoadResponse, PullBytecodeRequest, PullBytecodeResponse,
        TcAttachInfo, TracepointAttachInfo, UnloadRequest, UnloadResponse, UprobeAttachInfo,
        XdpAttachInfo,
    },
    TcProceedOn, XdpProceedOn,
};
use tokio::sync::{mpsc::Sender, oneshot};
use tonic::{Request, Response, Status};
use crate::command::{Command, LoadArgs, Program, ProgramData, XdpProgram, TcProgram, TracepointProgram, KprobeProgram, UprobeProgram, UnloadArgs};

#[derive(Debug)]
pub struct ProgHandler {
    tx: Sender<Command>,
}

impl ProgHandler {
    pub(crate) fn new(tx: Sender<Command>) -> ProgHandler {
        ProgHandler { tx }
    }
}

#[tonic::async_trait]
impl Bpflet for ProgHandler {
    async fn load(&self, request: Request<LoadRequest>) -> Result<Response<LoadResponse>, Status> {
        let request = request.into_inner();
        let (tx, rx) = oneshot::channel();

        let bytecode = match request
            .bytecode
            .ok_or(Status::aborted("missing bytecode info"))?
            .location
            .ok_or(Status::aborted("missing bytecode location"))?
        {
            Location::Image(i) => crate::command::Location::Image(i.into()),
            Location::File(p) => crate::command::Location::File(p.into()),
        };

        let data = ProgramData::new(
            bytecode,
            request.name,
            request.metadata,
            request.global_data,
            request.map_owner_id,
        );

        let load_args = LoadArgs {
            program: match request
                .attach
                .ok_or(Status::aborted("missing attach info"))?
                .info
                .ok_or(Status::aborted("missing info"))?
            {
                Info::XdpAttachInfo(
                    XdpAttachInfo {
                        priority,
                        iface,
                        position: _,
                        proceed_on
                    }) => Program::Xdp(XdpProgram::new(
                    data,
                    priority,
                    iface,
                    XdpProceedOn::from_int32s(proceed_on)
                        .map_err(|_| Status::aborted("failed to parse proceed_on"))?,
                )),
                Info::TcAttachInfo(
                    TcAttachInfo {
                        priority,
                        iface,
                        position: _,
                        direction,
                        proceed_on,
                    }) => {
                    let direction = direction
                        .try_into()
                        .map_err(|_| Status::aborted("direction is not a string"))?;
                    Program::Tc(TcProgram::new(
                        data,
                        priority,
                        iface,
                        TcProceedOn::from_int32s(proceed_on)
                            .map_err(|_| Status::aborted("failed to parse proceed_on"))?,
                        direction,
                    ))
                }
                Info::TracepointAttachInfo(
                    TracepointAttachInfo { tracepoint, }
                ) => Program::Tracepoint(TracepointProgram::new(data, tracepoint)),
                Info::KprobeAttachInfo(
                    KprobeAttachInfo {
                        fn_name,
                        offset,
                        retprobe,
                        container_pid
                    }
                ) => Program::Kprobe(
                    KprobeProgram::new(
                        data,
                        fn_name,
                        offset,
                        retprobe,
                        container_pid,
                    )
                ),
                Info::UprobeAttachInfo(
                    UprobeAttachInfo {
                        fn_name,
                        offset,
                        target,
                        retprobe,
                        pid,
                        container_pid
                    }
                ) => Program::Uprobe(
                    UprobeProgram::new(
                        data,
                        fn_name,
                        offset,
                        target,
                        retprobe,
                        pid,
                        container_pid,
                    )
                ),
            },
            responder: tx,
        };

        self.tx.send(Command::Load(load_args)).await.unwrap();

        match rx.await {
            Ok(res) => match res {
                Ok(prog) => {
                    let response = LoadResponse {
                        info: match (&prog).try_into() {
                            Ok(i) => Some(i),
                            Err(_) => None
                        },
                        kernel_info: match (&prog).try_into() {
                            Ok(i) => Some(i),
                            Err(_) => None
                        },
                    };
                    Ok(Response::new(response))
                }
                Err(e) => {
                    warn!("Bpflet load error = {:#?}", e);
                    Err(Status::aborted(format!("{e}")))
                }
            }
            Err(e) => {
                warn!("RPC load error = {:#?}", e);
                Err(Status::aborted(format!("{e}")))
            }
        }

    }
    async fn unload(&self, request: Request<UnloadRequest>) -> Result<Response<UnloadResponse>, Status> {
        let reply = UnloadResponse {};
        let request = request.into_inner();
        let id = request.id;

        let (tx, rx) = oneshot::channel();
        let cmd = Command::Unload(UnloadArgs {
            id,
            responder: tx,
        });

        // Send the GET request
        self.tx.send(cmd).await.unwrap();

        // Await the response
        match rx.await {
            Ok(res) => match res {
                Ok(_) => Ok(Response::new(reply)),
                Err(e) => {
                    warn!("Bpflet unload error: {}", e);
                    Err(Status::aborted(format!("{e}")))
                }
            },
            Err(e) => {
                warn!("RPC unload error: {}", e);
                Err(Status::aborted(format!("{e}")))
            }
        }
    }
    async fn list(&self, request: Request<ListRequest>) -> Result<Response<ListResponse>, Status> {
        todo!()
    }
    async fn pull_bytecode(&self, request: Request<PullBytecodeRequest>) -> Result<Response<PullBytecodeResponse>, Status> {
        todo!()
    }
    async fn get(&self, request: Request<GetRequest>) -> Result<Response<GetResponse>, Status> {
        todo!()
    }
}