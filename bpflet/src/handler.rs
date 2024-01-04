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
use bpflet_api::v1::list_response::ListResult;
use crate::command::{Command, LoadArgs, Program, ProgramData, XdpProgram, TcProgram, TracepointProgram, KprobeProgram, UprobeProgram, UnloadArgs, GetArgs};

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

        let data = ProgramData::new_pre_load(
            bytecode,
            request.name,
            request.metadata,
            request.global_data,
            request.map_owner_id,
        )
            .map_err(|e| Status::aborted(format!("failed to create ProgramData: {e}")))?;

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
                    }) => Program::Xdp(
                    XdpProgram::new(
                        data,
                        priority,
                        iface,
                        XdpProceedOn::from_int32s(proceed_on)
                            .map_err(|_| Status::aborted("failed to parse proceed_on"))?,
                    )
                        .map_err(|e| Status::aborted(format!("failed to create xdpprogram: {e}")))?,
                ),
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
                    Program::Tc(
                        TcProgram::new(
                            data,
                            priority,
                            iface,
                            TcProceedOn::from_int32s(proceed_on)
                                .map_err(|_| Status::aborted("failed to parse proceed_on"))?,
                            direction,
                        ).map_err(|e| Status::aborted(format!("failed to create tcprogram: {e}")))?,
                    )
                }
                Info::TracepointAttachInfo(
                    TracepointAttachInfo { tracepoint, }
                ) => Program::Tracepoint(
                    TracepointProgram::new(data, tracepoint).map_err(|e| {
                        Status::aborted(format!("failed to create tcprogram: {e}"))
                    })?,
                ),
                Info::KprobeAttachInfo(
                    KprobeAttachInfo {
                        fn_name,
                        offset,
                        retprobe,
                        container_pid
                    }
                ) => Program::Kprobe(
                    KprobeProgram::new(data, fn_name, offset, retprobe, container_pid).map_err(
                        |e| Status::aborted(format!("failed to create kprobeprogram: {e}")),
                    )?,
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
                    UprobeProgram::new(data, fn_name, offset, target, retprobe, pid, container_pid)
                        .map_err(|e| {
                            Status::aborted(format!("failed to create uprobeprogram: {e}"))
                        })?,
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
        let mut reply = ListResponse { results: vec![] };

        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = Command::List { responder: resp_tx };

        // Send the GET request
        self.tx.send(cmd).await.unwrap();

        // Await the response
        match resp_rx.await {
            Ok(res) => match res {
                Ok(results) => {
                    for r in results {
                        // If filtering on Program Type, then make sure this program matches, else skip.
                        if let Some(p) = request.get_ref().program_type {
                            if p != r.kind() as u32 {
                                continue;
                            }
                        }

                        // filter based on list all flag
                        if let Program::Unsupported(_) = r {
                            if request.get_ref().bpflet_programs_only()
                                || !request.get_ref().match_metadata.is_empty()
                            {
                                continue;
                            }
                        } else {
                            // Filter on the input metadata field if provided
                            // let mut meta_match = true;
                            // for (key, value) in &request.get_ref().match_metadata {
                            //     if let Some(v) = r
                            //         .get_data()
                            //         .get_metadata()
                            //         .map_err(|e| {
                            //             Status::aborted(format!(
                            //                 "failed to get program metadata: {e}"
                            //             ))
                            //         })?
                            //         .get(key)
                            //     {
                            //         if *value != *v {
                            //             meta_match = false;
                            //             break;
                            //         }
                            //     } else {
                            //         meta_match = false;
                            //         break;
                            //     }
                            // }

                            // if !meta_match {
                            //     continue;
                            // }
                        }

                        // Populate the response with the Program Info and the Kernel Info.
                        let reply_entry = ListResult {
                            info: if let Program::Unsupported(_) = r {
                                None
                            } else {
                                Some((&r).try_into().map_err(|e| {
                                    Status::aborted(format!("failed to get program metadata: {e}"))
                                })?)
                            },
                            kernel_info: match (&r).try_into() {
                                Ok(i) => {
                                    // if let Program::Unsupported(_) = r {
                                    //     r.delete().map_err(|e| {
                                    //         Status::aborted(format!(
                                    //             "failed to get program metadata: {e}"
                                    //         ))
                                    //     })?;
                                    // };
                                    Ok(Some(i))
                                }
                                Err(e) => Err(Status::aborted(format!(
                                    "convert Program to GRPC kernel program info: {e}"
                                ))),
                            }?,
                        };
                        reply.results.push(reply_entry)
                    }
                    Ok(Response::new(reply))
                }
                Err(e) => {
                    warn!("Bpflet list error: {}", e);
                    Err(Status::aborted(format!("{e}")))
                }
            },
            Err(e) => {
                warn!("RPC list error: {}", e);
                Err(Status::aborted(format!("{e}")))
            }
        }
    }
    async fn pull_bytecode(&self, request: Request<PullBytecodeRequest>) -> Result<Response<PullBytecodeResponse>, Status> {
        todo!()
    }
    async fn get(&self, request: Request<GetRequest>) -> Result<Response<GetResponse>, Status> {
        let request = request.into_inner();
        let id = request.id;

        let (tx, rx) = oneshot::channel();
        let cmd = Command::Get(GetArgs {
            id,
            responder: tx,
        });

        // Send the GET request
        self.tx.send(cmd).await.unwrap();

        // Await the response
        match rx.await {
            Ok(res) => match res {
                Ok(program) => {
                    let reply_entry = GetResponse {
                        info: if let Program::Unsupported(_) = program {
                            None
                        } else {
                            Some((&program).try_into().map_err(|e| {
                                Status::aborted(format!("failed to get program metadata: {e}"))
                            })?)
                        },
                        kernel_info: match (&program).try_into() {
                            Ok(i) => {
                                if let Program::Unsupported(_) = program {
                                    program.delete().map_err(|e| {
                                        Status::aborted(format!(
                                            "failed to get program metadata: {e}"
                                        ))
                                    })?;
                                };
                                Ok(Some(i))
                            }
                            Err(e) => Err(Status::aborted(format!(
                                "convert Program to GRPC kernel program info: {e}"
                            ))),
                        }?,
                    };
                    Ok(Response::new(reply_entry))
                }
                Err(e) => {
                    warn!("Bpflet get error: {}", e);
                    Err(Status::aborted(format!("{e}")))
                }
            },
            Err(e) => {
                warn!("RPC get error: {}", e);
                Err(Status::aborted(format!("{e}")))
            }
        }
    }
}