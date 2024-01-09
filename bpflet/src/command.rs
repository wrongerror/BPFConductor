use tokio::sync::oneshot;

use crate::{
    errors::BpfletError,
    oci::manager::BytecodeImage,
    program::program::Program
};

/// Provided by the requester and used by the manager task to send
/// the command response back to the requester.
type Responder<T> = oneshot::Sender<T>;

/// Multiple different commands are multiplexed over a single channel.
#[derive(Debug)]
pub(crate) enum Command {
    /// Load a program
    Load(LoadArgs),
    Unload(UnloadArgs),
    List {
        responder: Responder<Result<Vec<Program>, BpfletError>>,
    },
    Get(GetArgs),
    PullBytecode(PullBytecodeArgs),
}

#[derive(Debug)]
pub(crate) struct LoadArgs {
    pub(crate) program: Program,
    pub(crate) responder: Responder<Result<Program, BpfletError>>,
}

#[derive(Debug)]
pub(crate) struct UnloadArgs {
    pub(crate) id: u32,
    pub(crate) responder: Responder<Result<(), BpfletError>>,
}

#[derive(Debug)]
pub(crate) struct GetArgs {
    pub(crate) id: u32,
    pub(crate) responder: Responder<Result<Program, BpfletError>>,
}

#[derive(Debug)]
pub(crate) struct PullBytecodeArgs {
    pub(crate) image: BytecodeImage,
    pub(crate) responder: Responder<Result<(), BpfletError>>,
}
