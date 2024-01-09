use tokio::sync::mpsc::Sender;
use tokio::sync::oneshot;
use serde::{Deserialize, Serialize};
use bpflet_api::ParseError;
use std::fmt;
use crate::errors::BpfletError;
use crate::oci::manager::{BytecodeImage, Command as ImageManagerCommand};

pub(crate) mod xdp;
pub(crate) mod tc;
pub(crate) mod kprobe;
pub(crate) mod uprobe;
pub(crate) mod program;
pub(crate) mod tracepoint;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) enum Location {
    Image(BytecodeImage),
    File(String),
}

impl Location {
    async fn get_program_bytes(
        &self,
        image_manager: Sender<ImageManagerCommand>,
    ) -> Result<(Vec<u8>, String), BpfletError> {
        match self {
            Location::File(l) => Ok((crate::helper::read(l).await?, "".to_owned())),
            Location::Image(l) => {
                let (tx, rx) = oneshot::channel();
                image_manager
                    .send(ImageManagerCommand::Pull {
                        image: l.image_url.clone(),
                        pull_policy: l.image_pull_policy.clone(),
                        username: l.username.clone(),
                        password: l.password.clone(),
                        resp: tx,
                    })
                    .await
                    .map_err(|e| BpfletError::RpcSendError(e.into()))?;
                let (path, bpf_function_name) = rx
                    .await
                    .map_err(BpfletError::RpcRecvError)?
                    .map_err(BpfletError::BpfBytecodeError)?;

                let (tx, rx) = oneshot::channel();
                image_manager
                    .send(ImageManagerCommand::GetBytecode { path, resp: tx })
                    .await
                    .map_err(|e| BpfletError::RpcSendError(e.into()))?;

                let bytecode = rx
                    .await
                    .map_err(BpfletError::RpcRecvError)?
                    .map_err(BpfletError::BpfBytecodeError)?;

                Ok((bytecode, bpf_function_name))
            }
        }
    }
}

#[derive(Debug, Serialize, Hash, Deserialize, Eq, PartialEq, Copy, Clone)]
pub(crate) enum Direction {
    Ingress = 1,
    Egress = 2,
}

impl TryFrom<String> for Direction {
    type Error = ParseError;

    fn try_from(v: String) -> Result<Self, Self::Error> {
        match v.as_str() {
            "ingress" => Ok(Self::Ingress),
            "egress" => Ok(Self::Egress),
            m => Err(ParseError::InvalidDirection {
                direction: m.to_string(),
            }),
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Direction::Ingress => f.write_str("ingress"),
            Direction::Egress => f.write_str("egress"),
        }
    }
}
