use log::warn;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;
use url::ParseError as urlParseError;

use crate::v1::agent_client::AgentClient;

#[path = "agent.v1.rs"]
#[rustfmt::skip]
#[allow(clippy::all)]
pub mod v1;

pub fn select_channel(path: String) -> Option<Channel> {
    let address = Endpoint::try_from(format!("unix:/{path}"));
    if let Err(e) = address {
        warn!("Failed to parse unix endpoint: {e:?}");
        return None;
    };
    let address = address.unwrap();
    let channel = address
        .connect_with_connector_lazy(service_fn(move |_: Uri| UnixStream::connect(path.clone())));
    Some(channel)
}

pub async fn new_agent_client(sock_patch: String) -> anyhow::Result<AgentClient<Channel>> {
    let channel = select_channel(sock_patch).unwrap();
    Ok(AgentClient::new(channel))
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ImagePullPolicy {
    Always,
    IfNotPresent,
    Never,
}

impl std::fmt::Display for ImagePullPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let v = match self {
            ImagePullPolicy::Always => "Always",
            ImagePullPolicy::IfNotPresent => "IfNotPresent",
            ImagePullPolicy::Never => "Never",
        };
        write!(f, "{v}")
    }
}

impl TryFrom<i32> for ImagePullPolicy {
    type Error = ParseError;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => ImagePullPolicy::Always,
            1 => ImagePullPolicy::IfNotPresent,
            2 => ImagePullPolicy::Never,
            policy => {
                return Err(ParseError::InvalidBytecodeImagePullPolicy {
                    pull_policy: policy.to_string(),
                })
            }
        })
    }
}

impl TryFrom<&str> for ImagePullPolicy {
    type Error = ParseError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(match value {
            "Always" => ImagePullPolicy::Always,
            "IfNotPresent" => ImagePullPolicy::IfNotPresent,
            "Never" => ImagePullPolicy::Never,
            policy => {
                return Err(ParseError::InvalidBytecodeImagePullPolicy {
                    pull_policy: policy.to_string(),
                })
            }
        })
    }
}

impl From<ImagePullPolicy> for i32 {
    fn from(value: ImagePullPolicy) -> Self {
        match value {
            ImagePullPolicy::Always => 0,
            ImagePullPolicy::IfNotPresent => 1,
            ImagePullPolicy::Never => 2,
        }
    }
}

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("{program_type} is not a valid program type")]
    InvalidProgramType { program_type: u32 },
    #[error("{program_state} is not a valid program state")]
    InvalidProgramState { program_state: u32 },
    #[error("Failed to Parse bytecode location: {0}")]
    BytecodeLocationParseFailure(#[source] urlParseError),
    #[error("Invalid bytecode location: {location}")]
    InvalidBytecodeLocation { location: String },
    #[error("Invalid bytecode image pull policy: {pull_policy}")]
    InvalidBytecodeImagePullPolicy { pull_policy: String },
}

#[derive(Clone, Debug)]
pub enum ProgramType {
    Builtin,
    Wasm,
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub enum ProgramState {
    Uninitialized,
    Initialized,
    Running,
    Stopped,
    Failed,
}

impl TryFrom<u32> for ProgramType {
    type Error = ParseError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ProgramType::Builtin),
            1 => Ok(ProgramType::Wasm),
            _ => Err(ParseError::InvalidProgramType {
                program_type: value,
            }),
        }
    }
}

impl TryFrom<ProgramType> for u32 {
    type Error = ParseError;

    fn try_from(value: ProgramType) -> Result<Self, Self::Error> {
        match value {
            ProgramType::Builtin => Ok(0),
            ProgramType::Wasm => Ok(1),
        }
    }
}

impl TryFrom<u32> for ProgramState {
    type Error = ParseError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ProgramState::Uninitialized),
            1 => Ok(ProgramState::Initialized),
            2 => Ok(ProgramState::Running),
            3 => Ok(ProgramState::Stopped),
            4 => Ok(ProgramState::Failed),
            _ => Err(ParseError::InvalidProgramState {
                program_state: value,
            }),
        }
    }
}

impl TryFrom<ProgramState> for u32 {
    type Error = ParseError;

    fn try_from(value: ProgramState) -> Result<Self, Self::Error> {
        match value {
            ProgramState::Uninitialized => Ok(0),
            ProgramState::Initialized => Ok(1),
            ProgramState::Running => Ok(2),
            ProgramState::Stopped => Ok(3),
            ProgramState::Failed => Ok(4),
        }
    }
}
