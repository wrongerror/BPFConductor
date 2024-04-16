use thiserror::Error;
use url::ParseError as urlParseError;

#[derive(Error, Debug)]
pub enum AgentError {
    #[error("An error occurred. {0}")]
    Error(String),
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
