use thiserror::Error;

#[derive(Error, Debug)]
pub enum AgentError {
    #[error("An error occurred. {0}")]
    Error(String),
}
