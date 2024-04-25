use std::collections::HashMap;
use std::fmt::Debug;

use async_trait::async_trait;
use prometheus_client::encoding::DescriptorEncoder;
use tokio::sync::broadcast::Receiver;

use agent_api::v1::ProgramInfo;

use crate::managers::cache::CacheManager;
use agent_api::{ProgramState, ProgramType};

#[derive(Debug, Clone)]
pub enum ShutdownSignal {
    All,
    ProgramName(String),
}

#[async_trait]
pub trait Program: Debug + Send + Sync + 'static {
    fn init(
        &self,
        metadata: HashMap<String, String>,
        cache_manager: CacheManager,
        maps: HashMap<String, u32>,
    ) -> Result<(), anyhow::Error>;
    async fn start(&self, shutdown_rx: Receiver<ShutdownSignal>) -> Result<(), anyhow::Error>;

    async fn stop(&self) -> Result<(), anyhow::Error>;
    fn collect(&self, encoder: &mut DescriptorEncoder) -> Result<(), anyhow::Error>;
    fn get_name(&self) -> String;
    fn get_state(&self) -> ProgramState;
    fn set_state(&self, state: ProgramState);
    fn get_type(&self) -> ProgramType;
    fn get_metadata(&self) -> HashMap<String, String>;
    fn set_metadata(&self, metadata: HashMap<String, String>);
    fn get_program_info(&self) -> Result<ProgramInfo, anyhow::Error>;
}
