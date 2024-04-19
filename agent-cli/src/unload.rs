use clap::{Args, Parser};
use tonic::transport::Channel;

use agent_api::v1::agent_client::AgentClient;
use agent_api::v1::UnloadRequest;

#[derive(Parser, Debug)]
pub(crate) struct UnloadCommand {
    /// Required: The name of the program to unload.
    pub(crate) name: String,
}

impl UnloadCommand {
    pub(crate) async fn execute(&self, agent_client: AgentClient<Channel>) -> anyhow::Result<()> {
        let mut client = agent_client;
        let request = UnloadRequest {
            name: self.name.clone(),
        };
        let _response = client.unload(request).await?.into_inner();
        Ok(())
    }
}
