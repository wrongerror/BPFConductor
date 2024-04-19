use clap::{Args, Parser};
use tonic::transport::Channel;

use agent_api::v1::agent_client::AgentClient;
use agent_api::v1::GetRequest;

use crate::table::ProgTable;

#[derive(Parser, Debug)]
pub(crate) struct GetCommand {
    /// Required: The name of the program to get.
    pub(crate) name: String,
}

impl GetCommand {
    pub(crate) async fn execute(&self, agent_client: AgentClient<Channel>) -> anyhow::Result<()> {
        let mut client = agent_client;
        let request = GetRequest {
            name: self.name.clone(),
        };
        let response = client.get(request).await?.into_inner();
        ProgTable::new_program(&response.info)?.print();
        Ok(())
    }
}
