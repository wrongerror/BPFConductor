use std::collections::HashMap;

use anyhow::bail;
use clap::Parser;
use tonic::transport::Channel;

use agent_api::v1::agent_client::AgentClient;
use agent_api::v1::ListRequest;

use crate::table::ProgTable;
use crate::utils::parse_key_val;

#[derive(Parser, Debug)]
pub(crate) struct ListCommand {
    /// Optional: The type of programs to list.
    /// Options: builtin, wasm
    /// Example: --type wasm
    #[clap(short, long, verbatim_doc_comment)]
    pub(crate) program_type: Option<u32>,

    /// Optional: The metadata to filter the list of programs by.
    /// Format: <KEY>=<VALUE>
    /// Example: --metadata owner=acme
    #[clap(short, long, verbatim_doc_comment, value_parser=parse_key_val, value_delimiter = ',')]
    pub(crate) match_metadata: Option<Vec<(String, String)>>,
}

impl ListCommand {
    pub(crate) async fn execute(&self, agent_client: AgentClient<Channel>) -> anyhow::Result<()> {
        let mut client = agent_client;
        let request = tonic::Request::new(ListRequest {
            program_type: self.program_type,
            match_metadata: self
                .match_metadata
                .clone()
                .unwrap_or_default()
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
        });
        let response = client.list(request).await?.into_inner();
        let mut table = ProgTable::new_list();

        for r in response.results {
            if let Err(e) = table.add_response_prog(r) {
                bail!(e)
            }
        }
        table.print();
        Ok(())
    }
}
