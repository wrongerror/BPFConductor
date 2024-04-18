use crate::args::AgentCli;
use clap::Parser;

mod args;
mod load;
mod table;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    AgentCli::parse().execute().await
}
