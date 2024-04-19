use crate::args::AgentCli;
use clap::Parser;

mod args;
mod get;
mod list;
mod load;
mod table;
mod unload;
mod utils;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    AgentCli::parse().execute().await
}
