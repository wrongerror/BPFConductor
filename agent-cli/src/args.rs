use crate::get::GetCommand;
use crate::list::ListCommand;
use crate::load::LoadCommand;
use crate::unload::UnloadCommand;
use agent_api::new_agent_client;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    long_about = "A program manager designed to streamline the deployment and management of eBPF user space programs."
)]
#[command(name = "conductor")]
#[command(disable_version_flag = true)]
pub(crate) struct AgentCli {
    #[command(subcommand)]
    pub(crate) command: SubCommands,
}

#[derive(Subcommand, Debug)]
pub(crate) enum SubCommands {
    /// Handles the loading of programs.
    /// Supports loading either a builtin program or a wasm program from an OCI container image.
    #[command(subcommand)]
    Load(LoadCommand),

    /// Handles the unloading of loaded programs.
    /// Requires the name of the program to be unloaded.
    Unload(UnloadCommand),

    /// Lists the programs in the system.
    /// Programs can be filtered by type (builtin or wasm) and metadata.
    List(ListCommand),

    /// Retrieves detailed information about a specific program.
    /// Requires the name of the program to be retrieved.
    Get(GetCommand),
}

impl AgentCli {
    pub(crate) async fn execute(&self) -> anyhow::Result<()> {
        let socket_path = "/run/eva/agent.sock";
        let agent_client = new_agent_client(socket_path.to_string()).await?;
        match &self.command {
            SubCommands::Load(l) => l.execute(agent_client).await,
            SubCommands::Unload(u) => u.execute(agent_client).await,
            SubCommands::List(l) => l.execute(agent_client).await,
            SubCommands::Get(g) => g.execute(agent_client).await,
            // SubCommands::Image(i) => i.execute(agent_client).await,
        }
    }
}
