use crate::load::LoadCommand;
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
    #[command(subcommand)]
    Load(LoadCommand),
    // #[command(name = "unload", about = "Unload a program.")]
    // Unload(UnloadCommand),
    // #[command(name = "list", about = "List all programs.")]
    // List(ListCommand),
    // #[command(name = "get", about = "Get a program.")]
    // Get(GetCommand),
}

impl AgentCli {
    pub(crate) async fn execute(&self) -> anyhow::Result<()> {
        let socket_path = "/run/eva/agent.sock";
        let agent_client = new_agent_client(socket_path.to_string()).await?;
        match &self.command {
            SubCommands::Load(l) => l.execute(agent_client).await,
            // SubCommands::Unload(u) => u.execute(agent_client).await,
            // SubCommands::List(l) => l.execute(agent_client).await,
            // SubCommands::Get(g) => g.execute(agent_client).await,
            // SubCommands::Image(i) => i.execute(agent_client).await,
        }
    }
}
