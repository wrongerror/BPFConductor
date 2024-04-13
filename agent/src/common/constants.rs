pub mod directories {
    pub const SOCK_MODE: u32 = 0o0660;
    pub const RTDIR_MODE: u32 = 0o6770;
    pub const RTDIR: &str = "/run/eva";
    pub const RTPATH_AGENT_SOCKET: &str = "/run/eva/agent.sock";
}

pub const PROG_TYPE_BUILTIN: u32 = 0;
pub const PROG_TYPE_WASM: u32 = 1;

pub const METRICS_INTERVAL: u64 = 15;
