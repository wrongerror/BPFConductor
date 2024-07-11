pub mod directories {
    pub const SOCK_MODE: u32 = 0o0660;
    pub const RTDIR_MODE: u32 = 0o6770;
    pub const RTDIR: &str = "/run/eva";
    pub const RTPATH_AGENT_SOCKET: &str = "/run/eva/agent.sock";
    pub const RTDIR_FS_MAPS: &str = "/run/bpfman/fs/maps";
}

pub const DEFAULT_INTERVAL: u64 = 15;
