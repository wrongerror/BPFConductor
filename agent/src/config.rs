use bpfman_lib::directories::RTPATH_BPFMAN_SOCKET;

use crate::common::constants::directories::RTDIR;

pub(crate) struct Config {
    pub(crate) bpfman_sock_path: String,
    pub(crate) agent_sock_path: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bpfman_sock_path: RTPATH_BPFMAN_SOCKET.to_string(),
            agent_sock_path: RTDIR.to_string(),
        }
    }
}
