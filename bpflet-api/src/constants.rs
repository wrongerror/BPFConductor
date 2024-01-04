pub mod directories {
    // The following directories are used by bpflet. They should be created by bpflet service
    // via the bpflet.service settings. They will be manually created in the case where bpflet
    // is not being run as a service.
    //
    // ConfigurationDirectory: /etc/bpflet/
    pub const CFGDIR_MODE: u32 = 0o6750;
    pub const CFGDIR: &str = "/etc/bpflet";
    pub const CFGDIR_STATIC_PROGRAMS: &str = "/etc/bpflet/programs.d";
    pub const CFGPATH_BPFLET_CONFIG: &str = "/etc/bpflet/bpflet.toml";
    pub const CFGPATH_CA_CERTS_PEM: &str = "/etc/bpflet/certs/ca/ca.pem";
    pub const CFGPATH_CA_CERTS_KEY: &str = "/etc/bpflet/certs/ca/ca.key";
    pub const CFGPATH_BPFLET_CERTS_PEM: &str = "/etc/bpflet/certs/bpflet/bpflet.pem";
    pub const CFGPATH_BPFLET_CERTS_KEY: &str = "/etc/bpflet/certs/bpflet/bpflet.key";
    pub const CFGPATH_BPFLET_CLIENT_CERTS_PEM: &str =
        "/etc/bpflet/certs/bpflet-client/bpflet-client.pem";
    pub const CFGPATH_BPFLET_CLIENT_CERTS_KEY: &str =
        "/etc/bpflet/certs/bpflet-client/bpflet-client.key";

    // RuntimeDirectory: /run/bpflet/
    pub const RTDIR_MODE: u32 = 0o6770;
    pub const RTDIR: &str = "/run/bpflet";
    pub const RTDIR_XDP_DISPATCHER: &str = "/run/bpflet/dispatchers/xdp";
    pub const RTDIR_TC_INGRESS_DISPATCHER: &str = "/run/bpflet/dispatchers/tc-ingress";
    pub const RTDIR_TC_EGRESS_DISPATCHER: &str = "/run/bpflet/dispatchers/tc-egress";
    pub const RTDIR_FS: &str = "/run/bpflet/fs";
    pub const RTDIR_FS_TC_INGRESS: &str = "/run/bpflet/fs/tc-ingress";
    pub const RTDIR_FS_TC_EGRESS: &str = "/run/bpflet/fs/tc-egress";
    pub const RTDIR_FS_XDP: &str = "/run/bpflet/fs/xdp";
    pub const RTDIR_FS_MAPS: &str = "/run/bpflet/fs/maps";
    pub const RTDIR_PROGRAMS: &str = "/run/bpflet/programs";
    pub const RTDIR_SOCK: &str = "/run/bpflet/sock";
    pub const RTPATH_BPFLET_SOCKET: &str = "/run/bpflet/sock/bpflet.sock";

    // StateDirectory: /var/lib/bpflet/
    pub const STDIR_MODE: u32 = 0o6770;
    pub const STDIR: &str = "/var/lib/bpflet";
    pub const STDIR_DB: &str = "/var/lib/bpflet/db";
}
