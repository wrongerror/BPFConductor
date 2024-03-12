use std::collections;
use std::net::Ipv4Addr;
use std::sync::Arc;

use anyhow::Error;
use aya::maps::{HashMap, MapData};

use conn_tracer_common::{
    ConnectionKey, ConnectionStats, CONNECTION_ROLE_CLIENT, CONNECTION_ROLE_SERVER,
    CONNECTION_ROLE_UNKNOWN,
};

use crate::resolver::{Resolver, Workload};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Connection {
    pub(crate) client: Arc<Workload>,
    pub(crate) server: Arc<Workload>,
    pub(crate) role: u32,
    pub(crate) server_port: u32,
}

#[derive(Debug)]
pub struct ConnectionTracer {
    resolver: Resolver,
    tcp_conns_map: HashMap<MapData, ConnectionKey, ConnectionStats>,
    inactive_conns: collections::HashMap<Connection, u64>,
}

impl ConnectionTracer {
    pub fn new(
        resolver: Resolver,
        tcp_conns_map: HashMap<MapData, ConnectionKey, ConnectionStats>,
    ) -> Self {
        Self {
            resolver,
            tcp_conns_map,
            inactive_conns: collections::HashMap::new(),
        }
    }

    // a single polling from the eBPF maps
    // iterating the traces from the kernel-space, summing each network connection
    pub fn poll(&mut self) -> Result<collections::HashMap<Connection, u64>, Error> {
        let mut keys_to_remove = Vec::new();
        let mut current_conns = collections::HashMap::new();

        for item in self.tcp_conns_map.iter() {
            let (key, stats) = item?;
            if stats.is_active == 0 {
                keys_to_remove.push(key);
                continue;
            }
            if key.src_addr == key.dest_addr || self.is_loopback_address(key.dest_addr) {
                continue;
            }
            if key.role == CONNECTION_ROLE_UNKNOWN {
                continue;
            }

            let connection = self.build_connection(key)?;
            current_conns
                .entry(connection)
                .and_modify(|e| *e += stats.bytes_sent)
                .or_insert(stats.bytes_sent);
        }

        // add inactive connections to the current connections
        for (conn, bytes_sent) in self.inactive_conns.iter() {
            current_conns
                .entry(conn.clone())
                .and_modify(|e| *e += *bytes_sent)
                .or_insert(*bytes_sent);
        }

        for key in keys_to_remove {
            self.handle_inactive_connection(key)?;
        }

        Ok(current_conns)
    }

    fn build_connection(&self, key: ConnectionKey) -> Result<Connection, Error> {
        let client_workload = self
            .resolver
            .resolve_ip(key.src_addr)
            .ok_or(Error::msg(format!(
                "Unknown IP: {}",
                Ipv4Addr::from(key.src_addr)
            )))?;
        let server_workload =
            self.resolver
                .resolve_ip(key.dest_addr)
                .ok_or(Error::msg(format!(
                    "Unknown IP: {}",
                    Ipv4Addr::from(key.dest_addr)
                )))?;

        let (client, server, port) = match key.role {
            CONNECTION_ROLE_CLIENT => (client_workload, server_workload, key.dest_port),
            CONNECTION_ROLE_SERVER => (server_workload, client_workload, key.src_port),
            _ => return Err(Error::msg("Unknown connection role")),
        };

        Ok(Connection {
            client,
            server,
            role: key.role,
            server_port: port,
        })
    }

    fn handle_inactive_connection(&mut self, key: ConnectionKey) -> Result<(), Error> {
        let throughput = match self.tcp_conns_map.get(&key, 0) {
            Ok(stats) => stats.bytes_sent,
            Err(_) => 0,
        };

        self.tcp_conns_map.remove(&key)?;

        let connection = self.build_connection(key)?;
        self.inactive_conns
            .entry(connection)
            .and_modify(|e| *e += throughput)
            .or_insert(throughput);
        Ok(())
    }

    fn is_loopback_address(&self, addr: u32) -> bool {
        let ip_addr = Ipv4Addr::from(addr);
        ip_addr.is_loopback()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aya::maps::Map;
    use std::path::Path;

    #[tokio::test]
    async fn test_connection_tracer_poll() {
        let bpflet_maps_path = "/run/bpflet/fs/maps".to_string();
        let bpflet_maps = Path::new(&bpflet_maps_path);
        if !bpflet_maps.exists() {
            panic!("BPF maps path does not exist");
        }

        let tcp_conns_map: HashMap<_, ConnectionKey, ConnectionStats> = Map::HashMap(
            MapData::from_pin(bpflet_maps.join("238/CONNECTIONS"))
                .expect("no maps named CONNECTIONS"),
        )
        .try_into()
        .unwrap();

        let resolver = Resolver::new().await.unwrap();
        resolver.wait_for_cache_sync().await.unwrap();

        let mut conn_tracer = ConnectionTracer::new(resolver, tcp_conns_map);

        let conns = conn_tracer.poll().unwrap();

        assert_ne!(conns.len(), 0);
    }
}
