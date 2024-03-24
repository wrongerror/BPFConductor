use std::sync::RwLock;

use anyhow::Error;
use aya::maps::{HashMap, MapData};
use prometheus_client::collector::Collector;
use prometheus_client::encoding::{DescriptorEncoder, EncodeLabelSet, EncodeMetric};
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Unit;

use conn_tracer_common::{ConnectionKey, ConnectionStats};

use crate::resolver::Resolver;
use crate::tracer::ConnectionTracer;
use crate::utils::fnv_hash;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct Labels {
    conn_id: String,
    client_id: String,
    client_name: String,
    client_namespace: String,
    client_kind: String,
    server_id: String,
    server_name: String,
    server_namespace: String,
    server_kind: String,
    server_port: String,
    role: String,
}

#[derive(Debug)]
pub struct ConnectionCollector {
    conn_tracer: RwLock<ConnectionTracer>,
}

impl ConnectionCollector {
    pub async fn new(
        tcp_conns_map: HashMap<MapData, ConnectionKey, ConnectionStats>,
        resolver: Resolver,
    ) -> anyhow::Result<Self, Error> {
        let conn_tracer = ConnectionTracer::new(resolver, tcp_conns_map);

        Ok(Self {
            conn_tracer: RwLock::new(conn_tracer),
        })
    }
}

impl Collector for ConnectionCollector {
    fn encode(&self, mut encoder: DescriptorEncoder) -> Result<(), std::fmt::Error> {
        let mut tracer = self.conn_tracer.write().unwrap();

        let conns = match tracer.poll() {
            Ok(conns) => conns,
            Err(_) => {
                return Err(std::fmt::Error);
            }
        };
        let conn_metric = Family::<Labels, Gauge>::default();
        for (conn, value) in conns.iter() {
            let labels = Labels {
                conn_id: format!(
                    "{:x}",
                    fnv_hash(&format!(
                        "{}{}{}{}",
                        conn.client.name,
                        conn.client.namespace,
                        conn.server.name,
                        conn.server.namespace
                    ))
                ),
                client_id: format!(
                    "{:x}",
                    fnv_hash(&format!("{}{}", conn.client.name, conn.client.namespace))
                ),
                client_name: conn.client.name.clone(),
                client_namespace: conn.client.namespace.clone(),
                client_kind: conn.client.kind.clone(),
                server_id: format!(
                    "{:x}",
                    fnv_hash(&format!("{}{}", conn.server.name, conn.server.namespace))
                ),
                server_name: conn.server.name.clone(),
                server_namespace: conn.server.namespace.clone(),
                server_kind: conn.server.kind.clone(),
                server_port: conn.server_port.to_string(),
                role: conn.role.to_string(),
            };
            conn_metric.get_or_create(&labels).set(*value as i64);
        }

        let metric_encoder = encoder.encode_descriptor(
            "connection_observed",
            "total bytes_sent value of connections observed",
            Some(&Unit::Bytes),
            conn_metric.metric_type(),
        )?;
        conn_metric.encode(metric_encoder)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::Path;
    use std::time::Duration;

    use aya::maps::Map;
    use bytes::Buf;
    use http_body_util::BodyExt;
    use hyper::StatusCode;
    use log::info;
    use prometheus_client::registry::Registry;

    use crate::server::start_metrics_server;
    use crate::utils::{fetch_url, fnv_hash};

    use super::*;

    #[test]
    fn test_fnv_hash() {
        assert_eq!(fnv_hash("hello"), 2158673163);
    }

    #[tokio::test]
    async fn test_encode() {
        let bpflet_maps_path = "/run/bpflet/fs/maps".to_string();
        let bpflet_maps = Path::new(&bpflet_maps_path);

        if !bpflet_maps.exists() {
            info!("BPF maps path does not exist: {}", bpflet_maps_path);
            panic!("BPF maps path does not exist: {}", bpflet_maps_path);
        }

        let tcp_conns_map: HashMap<_, ConnectionKey, ConnectionStats> = Map::HashMap(
            MapData::from_pin(bpflet_maps.join("244/CONNECTIONS"))
                .expect("no maps named CONNECTIONS"),
        )
        .try_into()?;

        let resolver = Resolver::new().await?;
        resolver.wait_for_cache_sync().await?;
        let collector = ConnectionCollector::new(tcp_conns_map, resolver)
            .await
            .unwrap();
        let collector = Box::new(collector);
        let mut registry = Registry::default();
        registry.register_collector(collector);

        let metrics_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8001);

        let server_handle = tokio::spawn(async move {
            start_metrics_server(metrics_addr, registry).await.unwrap();
        });

        // Add a delay to ensure the server has time to start
        tokio::time::sleep(Duration::from_secs(600)).await;

        // send a request to the server
        let url = format!("http://{}/metrics", metrics_addr);
        println!("Fetching {}", url);
        let url = url.parse::<hyper::Uri>().unwrap();
        let resp = fetch_url(url).await.unwrap();

        // assert that the response status code is 200
        assert_eq!(resp.status(), StatusCode::OK);

        // assert that the response content type is "application/openmetrics-text; version=1.0.0; charset=utf-8"
        assert_eq!(
            resp.headers().get(hyper::header::CONTENT_TYPE).unwrap(),
            "application/openmetrics-text; version=1.0.0; charset=utf-8"
        );

        // assert that the response body is the expected metrics
        let body = resp.collect().await.unwrap().aggregate();
        let mut body_reader = body.reader();
        let mut body_string = String::new();
        body_reader.read_to_string(&mut body_string).unwrap();

        assert_eq!(body_string, "# HELP http_requests Number of HTTP requests received.\n# TYPE http_requests counter\nhttp_requests_total{method=\"GET\",path=\"/metrics\"} 1\n# EOF\n");
        server_handle.abort();
    }
}
