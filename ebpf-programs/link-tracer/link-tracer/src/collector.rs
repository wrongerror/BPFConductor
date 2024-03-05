use prometheus_client::collector::Collector;
use prometheus_client::encoding::{DescriptorEncoder, EncodeLabelSet, EncodeMetric};
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Unit;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct Labels {
    link_id: String,
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
struct LinkCollector {}

impl Collector for LinkCollector {
    fn encode(&self, mut encoder: DescriptorEncoder) -> Result<(), std::fmt::Error> {
        let link_metric = Family::<Labels, Gauge>::default();
        let metric_encoder = encoder.encode_descriptor(
            "link_observed",
            "total bytes_sent value of links observed",
            Some(&Unit::Bytes),
            link_metric.metric_type(),
        )?;
        metric_encoder.encode(metric_encoder)?;
        Ok(())
    }
}
