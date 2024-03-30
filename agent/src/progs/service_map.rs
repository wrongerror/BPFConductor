use crate::progs::types::Program;
use bpfman_api::v1::GetRequest;
use prometheus_client::encoding::DescriptorEncoder;

pub struct ServiceMap {
    id: Option<u32>,
    name: String,
    ebpf_prog_names: Vec<String>,
    ebpf_prog_ids: Vec<u32>,
}

impl ServiceMap {
    pub fn new() -> Self {
        let ebpf_prog_names = vec!["sock_conn_tracer".to_string(), "conn_tracer".to_string()];
        Self {
            id: None,
            name: "service_map".to_string(),
            ebpf_prog_names,
            ebpf_prog_ids: Vec::new(),
        }
    }

    // v
    async fn verify_ebpf_progs(&self) -> Result<(), anyhow::Error> {
        Ok(())
    }
}

impl Program for ServiceMap {
    async fn get_id(&self) -> u32 {
        self.id.unwrap()
    }

    async fn get_name(&self) -> &str {
        &self.name
    }

    async fn init(&self) -> Result<(), anyhow::Error> {
        Ok(())
    }

    async fn start(&self) -> Result<(), anyhow::Error> {
        Ok(())
    }

    async fn stop(&self) -> Result<(), anyhow::Error> {
        Ok(())
    }

    async fn collect(&self, mut encoder: DescriptorEncoder) -> Result<(), anyhow::Error> {
        Ok(())
    }
}
