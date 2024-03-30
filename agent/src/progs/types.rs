use prometheus_client::encoding::DescriptorEncoder;

#["async-trait"]
pub trait Program: Send + Sync + 'static {
    async fn get_id(&self) -> u32;
    async fn get_name(&self) -> &str;
    async fn init(&self) -> Result<(), anyhow::Error>;
    async fn start(&self) -> Result<(), anyhow::Error>;
    async fn stop(&self) -> Result<(), anyhow::Error>;
    async fn collect(&self, encoder: DescriptorEncoder) -> Result<(), anyhow::Error>;
}
