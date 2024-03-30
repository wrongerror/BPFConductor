use std::sync::Arc;

use registry::Registry;

use crate::progs::service_map::ServiceMap;

mod registry;

pub async fn register_programs(registry: Registry) {
    // Register programs here
    let service_map = Arc::new(ServiceMap::new());
    registry
        .insert("service_map".to_string(), service_map)
        .await;
}
