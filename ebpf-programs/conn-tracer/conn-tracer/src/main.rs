use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use aya::maps::{HashMap, MapData};
use aya::programs::{KProbe, TracePoint};
use aya::{include_bytes_aligned, Ebpf};
use aya_log::EbpfLogger;
use log::{debug, info, warn};
use prometheus_client::registry::Registry;
use tokio::signal;

use conn_tracer_common::{ConnectionKey, ConnectionStats};

use crate::server::start_metrics_server;

mod collector;
mod resolver;
mod server;
mod tracer;

mod utils;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/conn-tracer"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/conn-tracer"
    ))?;
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let sock_conn_tracer: &mut KProbe = bpf.program_mut("sock_conn_tracer").unwrap().try_into()?;
    sock_conn_tracer.load()?;
    sock_conn_tracer.attach("tcp_data_queue", 0)?;

    let sock_state_tracer: &mut TracePoint =
        bpf.program_mut("sock_state_tracer").unwrap().try_into()?;
    sock_state_tracer.load()?;
    sock_state_tracer.attach("sock", "inet_sock_set_state")?;

    let resolver = resolver::Resolver::new().await?;
    resolver.wait_for_cache_sync().await?;

    let tcp_conns_map: HashMap<MapData, ConnectionKey, ConnectionStats> = HashMap::try_from(
        bpf.take_map("CONNECTIONS")
            .expect("no maps named CONNECTIONS"),
    )?;

    let collector = collector::ConnectionCollector::new(tcp_conns_map, resolver).await?;

    let collector = Box::new(collector);
    let mut registry = Registry::default();
    registry.register_collector(collector);

    let metrics_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8001);

    let server_handle = tokio::spawn(async move {
        start_metrics_server(metrics_addr, registry).await.unwrap();
    });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    server_handle.abort();

    Ok(())
}
