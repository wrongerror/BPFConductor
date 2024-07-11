use std::sync::Arc;

use aya::{Bpf, include_bytes_aligned};
use aya::programs::TracePoint;
use aya_log::BpfLogger;
use log::warn;
use tokio::sync::Notify;

pub async fn run(notify: Arc<Notify>) -> anyhow::Result<()> {
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/socket-tracer-readv"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/socket-tracer-readv"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let programs = vec![
        ("entry_readv", "syscalls", "sys_enter_readv"),
        ("ret_readv", "syscalls", "sys_exit_readv"),
    ];

    for (prog_name, category, name) in programs {
        let program: &mut TracePoint = bpf.program_mut(prog_name).unwrap().try_into()?;
        program.load()?;
        program.attach(category, name)?;
    }

    notify.notified().await;

    Ok(())
}
