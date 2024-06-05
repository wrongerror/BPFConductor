use std::sync::Arc;

use aya::{Bpf, include_bytes_aligned};
use aya::programs::KProbe;
use aya_log::BpfLogger;
use log::warn;
use tokio::sync::Notify;

pub async fn run(notify: Arc<Notify>) -> anyhow::Result<()> {
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/socket-tracer-recvmmsg"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/socket-tracer-recvmmsg"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let programs = vec![
        ("entry_recvmmsg", "__x64_sys_recvmmsg"),
        ("ret_recvmmsg", "__x64_sys_recvmmsg"),
    ];

    for (prog_name, func_name) in programs {
        let program: &mut KProbe = bpf.program_mut(prog_name).unwrap().try_into()?;
        program.load()?;
        program.attach(func_name, 0)?;
    }

    notify.notified().await;

    Ok(())
}
