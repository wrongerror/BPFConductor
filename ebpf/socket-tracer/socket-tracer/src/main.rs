use std::path::Path;
use std::ptr;
use std::sync::Arc;

use aya::maps::{AsyncPerfEventArray, Map, MapData};
use aya::util::online_cpus;
use bytes::BytesMut;
use log::{debug, info};
use tokio::signal;
use tokio::sync::Notify;

use socket_tracer_common::{ConnStatsEvent, SocketControlEvent, SocketDataEvent};

mod accept;
mod accept4;
mod close;
mod connect;
mod read;
mod readv;
mod recv;
mod recvfrom;
mod recvmmsg;
mod recvmsg;
mod send;
mod sendfile;
mod sendmmsg;
mod sendmsg;
mod sendto;
mod sockalloc;
mod ssendmsg;
mod write;
mod writev;

const BPF_MAP_PATH: &str = "/sys/fs/bpf";

async fn process_perf_events<T: 'static>(
    map_path: &Path,
    event_handler: Arc<dyn Fn(&T) + Send + Sync>,
) -> Result<(), anyhow::Error> {
    let cpus = online_cpus()?;
    let num_cpus = cpus.len();
    let map_data =
        MapData::from_pin(map_path).map_err(|_| anyhow::anyhow!("No maps named {:?}", map_path))?;
    let map: Map = Map::PerfEventArray(map_data)
        .try_into()
        .map_err(|_| anyhow::anyhow!("Failed to convert map"))?;
    let mut events = AsyncPerfEventArray::try_from(map)?;
    for cpu in cpus {
        let mut buf = events.open(cpu, None)?;
        let event_handler = event_handler.clone();

        tokio::spawn(async move {
            let mut buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(9000))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];

                    let event = unsafe { ptr::read_unaligned(buf.as_ptr() as *const T) };
                    event_handler(&event);
                }
            }
        });
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let notify = Arc::new(Notify::new());

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

    let notify_connect = notify.clone();
    tokio::spawn(async move {
        connect::run(notify_connect).await.unwrap();
    });

    let notify_accept = notify.clone();
    tokio::spawn(async move {
        accept::run(notify_accept).await.unwrap();
    });

    let notify_accept4 = notify.clone();
    tokio::spawn(async move {
        accept4::run(notify_accept4).await.unwrap();
    });

    let notify_close = notify.clone();
    tokio::spawn(async move {
        close::run(notify_close).await.unwrap();
    });

    let notify_send = notify.clone();
    tokio::spawn(async move {
        send::run(notify_send).await.unwrap();
    });

    let notify_sendto = notify.clone();
    tokio::spawn(async move {
        sendto::run(notify_sendto).await.unwrap();
    });

    let notify_sendmsg = notify.clone();
    tokio::spawn(async move {
        sendmsg::run(notify_sendmsg).await.unwrap();
    });

    let notify_sendmmsg = notify.clone();
    tokio::spawn(async move {
        sendmmsg::run(notify_sendmmsg).await.unwrap();
    });

    let notify_sendfile = notify.clone();
    tokio::spawn(async move {
        sendfile::run(notify_sendfile).await.unwrap();
    });

    let notify_ssendmsg = notify.clone();
    tokio::spawn(async move {
        ssendmsg::run(notify_ssendmsg).await.unwrap();
    });

    let notify_recv = notify.clone();
    tokio::spawn(async move {
        recv::run(notify_recv).await.unwrap();
    });

    let notify_recvfrom = notify.clone();
    tokio::spawn(async move {
        recvfrom::run(notify_recvfrom).await.unwrap();
    });

    let notify_recvmsg = notify.clone();
    tokio::spawn(async move {
        recvmsg::run(notify_recvmsg).await.unwrap();
    });

    let notify_recvmmsg = notify.clone();
    tokio::spawn(async move {
        recvmmsg::run(notify_recvmmsg).await.unwrap();
    });

    let notify_read = notify.clone();
    tokio::spawn(async move {
        read::run(notify_read).await.unwrap();
    });

    let notify_readv = notify.clone();
    tokio::spawn(async move {
        readv::run(notify_readv).await.unwrap();
    });

    let notify_write = notify.clone();
    tokio::spawn(async move {
        write::run(notify_write).await.unwrap();
    });

    let notify_writev = notify.clone();
    tokio::spawn(async move {
        writev::run(notify_writev).await.unwrap();
    });

    let notify_sockalloc = notify.clone();
    tokio::spawn(async move {
        sockalloc::run(notify_sockalloc).await.unwrap();
    });

    let bpf_map_path = std::path::Path::new(BPF_MAP_PATH);

    // handle sk_ctrl_events
    let sk_ctrl_events_map_path = bpf_map_path.join("sk_ctrl_events");
    process_perf_events(
        &sk_ctrl_events_map_path,
        Arc::new(|event: &SocketControlEvent| {
            info!("sk_ctrl_event id: {:?}", event.id);
        }),
    )
    .await?;

    // handle conn_stat_events
    let conn_stat_events_map_path = bpf_map_path.join("conn_stat_events");
    process_perf_events(
        &conn_stat_events_map_path,
        Arc::new(|event: &ConnStatsEvent| {
            info!("conn_stat_event id: {:?}", event.id);
        }),
    )
    .await?;

    // handle sk_data_events
    let sk_data_events_map_path = bpf_map_path.join("sk_data_events");
    process_perf_events(
        &sk_data_events_map_path,
        Arc::new(|event: &SocketDataEvent| {
            info!("sk_data_event uid: {:?}", event.inner.id);
            let msg_str = String::from_utf8_lossy(&event.msg[..48]);
            info!(
                "sk_data_event source function: {:?}, msg : {:?}",
                event.inner.source_function, msg_str
            );
        }),
    )
    .await?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    notify.notify_one();

    Ok(())
}
