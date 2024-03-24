# Building eBPF Programs from Scratch with Rust and aya

## Development Environment

Please refer to the [Aya docs](https://aya-rs.dev/book/start/development) to set up your development environment.

## Starting A New Project

To start a new project, you can use cargo-generate:

```sh
cargo generate --name conn-tracer -d program_type=kprobe https://github.com/aya-rs/aya-template
```

This will create a new project named `conn-tracer` with a kprobe program.

there are several directories in the project:

- `conn-tracer-ebpf/` contains the Rust code for the eBPF program.
- `conn-tracer/` contains the Rust code for the userspace program.
- `conn-tracer-common/` contains the common code shared between the eBPF and userspace programs.
- `xtask/` contains the code for building the eBPF program and run the userspace program.

## Writing the eBPF Program

### Writing and Generating the common code

Using aya-tool to generate Rust bindings for specific kernel structures.
it can be installed with the following commands:

```sh
$ cargo install bindgen-cli
$ cargo install --git https://github.com/aya-rs/aya -- aya-tool
```

To generate the bindings for the `sock`,`inet_sock`,`inet_connection_sock`,`tcp_sock` structure, run the following
command:

```sh
$ aya-tool generate sock inet_sock inet_connection_sock tcp_sock > conn-tracer-common/src/vmlinux.rs
```

You can define some structures or constants in the `conn-tracer-common/src/lib.rs` file:

```rust
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct SockInfo {
    pub id: u32,
    pub pid: u32,
    pub role: u32,
    pub is_active: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SockInfo {}
```

> Note: The Rust compiler may generate padding fields in the `SockInfo` structure to align the fields to the size of the
> largest field.
> This may cause the uninitialized memory to be read when the structure is passed to the eBPF program.
> To avoid this, you can ensure that the structure size is the multiple of the largest field size.

> Note: The `#[cfg(feature = "user")]` attribute is used to conditionally compile the `Pod` trait implementation for the
> userspace program.
> If you want to use the `SockInfo` structure in the userspace program, you need to enable the `user` feature in
> the `conn-tracer-common` crate.

### Writing the eBPF Program

Map definitions:

```rust
#[map(name = "SOCKETS")]
static mut SOCKETS: aya_ebpf::maps::LruHashMap<*const sock, SockInfo> =
    aya_ebpf::maps::LruHashMap::<*const sock, SockInfo>::pinned(MAX_CONNECTIONS, 0);
```

> Note: The with_max_entries method will create a map each time the eBPF program is loaded, while the pinned method will
> only create it once and by default, it will pin it to the /sys/fs/bpf directory.

The eBPF program is written in Rust. The entry point of the program is the `#[kprobe]` function. The function signature
is:

```rust
#[kprobe = "tcp_data_queue"]
pub fn sock_conn_tracer(ctx: ProbeContext) -> u32 {
    match try_sock_conn_tracer(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

fn try_sock_conn_tracer(ctx: ProbeContext) -> Result<u32, i64> {
    // first argument to tcp_data_queue is a struct sock*
    let sk: *const sock = ctx.arg(0).ok_or(1i64)?;
}

fn parse_sock_data(
    sk: *const sock,
    conn_key: &mut ConnectionKey,
    conn_stats: &mut ConnectionStats,
) -> Result<u32, i64> {
    let sk_common =
        unsafe { bpf_probe_read_kernel(&(*sk).__sk_common as *const sock_common).map_err(|e| e)? };

    let tcp_sk = sk as *const tcp_sock;

    // read throughput data
    conn_stats.bytes_sent =
        unsafe { bpf_probe_read_kernel(&(*tcp_sk).bytes_sent as *const u64).map_err(|e| e)? };
    conn_stats.bytes_received =
        unsafe { bpf_probe_read_kernel(&(*tcp_sk).bytes_received as *const u64).map_err(|e| e)? };

    // read connection data
    match sk_common.skc_family {
        AF_INET => {
            let src_addr =
                u32::from_be(unsafe { sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_rcv_saddr });
            let dest_addr: u32 =
                u32::from_be(unsafe { sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_daddr });
            let src_port =
                u16::from_be(unsafe { sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_num });
            let dest_port =
                u16::from_be(unsafe { sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_dport });
            conn_key.src_addr = src_addr;
            conn_key.dest_addr = dest_addr;
            conn_key.src_port = src_port as u32;
            conn_key.dest_port = dest_port as u32;
            Ok(0)
        }
        _ => Err(1i64),
    }
}
```

There are some details in the code:

- The first argument to `ProbeContext` is a struct `*sock`.
- The `sock` structure can be cast to other structures like `tcp_sock` using the as keyword, because they have an
  inheritance relationship. When initialized in the kernel, it is done according to the largest struct.
- The `bpf_probe_read_kernel` function is used to read the kernel memory.
- The `from_be` is used to convert the network byte order to the host byte order.

Sometimes, single `kprobe` function are not enough to achieve the desired functionality.
We can use the `#[tracepoint]` function to trace the kernel events.

```rust
#[tracepoint = "sock/inet_sock_set_state"]
pub fn sock_state_tracer(ctx: TracePointContext) -> u32 {
    match try_state_tracer(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}


fn try_state_tracer(ctx: TracePointContext) -> Result<u32, i64> {
    let sk: *const sock = unsafe { ctx.read_at::<*const sock>(INET_SOCK_SKADDR_OFFSET)? };
    let new_state: i32 = unsafe { ctx.read_at::<i32>(INET_SOCK_NEWSTATE_OFFSET)? };

    match new_state {
        TCP_SYN_RECV => handle_tcp_syn_recv(sk),
        TCP_SYN_SENT => handle_tcp_syn_sent(sk),
        TCP_CLOSE => handle_tcp_close(sk),
        _ => Ok(0),
    }
}
```

The `ctx.read_at` function is used to read the kernel memory at the specified offset.
In this case, we read the `*sock` structure and the `newstate` of the socket.

Where to find the `INET_SOCK_SKADDR_OFFSET` and `INET_SOCK_NEWSTATE_OFFSET` values?
You can use this command:

```sh
cat /sys/kernel/debug/tracing/events/sock/inet_sock_set_state/format

name: inet_sock_set_state
ID: 1477
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:const void * skaddr;      offset:8;       size:8; signed:0;
        field:int oldstate;     offset:16;      size:4; signed:1;
        field:int newstate;     offset:20;      size:4; signed:1;
        field:__u16 sport;      offset:24;      size:2; signed:0;
        field:__u16 dport;      offset:26;      size:2; signed:0;
        field:__u16 family;     offset:28;      size:2; signed:0;
        field:__u16 protocol;   offset:30;      size:2; signed:0;
        field:__u8 saddr[4];    offset:32;      size:4; signed:0;
        field:__u8 daddr[4];    offset:36;      size:4; signed:0;
        field:__u8 saddr_v6[16];        offset:40;      size:16;        signed:0;
        field:__u8 daddr_v6[16];        offset:56;      size:16;        signed:0;

print fmt: "family=%s protocol=%s sport=%hu dport=%hu saddr=%pI4 daddr=%pI4 saddrv6=%pI6c daddrv6=%pI6c oldstate=%s newstate=%s", __print_symbolic(REC->family, { 2, "AF_INET" }, { 10, "AF_INET6" }), __print_symbolic(REC->protocol, { 6, "IPPROTO_TCP" }, { 33, "IPPROTO_DCCP" }, { 132, "IPPROTO_SCTP" }, { 262, "IPPROTO_MPTCP" }), REC->sport, REC->dport, REC->saddr, REC->daddr, REC->saddr_v6, REC->daddr_v6, __print_symbolic(REC->oldstate, { 1, "TCP_ESTABLISHED" }, { 2, "TCP_SYN_SENT" }, { 3, "TCP_SYN_RECV" }, { 4, "TCP_FIN_WAIT1" }, { 5, "TCP_FIN_WAIT2" }, { 6, "TCP_TIME_WAIT" }, { 7, "TCP_CLOSE" }, { 8, "TCP_CLOSE_WAIT" }, { 9, "TCP_LAST_ACK" }, { 10, "TCP_LISTEN" }, { 11, "TCP_CLOSING" }, { 12, "TCP_NEW_SYN_RECV" }), __print_symbolic(REC->newstate, { 1, "TCP_ESTABLISHED" }, { 2, "TCP_SYN_SENT" }, { 3, "TCP_SYN_RECV" }, { 4, "TCP_FIN_WAIT1" }, { 5, "TCP_FIN_WAIT2" }, { 6, "TCP_TIME_WAIT" }, { 7, "TCP_CLOSE" }, { 8, "TCP_CLOSE_WAIT" }, { 9, "TCP_LAST_ACK" }, { 10, "TCP_LISTEN" }, { 11, "TCP_CLOSING" }, { 12, "TCP_NEW_SYN_RECV" })
```

As you can see, the `INET_SOCK_SKADDR_OFFSET` is 8 and the `INET_SOCK_NEWSTATE_OFFSET` is 20. And
the `TCP_SYN_RECV`, `TCP_SYN_SENT`, and `TCP_CLOSE` values are 3, 2, and 7 respectively.

### Writing the Userspace Program

The userspace program is written in Rust. The entry point of the program is the `main` function.

```rust
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

    let tcp_conns_map: HashMap<MapData, ConnectionKey, ConnectionStats> = HashMap::try_from(
        bpf.take_map("CONNECTIONS")
            .expect("no maps named CONNECTIONS"),
    )?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
```

The main function does the following:

- Initializes the logger.
- Bumps the memlock rlimit.
- Loads the eBPF program.
- Attaches the eBPF program to the kprobe and tracepoint.
- Initializes the `HashMap` to store the connection data. the `bpf.take_map` function is used to take the map
  data, `MapData::from_pin` is another way to take the map data.
- Waits for the Ctrl-C signal to exit.

### Building the eBPF Program

To build the eBPF program, you can use the `xtask` tool:

```sh
$ cargo xtask build-ebpf
```

This will build the eBPF program and generate the `conn-tracer` elf file in
the `conn-tracer/target/bpfel-unknown-none/debug` directory.

### Running the Userspace Program

To run the userspace program, you can use the following command:

```sh
$ cargo xtask run
```

This will load the eBPF program and attach it to the kprobe and tracepoint. The program will then wait for the Ctrl-C
signal to exit.

## Conclusion

In this guide, we have shown how to build an eBPF program from scratch using Rust and aya. We have also demonstrated how
to write the userspace program to load and attach the eBPF program. By following these steps, you can create powerful
eBPF programs to trace and monitor various kernel events.
