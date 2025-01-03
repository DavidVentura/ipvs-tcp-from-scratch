use anyhow::Context;
use ipvs_tcp_from_scratch_common::TcpSocketEvent;

use aya::maps::{AsyncPerfEventArray, MapData};
use aya::programs::{KProbe, TracePoint};
use aya::util::online_cpus;
use aya::Ebpf;

use bytes::BytesMut;
use log::{debug, warn};

use tokio::spawn;
use tokio::sync::mpsc;

fn get_program() -> Result<Ebpf, anyhow::Error> {
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
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ipvs-tcp-from-scratch"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    Ok(ebpf)
}

/// Will spawn `online_cpus()` coroutines to watch for TCP events
/// on their respective cores.
/// If you close the returned Receiver, then they will all stop.
async fn watch_tcp_events(
    mut events: AsyncPerfEventArray<MapData>,
) -> Result<mpsc::Receiver<TcpSocketEvent>, anyhow::Error> {
    let (tx, rx) = mpsc::channel::<TcpSocketEvent>(32);
    for cpu_id in online_cpus().unwrap() {
        let mut cpu_buf = events.open(cpu_id, None)?;
        let tx = tx.clone();
        spawn(async move {
            loop {
                let mut bufs = (0..10)
                    // unsure what these buffers and their size do
                    // shouldn't they be sizeof(TcpSocketEvent) ?
                    .map(|_| BytesMut::with_capacity(1024))
                    .collect::<Vec<_>>();
                let events = cpu_buf.read_events(&mut bufs).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut bufs[i];
                    let ptr = buf.as_ptr() as *const TcpSocketEvent;
                    let event = unsafe { ptr.read_unaligned() };
                    // if channel is closed, stop listening for events
                    if let Err(_) = tx.send(event).await {
                        return;
                    }
                }
            }
        });
    }
    Ok(rx)
}

pub struct ConnectionWatcher {
    ebpf: Ebpf,
}

impl ConnectionWatcher {
    pub fn new() -> Result<ConnectionWatcher, anyhow::Error> {
        Ok(ConnectionWatcher {
            ebpf: get_program()?,
        })
    }
    pub async fn get_events(&mut self) -> Result<mpsc::Receiver<TcpSocketEvent>, anyhow::Error> {
        let tcp_conn: &mut KProbe = self.ebpf.program_mut("tcp_connect").unwrap().try_into()?;
        tcp_conn.load()?;
        tcp_conn.attach("tcp_connect", 0)?;

        let program: &mut TracePoint = self
            .ebpf
            .program_mut("ipvs_tcp_from_scratch")
            .unwrap()
            .try_into()?;
        program.load()?;
        program.attach("sock", "inet_sock_set_state")?;

        let ipvs_conn: &mut KProbe = self
            .ebpf
            .program_mut("ip_vs_conn_new")
            .unwrap()
            .try_into()?;
        ipvs_conn.load()?;
        ipvs_conn
            .attach("ip_vs_conn_new", 0)
            .context("failed to attach to ip_vs_conn_new, is the kernel module loaded?")?;

        let tcp_retrans: &mut TracePoint = self
            .ebpf
            .program_mut("tcp_retransmit_skb")
            .unwrap()
            .try_into()?;
        tcp_retrans.load()?;
        tcp_retrans.attach("tcp", "tcp_retransmit_skb")?;

        let tcp_rcv_reset: &mut TracePoint = self
            .ebpf
            .program_mut("tcp_receive_reset")
            .unwrap()
            .try_into()?;
        tcp_rcv_reset.load()?;
        tcp_rcv_reset.attach("tcp", "tcp_receive_reset")?;

        let events: AsyncPerfEventArray<_> =
            self.ebpf.take_map("TCP_EVENTS").unwrap().try_into()?;

        watch_tcp_events(events).await
    }
}
