#![no_std]
#![no_main]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
include!(concat!(env!("OUT_DIR"), "/ipvs_bindings.rs"));

use crate::tracepoint_gen::{
    trace_event_raw_inet_sock_set_state, trace_event_raw_tcp_event_sk_skb,
};

use aya_ebpf::helpers;
use aya_ebpf::macros::{kprobe, map, tracepoint};
use aya_ebpf::maps::{HashMap, PerfEventArray};
use aya_ebpf::programs::{ProbeContext, TracePointContext};
use aya_ebpf::EbpfContext;
use aya_log_ebpf::info;

use core::net::SocketAddrV4;
use ipvs_tcp_from_scratch_common::*;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod tracepoint_gen;

#[map]
static IPVS_TCP_MAP: HashMap<TcpKey, SocketAddrV4> = HashMap::with_max_entries(1024, 0);

#[map]
static mut TCP_EVENTS: PerfEventArray<TcpSocketEvent> = PerfEventArray::new(0);

#[tracepoint]
pub fn ipvs_tcp_from_scratch(ctx: TracePointContext) -> u32 {
    match try_ipvs_tcp_from_scratch(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_ipvs_tcp_from_scratch(ctx: TracePointContext) -> Result<u32, u32> {
    if let Some(ev) = make_ev_from_raw(&ctx) {
        let v = unsafe { IPVS_TCP_MAP.get(&ev.key) }.copied();
        if v.is_none() {
            return Ok(0);
        }
        let ev = TcpSocketEvent { ipvs_dest: v, ..ev };
        push_tcp_event(&ctx, &ev);
    }

    Ok(0)
}

fn make_ev_from_raw(ctx: &TracePointContext) -> Option<TcpSocketEvent> {
    let evt_ptr = ctx.as_ptr() as *const trace_event_raw_inet_sock_set_state;
    let evt = unsafe { evt_ptr.as_ref()? };
    if evt.protocol != IPPROTO_TCP {
        return None;
    }
    match evt.family {
        AF_INET => Family::IPv4,
        AF_INET6 => {
            // not supporting IPv6 for now
            return None;
        }
        other => {
            info!(ctx, "unknown family {}", other);
            return None;
        }
    };

    let ev = TcpSocketEvent {
        event: Event::StateChange {
            old: evt.oldstate.into(),
            new: evt.newstate.into(),
        },
        key: TcpKey {
            src: SocketAddrV4::new(evt.saddr.into(), evt.sport),
            dst: SocketAddrV4::new(evt.daddr.into(), evt.dport),
        },
        ipvs_dest: None,
    };
    Some(ev)
}

#[kprobe]
pub fn ip_vs_conn_new(ctx: ProbeContext) -> u32 {
    match try_ip_vs_conn_new(&ctx) {
        Ok(ret) => ret,
        Err(ret) => {
            info!(&ctx, "err code {}", ret);
            ret
        }
    }
}

// rustc why u dum
#[allow(dead_code)]
pub struct IpvsParam {
    src: SocketAddrV4,
    vdest: SocketAddrV4,
    rdest: SocketAddrV4,
}

fn try_ip_vs_conn_new(ctx: &ProbeContext) -> Result<u32, u32> {
    let conn_ptr: *const ip_vs_conn_param = ctx.arg(0).ok_or(0u32)?;

    let conn = unsafe {
        helpers::bpf_probe_read_kernel(&(*conn_ptr)).map_err(|x| {
            info!(ctx, "got err {}", x);
            1u32
        })?
    };
    if conn.protocol != IPPROTO_TCP {
        return Ok(0);
    }
    if conn.af != AF_INET {
        // Not supporting IPv6 for now
        return Ok(0);
    }
    let dport: u16 = ctx.arg(3).ok_or(0u32)?;

    let daddr_ptr: *const nf_inet_addr = ctx.arg(2).ok_or(0u32)?;
    let daddr = unsafe {
        helpers::bpf_probe_read_kernel(&(*daddr_ptr)).map_err(|x| {
            info!(ctx, "got err {}", x);
            1u32
        })?
    };

    let caddr = unsafe {
        helpers::bpf_probe_read_kernel(&(*conn.caddr)).map_err(|x| {
            info!(ctx, "got err {}", x);
            1u32
        })?
    };
    let vaddr = unsafe {
        helpers::bpf_probe_read_kernel(&(*conn.vaddr)).map_err(|x| {
            info!(ctx, "got err {}", x);
            1u32
        })?
    };
    let key = TcpKey {
        src: SocketAddrV4::new(
            u32::from_be(unsafe { caddr.ip }).into(),
            u16::from_be(conn.cport),
        ),
        dst: SocketAddrV4::new(
            u32::from_be(unsafe { vaddr.ip }).into(),
            u16::from_be(conn.vport),
        ),
    };
    let value = SocketAddrV4::new(
        u32::from_be(unsafe { daddr.ip }).into(),
        u16::from_be(dport),
    );
    if IPVS_TCP_MAP.insert(&key, &value, 0).is_ok() {
        info!(
            ctx,
            "IPVS mapping inserted {}:{} {}:{}",
            *key.src.ip(),
            key.src.port(),
            *key.dst.ip(),
            key.dst.port()
        );
    } else {
        info!(ctx, "failed to insert");
    }

    Ok(0)
}

#[kprobe]
pub fn tcp_connect(ctx: ProbeContext) -> u32 {
    match try_tcp_connect(&ctx) {
        Ok(_ev) => 0,
        Err(ret) => {
            info!(&ctx, "tcp_conn err code {}", ret);
            ret
        }
    }
}
fn tcp_key_from_sk_comm(ctx: &ProbeContext) -> Option<TcpKey> {
    let conn_ptr: *const sock = ctx.arg(0)?;
    let sk_comm = unsafe { helpers::bpf_probe_read_kernel(&((*conn_ptr).__sk_common)).ok()? };

    // By definition, `tcp_connect` is called with SynSent state
    // This `if` will never trigger -- it is here only to make the
    // expected precondition explicit
    if sk_comm.skc_state != TcpState::SynSent as u8 {
        return None;
    }

    if sk_comm.skc_family != AF_INET {
        // Not supporting IPv6 for now
        return None;
    }

    let sport = unsafe { sk_comm.__bindgen_anon_3.__bindgen_anon_1.skc_num };
    let vport = unsafe { sk_comm.__bindgen_anon_3.__bindgen_anon_1.skc_dport };
    let vport = u16::from_be(vport);

    let ip4daddr = unsafe { sk_comm.__bindgen_anon_1.__bindgen_anon_1.skc_daddr };
    let ip4saddr = unsafe { sk_comm.__bindgen_anon_1.__bindgen_anon_1.skc_rcv_saddr };

    Some(TcpKey {
        src: SocketAddrV4::new(u32::from_be(ip4saddr).into(), sport),
        dst: SocketAddrV4::new(u32::from_be(ip4daddr).into(), vport),
    })
}

fn tcp_key_from_sk_skb(ctx: &TracePointContext) -> Option<(TcpKey, TcpState)> {
    let evt_ptr = ctx.as_ptr() as *const trace_event_raw_tcp_event_sk_skb;
    let evt = unsafe { evt_ptr.as_ref()? };
    let state: TcpState = evt.state.into();
    let key = TcpKey {
        src: SocketAddrV4::new(u32::from_be_bytes(evt.saddr).into(), evt.sport),
        dst: SocketAddrV4::new(u32::from_be_bytes(evt.daddr).into(), evt.dport),
    };
    Some((key, state))
}

fn try_tcp_connect(ctx: &ProbeContext) -> Result<u32, u32> {
    if let Some(key) = tcp_key_from_sk_comm(ctx) {
        let ev = TcpSocketEvent {
            key,
            event: Event::StateChange {
                old: TcpState::Close,
                new: TcpState::SynSent,
            },
            ipvs_dest: None,
        };
        push_tcp_event(ctx, &ev);
    }
    Ok(0)
}

#[tracepoint]
pub fn tcp_retransmit_skb(ctx: TracePointContext) -> i64 {
    match try_tcp_retransmit_skb(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}
fn try_tcp_retransmit_skb(ctx: &TracePointContext) -> Result<i64, i64> {
    let Some((key, state)) = tcp_key_from_sk_skb(ctx) else {
        return Ok(0);
    };
    // We only care about connection opening, to detect timeouts
    if TcpState::SynSent != state {
        return Ok(0);
    }
    let v = unsafe { IPVS_TCP_MAP.get(&key) };
    if v.is_none() {
        // Not IPVS related, we don't care
        return Ok(0);
    }

    let evt = TcpSocketEvent {
        key,
        ipvs_dest: v.copied(),
        event: Event::ConnectRetrans,
    };
    push_tcp_event(ctx, &evt);
    Ok(0)
}

fn push_tcp_event<C: EbpfContext>(ctx: &C, evt: &TcpSocketEvent) {
    unsafe {
        #[allow(static_mut_refs)]
        TCP_EVENTS.output(ctx, evt, 0);
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
