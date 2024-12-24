#![no_std]
#![no_main]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
include!(concat!(env!("OUT_DIR"), "/ipvs_bindings.rs"));

use crate::tracepoint_gen::trace_event_raw_inet_sock_set_state;

use aya_ebpf::helpers;
use aya_ebpf::macros::{kprobe, map, tracepoint};
use aya_ebpf::maps::HashMap;
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

#[allow(dead_code)]
struct TcpKey {
    src: SocketAddrV4,
    dst: SocketAddrV4,
}

#[tracepoint]
pub fn ipvs_tcp_from_scratch(ctx: TracePointContext) -> u32 {
    match try_ipvs_tcp_from_scratch(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_ipvs_tcp_from_scratch(ctx: TracePointContext) -> Result<u32, u32> {
    if let Some(ev) = make_ev_from_raw(&ctx) {
        let os_name: &'static str = ev.oldstate.into();
        let ns_name: &'static str = ev.newstate.into();
        let key = TcpKey {
            src: ev.src,
            dst: ev.dst,
        };

        info!(
            &ctx,
            "getting key {}:{} {}:{} for state {}->{}",
            *ev.src.ip(),
            ev.src.port(),
            *ev.dst.ip(),
            ev.dst.port(),
            os_name,
            ns_name,
        );
        let v = unsafe { IPVS_TCP_MAP.get(&key) }.copied();
        if v.is_none() {
            info!(&ctx, "Ignoring TCP conn not going to IPVS",);
            return Ok(0);
        }
        let v = v.unwrap();
        info!(
            &ctx,
            "TCP connection {}:{}->{}:{} (real {}:{}) changed state {}->{}",
            *ev.src.ip(),
            ev.src.port(),
            *ev.dst.ip(),
            ev.dst.port(),
            *v.ip(),
            v.port(),
            os_name,
            ns_name
        );
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
        oldstate: evt.oldstate.into(),
        newstate: evt.newstate.into(),
        src: SocketAddrV4::new(evt.saddr.into(), evt.sport),
        dst: SocketAddrV4::new(evt.daddr.into(), evt.dport),
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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
