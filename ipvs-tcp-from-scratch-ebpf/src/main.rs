#![no_std]
#![no_main]

use crate::tracepoint_gen::trace_event_raw_inet_sock_set_state;
use aya_ebpf::EbpfContext;
use aya_ebpf::{macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::info;
use core::net::SocketAddrV4;
use ipvs_tcp_from_scratch_common::*;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod tracepoint_gen;

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
        info!(
            &ctx,
            "TCP connection {}:{}->{}:{} changed state {}->{}",
            *ev.src.ip(),
            ev.src.port(),
            *ev.dst.ip(),
            ev.dst.port(),
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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
