#![no_std]
#![no_main]

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::info;

#[tracepoint]
pub fn ipvs_tcp_from_scratch(ctx: TracePointContext) -> u32 {
    match try_ipvs_tcp_from_scratch(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_ipvs_tcp_from_scratch(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "tracepoint tcp_set_state called");
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
