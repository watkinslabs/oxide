//! Bounded position diagnostics. Request/nccalc-input carry the old client;
//! nccalc-answer carries the raw callback rectangle, commit the adopted client.
use core::sync::atomic::{AtomicU32,Ordering};
use ipc::win32_window::WindowRect;
use crate::nt_wine_window::position::Request;

const LIMIT:u32=512;
static LINES:AtomicU32=AtomicU32::new(0);

/// Correlate requested and returned geometry without retaining window state. # C: O(1)
#[inline(never)]
pub(super) fn position(step:&'static [u8],request:&Request,token:u64,client:WindowRect,result:u64){
    if LINES.fetch_add(1,Ordering::Relaxed)>=LIMIT{return;}
    klog::write_raw(b"[WINDOWS-POSITION] hwnd=");klog::write_hex_u64(request.hwnd);
    klog::write_raw(b" token=");klog::write_hex_u64(token);
    klog::write_raw(b" step=");klog::write_raw(step);
    klog::write_raw(b" flags=");klog::write_hex_u64(request.flags as u64);
    klog::write_raw(b" outer=");rect(request.rect);
    klog::write_raw(b" client=");rect(client);
    klog::write_raw(b" result=");klog::write_hex_u64(result);
    klog::write_raw(b"\n");
}

fn rect(r:WindowRect){
    for (i,value) in [r.left,r.top,r.right,r.bottom].iter().enumerate(){
        if i!=0{klog::write_raw(b",");}klog::write_hex_u64(*value as i64 as u64);
    }
}
