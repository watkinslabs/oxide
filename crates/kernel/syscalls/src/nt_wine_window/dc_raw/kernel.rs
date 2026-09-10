//! Raw DC operations call the canonical lease owner, with NULL/BOOL result channels.
use super::Request;
/// # C: canonical DC operation cost
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    super::route(ordinal, args, |request| match request {
        Request::Acquire { hwnd, region, flags } => {
            let dc=crate::nt_gdi::get_dc_ex_for_current(hwnd, region, flags);
            trace_acquire(hwnd,region,flags,dc);dc
        }
        Request::Release { dc } => u64::from(crate::nt_gdi::release_dc_lease_for_current(dc)),
    })
}

#[cfg(feature="debug-wingeom")]
fn trace_acquire(hwnd:u32,region:u32,flags:u32,dc:u64){
    klog::write_raw(b"[WINDOWS-DC-ACQUIRE] hwnd=");klog::write_hex_u64(hwnd as u64);
    klog::write_raw(b" region=");klog::write_hex_u64(region as u64);
    klog::write_raw(b" flags=");klog::write_hex_u64(flags as u64);
    klog::write_raw(b" dc=");klog::write_hex_u64(dc);klog::write_raw(b"\n");
}
#[cfg(not(feature="debug-wingeom"))]
fn trace_acquire(_:u32,_:u32,_:u32,_:u64){}
