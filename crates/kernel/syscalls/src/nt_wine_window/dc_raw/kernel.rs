//! Raw DC operations call the canonical lease owner, with NULL/BOOL result channels.
use super::Request;
/// # C: canonical DC operation cost
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    super::route(ordinal, args, |request| match request {
        Request::Acquire { hwnd, region, flags } => crate::nt_gdi::get_dc_ex_for_current(hwnd, region, flags),
        Request::Release { dc } => u64::from(crate::nt_gdi::release_dc_lease_for_current(dc)),
    })
}
