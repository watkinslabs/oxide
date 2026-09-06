//! Raw DC ingress preserves handle widths and the complete GetDCEx region argument.
pub(crate) const GET_DC: u64 = 0x13eb;
pub(crate) const GET_DC_EX: u64 = 0x13ec;
pub(crate) const RELEASE_DC: u64 = 0x1509;
use ipc::win32_gdi::{DCX_CACHE, DCX_WINDOW, DCX_USESTYLE, DCX_INTERSECTRGN, DCX_EXCLUDERGN};
#[cfg(target_os = "oxide-kernel")]
#[path = "dc_raw/kernel.rs"]
pub(crate) mod kernel;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Request { Acquire { hwnd: u32, region: u32, flags: u32 }, Release { dc: u32 } }

/// Validate consumed identities only; ReleaseDC ignores HWND and returns BOOL.
/// # C: O(1) plus owner operation
pub(crate) fn route(ordinal: u64, args: &[u64], execute: impl FnOnce(Request) -> u64) -> Option<u64> {
    let request = match ordinal {
        GET_DC => {
            let Some(&hwnd) = args.first() else { return Some(0); };
            let Ok(hwnd) = u32::try_from(hwnd) else { return Some(0); };
            Request::Acquire { hwnd, region: 0, flags: if hwnd == 0 { DCX_CACHE | DCX_WINDOW } else { DCX_USESTYLE } }
        }
        GET_DC_EX => {
            let [hwnd, region, flags, ..] = args else { return Some(0); };
            let Ok(hwnd) = u32::try_from(*hwnd) else { return Some(0); };
            let flags = *flags as u32;
            let region = if flags & (DCX_INTERSECTRGN | DCX_EXCLUDERGN) != 0 {
                let Ok(region) = u32::try_from(*region) else { return Some(0); }; region
            } else { 0 };
            Request::Acquire { hwnd, region, flags }
        }
        RELEASE_DC => {
            let [_, dc, ..] = args else { return Some(0); };
            let Ok(dc) = u32::try_from(*dc) else { return Some(0); };
            Request::Release { dc }
        }
        _ => return None,
    };
    Some(execute(request))
}

#[cfg(test)]
#[path = "tests/dc_raw.rs"]
mod tests;
