//! Kernel execution of the font-family ordinals against canonical owners.
use super::{Prefetch, Request};

/// Both device-context extents are equal under the only mapping this owner
/// realizes, so the justification amount is used at its device magnitude.
const IDENTITY_EXTENT: i32 = 1;

/// Route one raw win32u font-family ordinal. # C: O(1) plus canonical owner cost
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    super::route(ordinal, args, prefetch, snapshot, crate::nt_native_gdi::begin_query, immediate)
}

fn prefetch(needed: Prefetch) -> Option<u64> {
    match needed {
        Prefetch::None => None,
        Prefetch::Dword(pointer) => uaccess::get_user_u32(pointer).ok().map(u64::from),
        Prefetch::Qword(pointer) => uaccess::get_user_u64(pointer).ok(),
    }
}

fn snapshot(dc: u64) -> Option<ipc::win32_gdi::Font> {
    crate::nt_gdi::text_snapshot_for_current(dc).ok().and_then(|state| state.font)
}

fn immediate(request: Request) -> u64 {
    match request {
        // A realization of the installed font set links no child font.
        Request::FontIsLinked => 0,
        Request::RasterizerCaps { status } => {
            let bytes = super::rasterizer_status(crate::nt_native_gdi::has_font_backend());
            u64::from(status != 0 && uaccess::copy_to_user(status, &bytes).is_ok())
        }
        Request::Justify { dc, extra, breaks } => {
            let Some(split) = super::justification(extra, breaks, IDENTITY_EXTENT, IDENTITY_EXTENT) else { return 0; };
            u64::from(crate::nt_gdi::set_justification_for_current(dc, split).is_ok())
        }
        Request::Query(_) => 0,
    }
}
