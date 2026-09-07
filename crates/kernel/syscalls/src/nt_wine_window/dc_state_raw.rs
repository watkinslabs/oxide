//! Raw device-context state ingress: save stack, layout, bounds, limits,
//! pixel format, client objects and extended pens.
//!
//! Decoding only. Every user buffer is named by address and copied by the
//! kernel binding after the canonical owner has answered.

/// Discard a print job on a device context.
pub(crate) const CANCEL_DC: u64 = 0x109b;
/// Reset a device context to a new device mode.
pub(crate) const RESET_DC: u64 = 0x125d;
/// Pop the save stack down to one level.
pub(crate) const RESTORE_DC: u64 = 0x125f;
/// Push one level onto the save stack.
pub(crate) const SAVE_DC: u64 = 0x1266;
/// Install a text layout direction.
pub(crate) const SET_LAYOUT: u64 = 0x127d;
/// Read the accumulated drawing bounds.
pub(crate) const GET_BOUNDS_RECT: u64 = 0x11e0;
/// Change bounds accumulation.
pub(crate) const SET_BOUNDS_RECT: u64 = 0x1273;
/// Read the colour adjustment.
pub(crate) const GET_COLOR_ADJUSTMENT: u64 = 0x11eb;
/// Install a colour adjustment.
pub(crate) const SET_COLOR_ADJUSTMENT: u64 = 0x1276;
/// Read the device gamma ramp.
pub(crate) const GET_DEVICE_GAMMA_RAMP: u64 = 0x11f6;
/// Install a device gamma ramp.
pub(crate) const SET_DEVICE_GAMMA_RAMP: u64 = 0x1279;
/// Read the miter limit.
pub(crate) const GET_MITER_LIMIT: u64 = 0x1209;
/// Install a miter limit.
pub(crate) const SET_MITER_LIMIT: u64 = 0x1281;
/// Complete every pending drawing operation.
pub(crate) const FLUSH: u64 = 0x11d5;
/// Allocate an opaque client object handle.
pub(crate) const CREATE_CLIENT_OBJ: u64 = 0x10aa;
/// Release an opaque client object handle.
pub(crate) const DELETE_CLIENT_OBJ: u64 = 0x118c;
/// Create an enhanced-metafile device context.
pub(crate) const CREATE_METAFILE_DC: u64 = 0x10b5;
/// Describe one pixel format.
pub(crate) const DESCRIBE_PIXEL_FORMAT: u64 = 0x1190;
/// Claim a pixel format for a device context.
pub(crate) const SET_PIXEL_FORMAT: u64 = 0x1285;
/// Present the back buffer.
pub(crate) const SWAP_BUFFERS: u64 = 0x1293;
/// Create an extended pen.
pub(crate) const EXT_CREATE_PEN: u64 = 0x11c3;

/// Windows argument counts, in words, for the ordinals this family owns.
const CALLS: &[(u64, usize)] = &[
    (CANCEL_DC, 1), (CREATE_CLIENT_OBJ, 1), (CREATE_METAFILE_DC, 1), (DELETE_CLIENT_OBJ, 1),
    (DESCRIBE_PIXEL_FORMAT, 4), (FLUSH, 0), (GET_BOUNDS_RECT, 3), (GET_COLOR_ADJUSTMENT, 2),
    (GET_DEVICE_GAMMA_RAMP, 2), (GET_MITER_LIMIT, 2), (EXT_CREATE_PEN, 11), (RESET_DC, 5),
    (RESTORE_DC, 2), (SAVE_DC, 1), (SET_BOUNDS_RECT, 3), (SET_COLOR_ADJUSTMENT, 2),
    (SET_DEVICE_GAMMA_RAMP, 2), (SET_LAYOUT, 3), (SET_MITER_LIMIT, 3), (SET_PIXEL_FORMAT, 2),
    (SWAP_BUFFERS, 1),
];

/// # C: O(N_family_ordinals)
pub(crate) fn argument_count(ordinal: u64) -> Option<usize> {
    CALLS.iter().find(|entry| entry.0 == ordinal).map(|entry| entry.1)
}

/// The longest signature this family carries.
pub(crate) const MAX_ARGUMENTS: usize = 11;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Call {
    /// A call whose result the reference reports without consulting any state.
    Constant(u64),
    SaveDc { dc: u32 },
    RestoreDc { dc: u32, level: i32 },
    ResetDc { dc: u32 },
    SetLayout { dc: u32, layout: u32 },
    GetBoundsRect { dc: u32, rect: u64, flags: u32 },
    SetBoundsRect { dc: u32, rect: u64, flags: u32 },
    GetMiterLimit { dc: u32, limit: u64 },
    SetMiterLimit { dc: u32, limit_bits: u32, previous: u64 },
    SetPixelFormat { dc: u32, format: i32 },
    CreateClientObj { kind: u32 },
    DeleteClientObj { handle: u32 },
    CreateMetafileDc,
    ExtCreatePen { style: u32, width: u32, brush_style: u32, color: u32, style_count: u32, style_bits: u64 },
}

/// Every call in this family reports zero when its device context cannot be
/// resolved, except the layout query, which reports the GDI error sentinel.
const FALSE: u64 = 0;
/// The reference reports success for these whatever the device context holds.
const TRUE: u64 = 1;

/// Decode and run one call. An ordinal this family owns is always consumed:
/// an argument it cannot admit reports the family's own failure value rather
/// than falling through to an unrelated router. # C: O(N_family_ordinals)
pub(crate) fn route(ordinal: u64, args: &[u64], execute: impl FnOnce(Call) -> u64) -> Option<u64> {
    argument_count(ordinal)?;
    Some(match decode(ordinal, args) { Some(call) => execute(call), None => failure(ordinal) })
}

/// # C: O(1)
pub(crate) fn decode(ordinal: u64, args: &[u64]) -> Option<Call> {
    let dc = |index: usize| args.get(index).copied().and_then(|value| u32::try_from(value).ok());
    let call = match ordinal {
        // The reference discards no job here and reports success unconditionally.
        CANCEL_DC => Call::Constant(TRUE),
        // No pending drawing outlives a syscall return, so the flush is complete.
        FLUSH => Call::Constant(TRUE),
        // No colour adjustment is carried by any device context.
        GET_COLOR_ADJUSTMENT | SET_COLOR_ADJUSTMENT => Call::Constant(FALSE),
        // The gamma ramp read reports success and writes nothing; the write is
        // refused by every driver.
        GET_DEVICE_GAMMA_RAMP => Call::Constant(TRUE),
        SET_DEVICE_GAMMA_RAMP => Call::Constant(FALSE),
        // No pixel format is described and no back buffer is presented without
        // an accelerated driver.
        DESCRIBE_PIXEL_FORMAT => Call::Constant(0),
        SWAP_BUFFERS => Call::Constant(FALSE),
        SAVE_DC => Call::SaveDc { dc: dc(0)? },
        RESTORE_DC => Call::RestoreDc { dc: dc(0)?, level: *args.get(1)? as u32 as i32 },
        RESET_DC => Call::ResetDc { dc: dc(0)? },
        SET_LAYOUT => Call::SetLayout { dc: dc(0)?, layout: *args.get(2)? as u32 },
        GET_BOUNDS_RECT => Call::GetBoundsRect { dc: dc(0)?, rect: *args.get(1)?, flags: *args.get(2)? as u32 },
        SET_BOUNDS_RECT => Call::SetBoundsRect { dc: dc(0)?, rect: *args.get(1)?, flags: *args.get(2)? as u32 },
        GET_MITER_LIMIT => Call::GetMiterLimit { dc: dc(0)?, limit: *args.get(1)? },
        SET_MITER_LIMIT => Call::SetMiterLimit { dc: dc(0)?, limit_bits: *args.get(1)? as u32, previous: *args.get(2)? },
        SET_PIXEL_FORMAT => Call::SetPixelFormat { dc: dc(0)?, format: *args.get(1)? as u32 as i32 },
        CREATE_CLIENT_OBJ => Call::CreateClientObj { kind: *args.get(0)? as u32 },
        DELETE_CLIENT_OBJ => Call::DeleteClientObj { handle: u32::try_from(*args.get(0)?).ok()? },
        CREATE_METAFILE_DC => Call::CreateMetafileDc,
        EXT_CREATE_PEN => Call::ExtCreatePen {
            style: *args.get(0)? as u32, width: *args.get(1)? as u32, brush_style: *args.get(2)? as u32,
            color: *args.get(3)? as u32, style_count: *args.get(6)? as u32, style_bits: *args.get(7)? },
        _ => return None,
    };
    Some(call)
}

/// A handle argument this family cannot admit still consumed the ordinal, so
/// the caller reports the family's failure value rather than falling through
/// to an unrelated router. # C: O(1)
pub(crate) fn failure(ordinal: u64) -> u64 {
    if ordinal == SET_LAYOUT { u64::from(ipc::win32_gdi::GDI_ERROR) } else { FALSE }
}

#[cfg(target_os = "oxide-kernel")]
#[path = "dc_state_raw/kernel.rs"]
pub(crate) mod kernel;

#[cfg(test)]
#[path = "tests/dc_state_raw.rs"]
mod tests;
