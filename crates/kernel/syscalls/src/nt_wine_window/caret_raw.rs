// Uniform caret syscall admission; masks never guessed for bitmap requests.
use crate::nt_window::caret::{self, live, publish::Current};

pub(crate) const GET_CARET_BLINK_TIME_ORDINAL: u64 = 0x13d5;
pub(crate) const GET_CARET_POS_ORDINAL: u64 = 0x13d6;
pub(crate) const SET_CARET_BLINK_TIME_ORDINAL: u64 = 0x153b;

/// Complete the raw GetCaretPos contract after Main validates the user
/// pointer. The copyout is supplied by the raw boundary, outside GUI state.
/// # C: O(GUI entries + queues)
pub(crate) fn get_caret_pos(address: u64, copyout: impl FnOnce(u64, [u8; 8]) -> bool) -> Option<u64> {
    if address == 0 { return Some(0); }
    if address.checked_add(8).is_none() { return Some(0); }
    let position = crate::nt_window::caret::query::position_for_current();
    let Some(position) = position else { return Some(0); };
    let mut bytes = [0u8; 8];
    bytes[0..4].copy_from_slice(&position.x.to_le_bytes());
    bytes[4..8].copy_from_slice(&position.y.to_le_bytes());
    Some(copyout(address, bytes) as u64)
}

/// Route caret settings and position through the same bounded copyout seam as
/// the raw kernel entry. The callback is never called while canonical state is
/// borrowed, and receives exactly the eight-byte POINT payload.
/// # C: O(GUI entries + queues + bounded usercopy)
pub(crate) fn dispatch_with_copyout(ordinal: u64, args: [u64; 4], copyout: impl FnOnce(u64, [u8; 8]) -> bool) -> Option<u64> {
    match ordinal {
        GET_CARET_BLINK_TIME_ORDINAL => return Some(crate::nt_window::settings::get_caret_blink_time()),
        SET_CARET_BLINK_TIME_ORDINAL => return Some(crate::nt_window::settings::set_caret_blink_time(args[0] as u32) as u64),
        GET_CARET_POS_ORDINAL => return get_caret_pos(args[0], copyout),
        _ => {}
    }
    let mut sink = Current;
    Some(match ordinal {
        caret::CREATE_CARET_ORDINAL => {
            if args[1] != 0 { return Some(0); }
            let width = if args[2] as i32 == 0 { 1 } else { args[2] as i32 };
            let height = if args[3] as i32 == 0 { 1 } else { args[3] as i32 };
            if width <= 0 || height <= 0 || width as u32 > syscall::nt_compositor::MAX_DIMENSION
                || height as u32 > syscall::nt_compositor::MAX_DIMENSION
                || width as u64 * height as u64 > (syscall::nt_compositor::caret::MAX_MASK_BYTES / 4) as u64 { return Some(0); }
            live::create_caret_for_current(args[0], width, height, &mut sink)
        }
        caret::DESTROY_CARET_ORDINAL => live::destroy_caret_for_current(&mut sink),
        caret::SET_CARET_POS_ORDINAL => live::set_caret_pos_for_current(args[0] as i32, args[1] as i32, &mut sink),
        caret::SHOW_CARET_ORDINAL => live::show_caret_for_current(args[0], &mut sink),
        caret::HIDE_CARET_ORDINAL => live::hide_caret_for_current(args[0], &mut sink),
        _ => return None,
    })
}

#[cfg(target_os = "oxide-kernel")]
pub(crate) fn dispatch(ordinal: u64, args: [u64; 4]) -> Option<u64> {
    dispatch_with_copyout(ordinal, args, |address, bytes| uaccess::copy_to_user(address, &bytes).is_ok())
}

#[cfg(not(target_os = "oxide-kernel"))]
pub(crate) fn dispatch(ordinal: u64, args: [u64; 4]) -> Option<u64> {
    dispatch_with_copyout(ordinal, args, |_, _| false)
}
