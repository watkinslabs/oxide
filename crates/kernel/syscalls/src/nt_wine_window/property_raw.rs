//! Canonical HWND property routing (`31fj`).
pub(crate) const GET: u64 = 0x1438;
pub(crate) const REMOVE: u64 = 0x151e;
pub(crate) const SET: u64 = 0x157f;

pub(crate) fn dispatch(ordinal: u64, args: [u64; 3]) -> Option<u64> {
    use crate::nt_window::property;
    Some(match ordinal {
        GET => property::get_prop_for_current(args[0], args[1]),
        REMOVE => property::remove_prop_for_current(args[0], args[1]),
        SET => property::set_prop_for_current(args[0], args[1], args[2]),
        _ => return None,
    })
}
