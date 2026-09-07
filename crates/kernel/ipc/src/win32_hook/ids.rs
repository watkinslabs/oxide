//! Hook identifiers, chain index mapping and the WinEvent bounds.

pub const WH_MSGFILTER: i32 = -1;
pub const WH_JOURNALRECORD: i32 = 0;
pub const WH_JOURNALPLAYBACK: i32 = 1;
pub const WH_KEYBOARD: i32 = 2;
pub const WH_GETMESSAGE: i32 = 3;
pub const WH_CALLWNDPROC: i32 = 4;
pub const WH_CBT: i32 = 5;
pub const WH_SYSMSGFILTER: i32 = 6;
pub const WH_CALLWNDPROCRET: i32 = 12;
pub const WH_KEYBOARD_LL: i32 = 13;
pub const WH_MOUSE_LL: i32 = 14;
pub const WH_MINHOOK: i32 = WH_MSGFILTER;
pub const WH_MAXHOOK: i32 = WH_MOUSE_LL;
/// WinEvent hooks share the hook table one chain past the last window hook.
pub const WH_WINEVENT: i32 = WH_MAXHOOK + 1;
/// Number of chains one table carries.
pub const NB_HOOKS: usize = (WH_WINEVENT - WH_MINHOOK + 1) as usize;

pub const EVENT_MIN: u32 = 0x0000_0001;
pub const EVENT_MAX: u32 = 0x7fff_ffff;

pub const WINEVENT_OUTOFCONTEXT: u32 = 0x0000;
pub const WINEVENT_SKIPOWNTHREAD: u32 = 0x0001;
pub const WINEVENT_SKIPOWNPROCESS: u32 = 0x0002;
pub const WINEVENT_INCONTEXT: u32 = 0x0004;

/// Chain index for one hook identifier, or none when out of range. # C: O(1)
pub const fn chain_index(id: i32) -> Option<usize> {
    if id < WH_MINHOOK || id > WH_WINEVENT { return None; }
    Some((id - WH_MINHOOK) as usize)
}

/// Identifiers that may not be installed for a single thread. # C: O(1)
pub const fn hook_name_is_global_only(id: i32) -> bool {
    matches!(id, WH_JOURNALRECORD | WH_JOURNALPLAYBACK | WH_KEYBOARD_LL | WH_MOUSE_LL | WH_SYSMSGFILTER)
}
