//! Windows hook chains: per-thread and desktop-global tables, the WinEvent
//! range filters, and the chain walk a hook call consults.
//!
//! Module manifest:
//! - `ids.rs`     — hook identifiers, chain index mapping, event bounds.
//! - `install.rs` — installation admission ladder (global-only, module rules).
//! - `chain.rs`   — chain insertion, removal and the ordered walk.
//! - `lifetime.rs`— active walks retain removed cursor records.
//! - `tests/`     — admission and chain-order contracts.

use alloc::vec::Vec;

#[path = "win32_hook/ids.rs"]
mod ids;
pub use ids::{chain_index, hook_name_is_global_only, EVENT_MAX, EVENT_MIN, NB_HOOKS, WH_CALLWNDPROC,
    WH_CALLWNDPROCRET, WH_CBT, WH_GETMESSAGE, WH_JOURNALPLAYBACK, WH_JOURNALRECORD, WH_KEYBOARD,
    WH_KEYBOARD_LL, WH_MAXHOOK, WH_MINHOOK, WH_MOUSE_LL, WH_MSGFILTER, WH_SYSMSGFILTER, WH_WINEVENT,
    WINEVENT_INCONTEXT, WINEVENT_OUTOFCONTEXT, WINEVENT_SKIPOWNPROCESS, WINEVENT_SKIPOWNTHREAD};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum HookError {
    /// The hook procedure pointer is absent.
    InvalidFilterProc,
    /// This identifier may only be installed system-wide.
    GlobalOnlyHook,
    /// Journal hooks are refused system-wide.
    AccessDenied,
    /// A global hook of this identifier needs a module.
    HookNeedsModule,
    /// The event range is inverted.
    InvalidHookFilter,
    InvalidParameter,
    InvalidHandle,
    NoMemory,
}

/// One installed hook. `thread` absent marks a desktop-global hook.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hook {
    pub handle: u32,
    pub id: i32,
    pub process: Option<u64>,
    pub thread: Option<u64>,
    /// Thread that installed it; a low-level hook runs there, not in the hooked thread.
    pub owner: u64,
    pub event_min: u32,
    pub event_max: u32,
    pub flags: u32,
    pub proc_address: u64,
    pub unicode: bool,
    pub module: Vec<u16>,
}

/// One installation request, already carrying the caller's identity.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct HookRequest<'a> {
    pub id: i32,
    pub process: Option<u64>,
    pub thread: Option<u64>,
    pub owner: u64,
    pub event_min: u32,
    pub event_max: u32,
    pub flags: u32,
    pub proc_address: u64,
    pub unicode: bool,
    pub module: &'a [u16],
}

/// Chains for one scope. A desktop owns one global table; each thread owns its own.
#[derive(Default)]
pub struct HookTable { hooks: Vec<Hook>, next_handle: u32, active: [u32; NB_HOOKS] }

#[path = "win32_hook/install.rs"]
mod install;
pub use install::{admit_table_install, admit_win_event_hook, admit_window_hook, HookScope};
#[path = "win32_hook/chain.rs"]
mod chain;
pub use chain::{runs_in_owner_thread, runs_in_thread, HookThread};
#[path = "win32_hook/registry.rs"]
mod registry;
pub use registry::{ChainLease, HookLocation, HookRegistry};
#[path = "win32_hook/lifetime.rs"]
mod lifetime;

#[cfg(test)]
#[path = "win32_hook/tests/install.rs"]
mod install_tests;
#[cfg(test)]
#[path = "win32_hook/tests/chain.rs"]
mod chain_tests;

#[cfg(test)]
#[path = "win32_hook/tests/lifetime.rs"]
mod lifetime_tests;
