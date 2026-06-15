//! fenv non-target fallback (docs/59§6 G15). Dev boxes may type-check the rlib
//! on an arch with no x86/aarch64 FP-env register access; this shim keeps the
//! symbols resolving. Real FP-env behavior + the differential conformance test
//! run on x86_64/aarch64 only. No inline asm, no register effects.
use core::cell::Cell;
use super::FE_TONEAREST;

/// `fenv_t` — opaque round + flags + enable store (no host register).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct fenv_t {
    pub round: i32,
    pub flags: i32,
    pub enabled: i32,
}

/// `femode_t` — opaque round + enable store.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct femode_t {
    pub round: i32,
    pub enabled: i32,
}

// Single-threaded shim state (this path is the non-target type-check only).
struct S { round: Cell<i32>, flags: Cell<i32>, enabled: Cell<i32> }
// SAFETY: the fallback backend is only built for non-target type-checking,
// never linked into a running multi-threaded artifact; the Cells are never
// shared across threads in that single-purpose build path.
unsafe impl Sync for S {}
static STATE: S = S { round: Cell::new(FE_TONEAREST), flags: Cell::new(0), enabled: Cell::new(0) };

pub(super) fn testexcept() -> i32 { STATE.flags.get() & super::FE_ALL_EXCEPT }
pub(super) fn clearexcept(e: i32) { STATE.flags.set(STATE.flags.get() & !e); }
pub(super) fn setexcept(e: i32) { STATE.flags.set(STATE.flags.get() | (e & super::FE_ALL_EXCEPT)); }
pub(super) fn raiseexcept(e: i32) { setexcept(e); }
pub(super) fn getround() -> i32 { STATE.round.get() }
pub(super) fn setround(m: i32) { STATE.round.set(m); }
pub(super) fn getexcept() -> i32 { STATE.enabled.get() }
pub(super) fn enableexcept(e: i32) { STATE.enabled.set(STATE.enabled.get() | e); }
pub(super) fn disableexcept(e: i32) { STATE.enabled.set(STATE.enabled.get() & !e); }
pub(super) fn getenv() -> fenv_t { fenv_t { round: STATE.round.get(), flags: STATE.flags.get(), enabled: STATE.enabled.get() } }
pub(super) fn setenv(e: &fenv_t) { STATE.round.set(e.round); STATE.flags.set(e.flags); STATE.enabled.set(e.enabled); }
pub(super) fn set_default_env() -> i32 { STATE.round.set(FE_TONEAREST); STATE.flags.set(0); STATE.enabled.set(0); 0 }
pub(super) fn getmode() -> femode_t { femode_t { round: STATE.round.get(), enabled: STATE.enabled.get() } }
pub(super) fn setmode(m: &femode_t) { STATE.round.set(m.round); STATE.enabled.set(m.enabled); }
pub(super) fn set_default_mode() -> i32 { STATE.round.set(FE_TONEAREST); STATE.enabled.set(0); 0 }
