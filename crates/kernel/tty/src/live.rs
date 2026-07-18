// Keyboard input routing + foreground-VT tracking.
//
// This was the legacy per-VT ring + ad-hoc N_TTY (VT_RINGS / VT_TERMIOS /
// VT_LINES / VT_WAITERS / per-VT pgrp+sid + canonical input + '\0' EOF
// sentinel) — a SECOND tty implementation parallel to the real
// `TtyStruct`/`NTty` core. That whole stack is gone: numbered VTs now run on
// per-VT `TtyStruct<VtConsoleDriver>` (console::vt_tty) and the system console
// on `static_console`, all on the ONE core (console-plan B4). What remains
// here is only:
//   * the keyboard → system-console input sink (`input_push_byte` →
//     registered `KBD_SINK`, wired to `console::static_console::rx_byte` at
//     boot), and
//   * `FOREGROUND_VT` tracking (`set_foreground`/`foreground`) for the
//     VT_ACTIVATE / Ctrl-Alt-Fn keyboard-foreground target.

use core::sync::atomic::{AtomicPtr, AtomicU8, Ordering};

/// Number of distinct numbered-VT slots (1..=N_VT). VT 0 is the
/// "foreground alias" (`/dev/console`/`/dev/tty`/`/dev/tty0`).
pub const N_VT: usize = 63;

/// Foreground VT (1..=N_VT) — the keyboard-input target a VT switch sets.
static FOREGROUND_VT: AtomicU8 = AtomicU8::new(1);

/// Keyboard → console input sink. The physical keyboard drives the VT
/// subsystem (Linux: the VT keyboard driver feeds the FOREGROUND VT's flip
/// buffer / N_TTY). Registered at boot (`kmain` runtime) to `console::kbd_input`,
/// which pushes each byte into the foreground numbered VT's `TtyStruct`
/// (`console::vt_tty`) — NOT the serial `static_console`. `null` = not yet
/// installed.
static KBD_SINK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Register the keyboard → system-console RX sink (boot wiring, once).
/// # C: O(1)
pub fn set_kbd_sink(f: fn(u8)) {
    KBD_SINK.store(f as *mut (), Ordering::Release);
}

/// Public input entry point. virtio-input (keyboard) translates each EV_KEY
/// press to an ASCII byte and delivers it to the FOREGROUND console's line
/// discipline — the same N_TTY RX path a UART byte takes — so
/// getty/login/shell on `/dev/console` see keystrokes (cooked + echoed) on the
/// framebuffer. Dropped before the sink is installed (no keypress can occur
/// that early); there is no legacy ring fallback anymore.
/// # C: O(1) + sink cost
pub fn input_push_byte(b: u8) {
    let raw = KBD_SINK.load(Ordering::Acquire);
    if raw.is_null() { return; }
    // SAFETY: KBD_SINK is only set via set_kbd_sink with a non-null fn(u8) cast through `as *mut ()`; the reverse cast restores the identical signature.
    let f: fn(u8) = unsafe { core::mem::transmute::<*mut (), fn(u8)>(raw) };
    f(b);
}

/// Currently-foreground VT id (1..=N_VT). procfs / introspection.
/// # C: O(1)
pub fn foreground() -> u8 {
    FOREGROUND_VT.load(Ordering::Acquire)
}

/// Foreground-VT keyboard-mode queries. The fbcon VT layer owns the per-VT
/// emulators (DECCKM / bracketed-paste live there); these fn-pointers are
/// registered at boot so the keyboard driver (`tty` dep only) and the
/// selection-paste path can read the FOREGROUND VT's mode without a direct
/// fbcon dependency (Linux `applkey` reads `vc_cons[fg_console]`). `null` =
/// not installed → mode off.
static APP_CURSOR_Q: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static BRACKETED_Q: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Register the foreground-VT DECCKM query (boot wiring, once). # C: O(1)
pub fn set_app_cursor_query(f: fn() -> bool) {
    APP_CURSOR_Q.store(f as *mut (), Ordering::Release);
}

/// Register the foreground-VT bracketed-paste query (boot wiring). # C: O(1)
pub fn set_bracketed_paste_query(f: fn() -> bool) {
    BRACKETED_Q.store(f as *mut (), Ordering::Release);
}

/// Clear foreground-VT mode query hooks when the owning console driver is
/// unregistered.
/// # C: O(1)
pub fn clear_vt_mode_queries() {
    APP_CURSOR_Q.store(core::ptr::null_mut(), Ordering::Release);
    BRACKETED_Q.store(core::ptr::null_mut(), Ordering::Release);
}

fn query(slot: &AtomicPtr<()>) -> bool {
    let raw = slot.load(Ordering::Acquire);
    if raw.is_null() {
        return false;
    }
    // SAFETY: slot is only ever set via the matching set_*_query with a non-null fn() -> bool cast through `as *mut ()`; the reverse transmute restores the identical signature.
    let f: fn() -> bool = unsafe { core::mem::transmute::<*mut (), fn() -> bool>(raw) };
    f()
}

/// DECCKM (application cursor keys) of the foreground VT. The keyboard
/// driver encodes arrows as `ESC O x` when set. # C: O(1) + query cost
pub fn fg_app_cursor() -> bool {
    query(&APP_CURSOR_Q)
}

/// Bracketed-paste mode of the foreground VT. The selection-paste path
/// wraps pasted bytes in `ESC[200~`…`ESC[201~` when set. # C: O(1) + query
pub fn fg_bracketed_paste() -> bool {
    query(&BRACKETED_Q)
}

/// Set the foreground VT (the keyboard-input target). Called by `vt::activate`
/// (VT_ACTIVATE ioctl + Ctrl-Alt-Fn). Out-of-range clamps to 1..=N_VT.
/// # C: O(1)
pub fn set_foreground(vt: u8) {
    let clamped = (vt.max(1) as usize).min(N_VT) as u8;
    FOREGROUND_VT.store(clamped, Ordering::Release);
}
