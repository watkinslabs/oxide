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

/// Keyboard → system-console input sink. The interactive console (where
/// `console-getty` runs) is `/dev/console` — a real `TtyStruct`/N_TTY fed
/// from the UART RX. The physical keyboard is just a SECOND input source for
/// that same console (Linux: the VT keyboard driver feeds the foreground
/// console tty's flip buffer). Registered at boot to
/// `console::static_console::rx_byte`. `null` = not yet installed.
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

/// Set the foreground VT (the keyboard-input target). Called by `vt::activate`
/// (VT_ACTIVATE ioctl + Ctrl-Alt-Fn). Out-of-range clamps to 1..=N_VT.
/// # C: O(1)
pub fn set_foreground(vt: u8) {
    let clamped = (vt.max(1) as usize).min(N_VT) as u8;
    FOREGROUND_VT.store(clamped, Ordering::Release);
}
