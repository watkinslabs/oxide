use core::sync::atomic::AtomicU64;

use crate::keymap::{self, Mods, Side};

// Linux KEY_* identifiers for modifier keys. The keymap text file owns
// printable keycodes; modifiers stay hard-wired here so a broken keymap can
// never lock the user out of layout switching.
const KEY_LEFTCTRL:   u16 = 29;
const KEY_LEFTSHIFT:  u16 = 42;
const KEY_RIGHTSHIFT: u16 = 54;
const KEY_LEFTALT:    u16 = 56;
const KEY_CAPSLOCK:   u16 = 58;
const KEY_NUMLOCK:    u16 = 69;
const KEY_SCROLLLOCK: u16 = 70;
const KEY_RIGHTCTRL:  u16 = 97;
const KEY_RIGHTALT:   u16 = 100; // a.k.a. AltGr
const KEY_LEFTMETA:   u16 = 125; // Super / Win
const KEY_RIGHTMETA:  u16 = 126;

const KEY_DELETE:   u16 = 111;
const KEY_PAGEUP:   u16 = 104;
const KEY_PAGEDOWN: u16 = 109;
const KEY_F1:       u16 = 59;
const KEY_F12:      u16 = 88;

pub static DRAINED_KEYS: AtomicU64 = AtomicU64::new(0);

/// If `keycode` is a function key while Ctrl+Alt are held, switch the
/// foreground VT to F<n> (Linux Ctrl-Alt-F<n>) and return `true`.
/// # C: O(cols*rows) on switch (full repaint), else O(1).
fn handle_vt_switch(keycode: u16, pressed: bool) -> bool {
    if !pressed {
        return is_fkey(keycode) && keymap::mods().contains(Mods::CTRL | Mods::ALT);
    }
    let m = keymap::mods();
    if !m.contains(Mods::CTRL) || !m.contains(Mods::ALT) { return false; }
    let vt = match keycode {
        KEY_F1..=68 => (keycode - KEY_F1 + 1) as u8,
        87 => 11u8,
        KEY_F12 => 12u8,
        _ => return false,
    };
    let _ = vt::activate(vt);
    true
}

/// Ctrl-Alt-Delete follows the configured `C_A_D` policy:
///   set   -> `schedule_work(&cad_work)` -> `kernel_restart(NULL)`
///   clear -> `kill_cad_pid(SIGINT, 1)` — init runs an orderly shutdown.
///
/// The restart is DEFERRED onto the workqueue exactly as Linux defers it: this
/// runs from the input drain, which must not shut every device down or triple-
/// fault in place. `reboot(2)`'s `LINUX_REBOOT_CMD_CAD_ON`/`CAD_OFF` — which
/// systemd issues at startup — exist solely to steer this decision, so without
/// this consumer both commands would latch a flag nothing ever reads.
/// # C: O(N_tasks) to find init, else O(1).
#[cfg(target_os = "oxide-kernel")]
fn deferred_cad(_arg: usize) {
    // SAFETY: runs on a kworker in process context, exactly where Linux's `deferred_cad` work item runs; the restart is irreversible by contract.
    unsafe { power::terminal(power::TerminalCmd::Restart) }
}

fn handle_ctrl_alt_del(keycode: u16, pressed: bool) -> bool {
    if keycode != KEY_DELETE { return false; }
    let m = keymap::mods();
    if !m.contains(Mods::CTRL) || !m.contains(Mods::ALT) { return false; }
    // Consume the release too, so the keycode never reaches the ldisc.
    if !pressed { return true; }
    #[cfg(target_os = "oxide-kernel")]
    match power::cad_action(power::cad_enabled()) {
        power::CadAction::Restart => {
            let _ = sched::live::workqueue::queue_work(deferred_cad, 0);
        }
        power::CadAction::SignalInit => {
            if let Some(init) = sched::live::initial_init_task() {
                // Linux `ctrl_alt_del` -> `kill_cad_pid(SIGINT, 1)`, i.e.
                // `kill_pid(..., priv = 1)` = SEND_SIG_PRIV: init cannot ignore
                // the Ctrl-Alt-Del request away.
                sched::live::send_sig_priv_group(&init, sched::Signum::Sigint as u32);
            }
        }
    }
    true
}

/// Shift+PgUp / Shift+PgDn scroll the foreground VT scrollback.
/// # C: O(cols*rows) on a scroll (full repaint), else O(1).
fn handle_scroll(keycode: u16, pressed: bool) -> bool {
    if keycode != KEY_PAGEUP && keycode != KEY_PAGEDOWN { return false; }
    if !keymap::mods().contains(Mods::SHIFT) { return false; }
    if pressed {
        let step = 12isize;
        let delta = if keycode == KEY_PAGEUP { step } else { -step };
        vt::scrolldelta(delta);
    }
    true
}

/// Is `keycode` one of the F1..F12 keys we treat as a VT-switch trigger?
/// # C: O(1).
fn is_fkey(keycode: u16) -> bool {
    matches!(keycode, KEY_F1..=68 | 87 | KEY_F12)
}

fn handle_modifier(keycode: u16, pressed: bool) -> bool {
    match keycode {
        KEY_LEFTSHIFT  => { keymap::set_side(Side::ShiftLeft,  pressed); true }
        KEY_RIGHTSHIFT => { keymap::set_side(Side::ShiftRight, pressed); true }
        KEY_LEFTCTRL   => { keymap::set_side(Side::CtrlLeft,   pressed); true }
        KEY_RIGHTCTRL  => { keymap::set_side(Side::CtrlRight,  pressed); true }
        KEY_LEFTALT    => { keymap::set_side(Side::AltLeft,    pressed); true }
        KEY_RIGHTALT   => { keymap::set_side(Side::AltRight,   pressed); true }
        KEY_LEFTMETA | KEY_RIGHTMETA => { keymap::set_mod(Mods::META, pressed); true }
        KEY_CAPSLOCK   => { if pressed { keymap::toggle_lock(Mods::CAPS); }   true }
        KEY_NUMLOCK    => { if pressed { keymap::toggle_lock(Mods::NUM); }    true }
        KEY_SCROLLLOCK => { if pressed { keymap::toggle_lock(Mods::SCROLL); } true }
        _ => false,
    }
}

/// Process one EV_KEY-equivalent key event through the shared keyboard path.
/// # C: O(cols*rows) on a VT switch/scroll repaint, else O(1).
pub fn handle_key_event(keycode: u16, pressed: bool) {
    if handle_modifier(keycode, pressed) {
    } else if handle_ctrl_alt_del(keycode, pressed) {
    } else if handle_vt_switch(keycode, pressed) {
    } else if handle_scroll(keycode, pressed) {
    } else if pressed {
        #[cfg(target_os = "oxide-kernel")]
        {
            let out = keymap::translate_app(keycode, tty::live::fg_app_cursor());
            out.for_each(|b| {
                tty::live::input_push_byte(b);
                DRAINED_KEYS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            });
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        let _ = keycode;
    }
}
