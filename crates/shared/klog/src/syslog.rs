// printk console-loglevel + `syslog(2)` cursor state. Linux keeps all of
// this in `kernel/printk/printk.c` next to the record ring (`console_loglevel`,
// `saved_console_loglevel`, `minimum_console_loglevel`, `syslog_seq`,
// `clear_seq`, `dmesg_restrict`). Same owner here: the ring lives in
// `klog`, so its read cursor, clear point and console gate live with it —
// a second copy in the syscall layer would be a split source of truth.
//
// Positions are byte offsets into the ring's monotonic `total` stream
// (`lib.rs` `ring_read`), not record sequence numbers: our ring is
// byte-granular, so "seq" maps to "bytes consumed".

use core::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering};

/// Linux `KERN_EMERG`..`KERN_DEBUG` numeric levels.
pub const LOGLEVEL_EMERG:   u32 = 0;
pub const LOGLEVEL_ALERT:   u32 = 1;
pub const LOGLEVEL_CRIT:    u32 = 2;
pub const LOGLEVEL_ERR:     u32 = 3;
pub const LOGLEVEL_WARNING: u32 = 4;
pub const LOGLEVEL_NOTICE:  u32 = 5;
pub const LOGLEVEL_INFO:    u32 = 6;
pub const LOGLEVEL_DEBUG:   u32 = 7;

/// Linux `minimum_console_loglevel` — the floor `SYSLOG_ACTION_CONSOLE_LEVEL`
/// clamps to and the value `SYSLOG_ACTION_CONSOLE_OFF` installs.
pub const MINIMUM_CONSOLE_LOGLEVEL: u32 = 1;
/// Linux `CONSOLE_LOGLEVEL_DEBUG` — the ceiling accepted by CONSOLE_LEVEL
/// (`len > 8` is `EINVAL`), and our build's boot default so every existing
/// `klog!` level still reaches the serial console until userspace lowers it.
pub const CONSOLE_LOGLEVEL_DEBUG: u32 = 8;
/// Linux `LOGLEVEL_DEFAULT` sentinel stored in `saved_console_loglevel`
/// meaning "nothing saved" (CONSOLE_ON is then a no-op).
pub const LOGLEVEL_DEFAULT: i32 = -1;
/// Linux `default_message_loglevel` (`CONFIG_MESSAGE_LOGLEVEL_DEFAULT`) —
/// the level assumed for a record emitted without an explicit one.
pub const DEFAULT_MESSAGE_LOGLEVEL: u32 = LOGLEVEL_WARNING;

static CONSOLE_LOGLEVEL:       AtomicU32   = AtomicU32::new(CONSOLE_LOGLEVEL_DEBUG);
static SAVED_CONSOLE_LOGLEVEL: AtomicI32   = AtomicI32::new(LOGLEVEL_DEFAULT);
static DMESG_RESTRICT:         AtomicU32   = AtomicU32::new(0);
/// Linux `syslog_seq`: SYSLOG_ACTION_READ consumption point.
static SYSLOG_CURSOR:          AtomicUsize = AtomicUsize::new(0);
/// Linux `clear_seq`: floor for SYSLOG_ACTION_READ_ALL / READ_CLEAR.
static CLEAR_CURSOR:           AtomicUsize = AtomicUsize::new(0);

/// Current `console_loglevel`. A record prints to the consoles when its
/// level is numerically **less** than this (Linux `suppress_message_printing`).
/// # C: O(1)
pub fn console_level() -> u32 { CONSOLE_LOGLEVEL.load(Ordering::Acquire) }

/// `SYSLOG_ACTION_CONSOLE_LEVEL`: install `lvl` (already validated 1..=8 by
/// the caller), clamped up to `minimum_console_loglevel`, and drop any saved
/// level so a later CONSOLE_ON does not undo it (Linux re-enables implicitly).
/// # C: O(1)
pub fn set_console_level(lvl: u32) {
    let lvl = if lvl < MINIMUM_CONSOLE_LOGLEVEL { MINIMUM_CONSOLE_LOGLEVEL } else { lvl };
    CONSOLE_LOGLEVEL.store(lvl, Ordering::Release);
    SAVED_CONSOLE_LOGLEVEL.store(LOGLEVEL_DEFAULT, Ordering::Release);
}

/// `SYSLOG_ACTION_CONSOLE_OFF`: save the live level once, then drop to
/// `minimum_console_loglevel`. Repeated OFF must not overwrite the save.
/// # C: O(1)
pub fn console_off() {
    if SAVED_CONSOLE_LOGLEVEL.load(Ordering::Acquire) == LOGLEVEL_DEFAULT {
        SAVED_CONSOLE_LOGLEVEL.store(console_level() as i32, Ordering::Release);
    }
    CONSOLE_LOGLEVEL.store(MINIMUM_CONSOLE_LOGLEVEL, Ordering::Release);
}

/// `SYSLOG_ACTION_CONSOLE_ON`: restore the saved level, if one was saved.
/// # C: O(1)
pub fn console_on() {
    let saved = SAVED_CONSOLE_LOGLEVEL.load(Ordering::Acquire);
    if saved != LOGLEVEL_DEFAULT {
        CONSOLE_LOGLEVEL.store(saved as u32, Ordering::Release);
        SAVED_CONSOLE_LOGLEVEL.store(LOGLEVEL_DEFAULT, Ordering::Release);
    }
}

/// Linux `suppress_message_printing`: true when a record at `lvl` must not
/// reach the consoles. The dmesg ring always keeps it regardless.
/// # C: O(1)
pub fn suppress_console(lvl: u32) -> bool { lvl >= console_level() }

/// `kernel.dmesg_restrict` sysctl. When set, every syslog action needs
/// CAP_SYSLOG; when clear, READ_ALL and SIZE_BUFFER are unrestricted.
/// # C: O(1)
pub fn dmesg_restrict() -> bool { DMESG_RESTRICT.load(Ordering::Acquire) != 0 }

/// Sysctl write side for `kernel.dmesg_restrict`.
/// # C: O(1)
pub fn set_dmesg_restrict(on: bool) {
    DMESG_RESTRICT.store(if on { 1 } else { 0 }, Ordering::Release);
}

/// Byte position of the `SYSLOG_ACTION_READ` cursor in the ring's total
/// stream, floored at the oldest byte still resident.
/// # C: O(1)
pub fn read_cursor() -> usize { floor(SYSLOG_CURSOR.load(Ordering::Acquire)) }

/// Byte position of the `SYSLOG_ACTION_CLEAR` point, floored likewise.
/// # C: O(1)
pub fn clear_cursor() -> usize { floor(CLEAR_CURSOR.load(Ordering::Acquire)) }

/// Advance the READ cursor (called after a successful copy to user).
/// # C: O(1)
pub fn set_read_cursor(pos: usize) { SYSLOG_CURSOR.store(pos, Ordering::Release); }

/// `SYSLOG_ACTION_CLEAR`: move the clear point to the end of the stream.
/// The ring itself is untouched — Linux `syslog_clear` only bumps
/// `clear_seq`, so an already-open `/proc/kmsg` reader keeps its position.
/// # C: O(1)
pub fn clear() { CLEAR_CURSOR.store(crate::ring_total(), Ordering::Release); }

/// Bytes readable by `SYSLOG_ACTION_READ` right now (Linux SIZE_UNREAD).
/// # C: O(1)
pub fn unread_bytes() -> usize { crate::ring_total() - read_cursor() }

/// `SYSLOG_ACTION_READ`: consume up to `out.len()` bytes from the READ
/// cursor and advance it (Linux `syslog_print`). Returns bytes copied; `0`
/// means nothing was pending, which the caller turns into a sleep.
/// # C: O(out.len())
pub fn read_into(out: &mut [u8]) -> usize {
    let (n, next) = crate::ring_read(read_cursor(), out);
    set_read_cursor(next);
    n
}

/// `SYSLOG_ACTION_READ_ALL` / `READ_CLEAR`: copy the newest bytes that fit
/// into `out`, never reaching behind the clear point, and never moving the
/// READ cursor (Linux `syslog_print_all`). `clear` additionally bumps the
/// clear point past what was returned.
/// # C: O(out.len())
pub fn read_all_into(out: &mut [u8], clear_after: bool) -> usize {
    let total = crate::ring_total();
    let floor_pos = clear_cursor();
    // Linux `find_first_fitting_seq`: start late enough that the tail fits.
    let start = if total - floor_pos > out.len() { total - out.len() } else { floor_pos };
    let (n, next) = crate::ring_read(start, out);
    if clear_after { CLEAR_CURSOR.store(next, Ordering::Release); }
    n
}

/// Clamp a stored position into the window the ring can still serve
/// (bytes older than `total - RING_BYTES` have been overwritten).
fn floor(pos: usize) -> usize {
    let total = crate::ring_total();
    let cap = crate::ring_size();
    let oldest = if total > cap { total - cap } else { 0 };
    if pos < oldest { oldest } else if pos > total { total } else { pos }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Console-level state is process-global; the assertions below only
    // touch the level knobs, which no other test in this crate reads.
    #[test]
    fn console_off_then_on_round_trips() {
        set_console_level(7);
        assert_eq!(console_level(), 7);
        console_off();
        assert_eq!(console_level(), MINIMUM_CONSOLE_LOGLEVEL);
        assert!(suppress_console(LOGLEVEL_WARNING));
        assert!(!suppress_console(LOGLEVEL_EMERG));
        console_on();
        assert_eq!(console_level(), 7);
        set_console_level(CONSOLE_LOGLEVEL_DEBUG);
    }

    #[test]
    fn repeated_off_keeps_first_save() {
        set_console_level(6);
        console_off();
        console_off();
        console_on();
        assert_eq!(console_level(), 6);
        set_console_level(CONSOLE_LOGLEVEL_DEBUG);
    }

    #[test]
    fn console_level_clamps_to_minimum() {
        set_console_level(0);
        assert_eq!(console_level(), MINIMUM_CONSOLE_LOGLEVEL);
        set_console_level(CONSOLE_LOGLEVEL_DEBUG);
    }

    #[test]
    fn console_on_without_save_is_noop() {
        set_console_level(5);
        console_on();
        assert_eq!(console_level(), 5);
        set_console_level(CONSOLE_LOGLEVEL_DEBUG);
    }

    #[test]
    fn dmesg_restrict_round_trips() {
        set_dmesg_restrict(true);
        assert!(dmesg_restrict());
        set_dmesg_restrict(false);
        assert!(!dmesg_restrict());
    }
}
