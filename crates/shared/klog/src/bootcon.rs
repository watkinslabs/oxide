// Boot console lifetime (the `earlycon` sink) and the printk policy knobs the
// boot command line installs.
//
// The boot console is the sink that exists BEFORE device init: the arch boot
// crate programs a UART from the command-line request and installs a writer
// here, so every record from that point on reaches a wire. When a real
// console registers, the boot console is handed over and dropped — that
// handover is where a hang's last words are lost, which is why `keep_bootcon`
// suppresses the drop.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::console;

/// Set once the boot line has been parsed and its printk policy applied, so a
/// late console registration can tell "keep_bootcon was not asked for" from
/// "the line has not been read yet".
static POLICY_APPLIED: AtomicBool = AtomicBool::new(false);
static KEEP_BOOTCON: AtomicBool = AtomicBool::new(false);
static IGNORE_LOGLEVEL: AtomicBool = AtomicBool::new(false);
/// Timestamp prefix on each line. On by default: a boot log without times
/// cannot distinguish a slow step from a hung one.
static PRINTK_TIME: AtomicBool = AtomicBool::new(true);
/// Default `/dev/kmsg` policy. Unrestricted, not rate-limited: the rate limit
/// is meant to exempt a privileged writer, and this kernel does not carry the
/// writer's credentials down to the record ring, so a default limit would
/// silently drop the system log daemon's own records.
static DEVKMSG: AtomicU32 = AtomicU32::new(DEVKMSG_ON);

/// `printk.devkmsg=on` — accept every `/dev/kmsg` write.
pub const DEVKMSG_ON: u32 = 0;
/// `printk.devkmsg=off` — discard `/dev/kmsg` writes.
pub const DEVKMSG_OFF: u32 = 1;
/// `printk.devkmsg=ratelimit` — accept under a rate limit (the default).
pub const DEVKMSG_RATELIMIT: u32 = 2;

/// Install the boot console sink. Called by the arch boot crate once it has
/// programmed the UART named by the command line.
/// # C: O(1)
pub fn set_boot_console(f: crate::LogSink) {
    console::install_slot_flags(console::SLOT_BOOT, f, console::CON_BOOT);
}

/// Is a boot console live? # C: O(1)
pub fn boot_console_registered() -> bool { console::slot_live(console::SLOT_BOOT) }

/// Drop the boot console (the handover a real console's registration
/// performs). A no-op when `keep_bootcon` was requested.
/// # C: O(1)
pub fn drop_boot_console() {
    if keep_bootcon() { return; }
    console::clear_slot(console::SLOT_BOOT);
}

/// Force the boot console down regardless of `keep_bootcon` — for a shutdown
/// path that is taking the UART away.
/// # C: O(1)
pub fn force_drop_boot_console() { console::clear_slot(console::SLOT_BOOT); }

/// Keep the boot console alive past the real console's registration?
/// # C: O(1)
pub fn keep_bootcon() -> bool { KEEP_BOOTCON.load(Ordering::Acquire) }

/// Record the boot line's `keep_bootcon` request. # C: O(1)
pub fn set_keep_bootcon(on: bool) { KEEP_BOOTCON.store(on, Ordering::Release); }

/// Has the boot line's printk policy been applied yet? # C: O(1)
pub fn policy_applied() -> bool { POLICY_APPLIED.load(Ordering::Acquire) }

/// Mark the boot line's printk policy as applied. # C: O(1)
pub fn set_policy_applied() { POLICY_APPLIED.store(true, Ordering::Release); }

/// Does every record reach the consoles regardless of its level?
/// # C: O(1)
pub fn ignore_loglevel() -> bool { IGNORE_LOGLEVEL.load(Ordering::Acquire) }

/// Record the boot line's `ignore_loglevel` request. # C: O(1)
pub fn set_ignore_loglevel(on: bool) { IGNORE_LOGLEVEL.store(on, Ordering::Release); }

/// Prefix each line with the monotonic timestamp? # C: O(1)
pub fn printk_time() -> bool { PRINTK_TIME.load(Ordering::Acquire) }

/// Record the boot line's `printk.time` request. # C: O(1)
pub fn set_printk_time(on: bool) { PRINTK_TIME.store(on, Ordering::Release); }

/// Current `/dev/kmsg` write policy. # C: O(1)
pub fn devkmsg_mode() -> u32 { DEVKMSG.load(Ordering::Acquire) }

/// Record the boot line's `printk.devkmsg` request. # C: O(1)
pub fn set_devkmsg_mode(mode: u32) { DEVKMSG.store(mode, Ordering::Release); }

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicUsize;

    static BOOT_BYTES: AtomicUsize = AtomicUsize::new(0);
    static REAL_BYTES: AtomicUsize = AtomicUsize::new(0);
    fn boot_sink(b: &[u8]) { BOOT_BYTES.fetch_add(b.len(), Ordering::Relaxed); }
    fn real_sink(b: &[u8]) { REAL_BYTES.fetch_add(b.len(), Ordering::Relaxed); }

    fn reset() {
        force_drop_boot_console();
        crate::clear_byte_sink();
        crate::clear_aux_sink();
        set_keep_bootcon(false);
        BOOT_BYTES.store(0, Ordering::Relaxed);
        REAL_BYTES.store(0, Ordering::Relaxed);
    }

    #[test]
    fn boot_console_receives_records_before_any_real_console() {
        let _g = crate::console::test_lock();
        reset();
        set_boot_console(boot_sink);
        assert!(boot_console_registered());
        console::fan_out(b"early");
        assert_eq!(BOOT_BYTES.load(Ordering::Relaxed), 5, "the pre-console window reaches a wire");
        assert_eq!(REAL_BYTES.load(Ordering::Relaxed), 0);
        reset();
    }

    #[test]
    fn handover_drops_the_boot_console() {
        let _g = crate::console::test_lock();
        reset();
        set_boot_console(boot_sink);
        crate::set_byte_sink(real_sink);
        assert!(!boot_console_registered(), "a real console's registration hands over");
        console::fan_out(b"late");
        assert_eq!(BOOT_BYTES.load(Ordering::Relaxed), 0, "no double-print after handover");
        assert_eq!(REAL_BYTES.load(Ordering::Relaxed), 4);
        reset();
    }

    #[test]
    fn keep_bootcon_survives_the_handover() {
        let _g = crate::console::test_lock();
        reset();
        set_keep_bootcon(true);
        set_boot_console(boot_sink);
        crate::set_byte_sink(real_sink);
        assert!(boot_console_registered(), "keep_bootcon suppresses the drop");
        console::fan_out(b"handover window");
        assert_eq!(BOOT_BYTES.load(Ordering::Relaxed), 15);
        assert_eq!(REAL_BYTES.load(Ordering::Relaxed), 15);
        reset();
    }

    #[test]
    fn emergency_route_reaches_the_boot_console() {
        let _g = crate::console::test_lock();
        reset();
        set_boot_console(boot_sink);
        console::primary_only(b"fault");
        assert_eq!(BOOT_BYTES.load(Ordering::Relaxed), 5, "an emergency diagnostic must not skip the only live sink");
        reset();
    }

    #[test]
    fn ignore_loglevel_defeats_the_console_gate() {
        let _g = crate::console::test_lock();
        reset();
        crate::syslog::set_console_level(crate::syslog::MINIMUM_CONSOLE_LOGLEVEL);
        assert!(crate::syslog::suppress_console(crate::syslog::LOGLEVEL_INFO), "gated by default");
        set_ignore_loglevel(true);
        assert!(!crate::syslog::suppress_console(crate::syslog::LOGLEVEL_INFO), "ignore_loglevel prints everything");
        assert!(!crate::syslog::suppress_console(crate::syslog::LOGLEVEL_DEBUG));
        set_ignore_loglevel(false);
        crate::syslog::set_console_level(crate::syslog::CONSOLE_LOGLEVEL_DEBUG);
        reset();
    }

    #[test]
    fn devkmsg_off_discards_writes() {
        let _g = crate::console::test_lock();
        reset();
        crate::set_byte_sink(real_sink);
        set_devkmsg_mode(DEVKMSG_OFF);
        crate::kmsg_write(b"<6>from userspace\n");
        assert_eq!(REAL_BYTES.load(Ordering::Relaxed), 0, "printk.devkmsg=off drops the write");
        set_devkmsg_mode(DEVKMSG_ON);
        crate::kmsg_write(b"<6>from userspace\n");
        assert!(REAL_BYTES.load(Ordering::Relaxed) > 0, "printk.devkmsg=on admits it");
        set_devkmsg_mode(DEVKMSG_ON);
        reset();
    }

    #[test]
    fn policy_knobs_default_to_todays_behaviour() {
        assert!(printk_time(), "timestamps stay on unless the line turns them off");
        assert_eq!(DEVKMSG_ON, 0);
    }
}
