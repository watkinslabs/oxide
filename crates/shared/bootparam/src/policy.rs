// Applying the boot command line's console and printk parameters.
//
// ONE place reads the line and installs its console/printk policy. A second
// site that also consulted the line would be a second answer to "how loud is
// this boot", and the two would disagree the moment either grew a case.
//
// Ungated and global-free apart from the klog knobs it sets, so the whole
// application step runs in a hosted test — the boot sequence that calls it is
// target-gated and could not be tested at all.

use cmdline::faults;
use cmdline::printk::{self, DevkmsgMode};

/// What the boot line asked for, as applied. Returned so the boot path can
/// report it and a test can assert it without reading klog's globals.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Applied {
    pub console_loglevel: Option<u32>,
    pub ignore_loglevel: bool,
    pub printk_time: Option<bool>,
    pub devkmsg: Option<DevkmsgMode>,
    pub initcall_debug: bool,
    pub keep_bootcon: bool,
    pub panic_timeout: Option<i64>,
    pub panic_on_oops: bool,
    pub panic_on_warn: bool,
}

/// Decide what a line asks for, without touching any global. # C: O(len)
pub fn decide(line: &[u8]) -> Applied {
    Applied {
        console_loglevel: printk::console_loglevel(line),
        ignore_loglevel: printk::ignore_loglevel(line),
        printk_time: printk::printk_time(line),
        devkmsg: printk::devkmsg_mode(line),
        initcall_debug: printk::initcall_debug(line),
        keep_bootcon: cmdline::keep_bootcon(line),
        panic_timeout: faults::panic_timeout_secs(line),
        panic_on_oops: faults::oops_panic(line),
        panic_on_warn: faults::panic_on_warn(line),
    }
}

/// Install `a` into klog. Idempotent; boot calls it as soon as the line is
/// known, and again after a later transport supplies a better one.
/// # C: O(1)
pub fn install(a: Applied) {
    if let Some(l) = a.console_loglevel { klog::syslog::set_console_level(l); }
    klog::set_ignore_loglevel(a.ignore_loglevel);
    if let Some(t) = a.printk_time { klog::set_printk_time(t); }
    if let Some(m) = a.devkmsg {
        klog::set_devkmsg_mode(match m {
            DevkmsgMode::On => klog::DEVKMSG_ON,
            DevkmsgMode::Off => klog::DEVKMSG_OFF,
            DevkmsgMode::Ratelimit => klog::DEVKMSG_RATELIMIT,
        });
    }
    klog::initcall::set_enabled(a.initcall_debug);
    klog::set_keep_bootcon(a.keep_bootcon);
    // A timeout larger than an i32 is a typo, not a request; clamp rather
    // than wrap it into a negative, which would mean "restart immediately".
    // Absent means the build default (wait forever), not "keep whatever a
    // previous line installed" — the line is the whole statement of policy.
    klog::oops::set_panic_timeout(match a.panic_timeout {
        Some(t) => t.clamp(i32::MIN as i64, i32::MAX as i64) as i32,
        None => klog::oops::PANIC_TIMEOUT_WAIT_FOREVER,
    });
    klog::oops::set_panic_on_oops(a.panic_on_oops);
    klog::oops::set_panic_on_warn(a.panic_on_warn);
    klog::bootcon::set_policy_applied();
}

/// Read the line, apply its policy, and report each parameter the line
/// carries that this kernel recognises but cannot yet honour. Naming them is
/// what stops an inert knob from looking like a working one.
/// # C: O(line length)
pub fn apply(line: &[u8]) -> Applied {
    let a = decide(line);
    install(a);
    for reason in printk::unsupported_in(line) {
        klog::write_raw_at(b"Unhonoured kernel parameter: ", klog::syslog::LOGLEVEL_WARNING);
        klog::write_raw_at(reason.as_bytes(), klog::syslog::LOGLEVEL_WARNING);
        klog::write_raw_at(b"\n", klog::syslog::LOGLEVEL_WARNING);
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Every knob `install` moves is process-global.
    static SERIAL: Mutex<()> = Mutex::new(());
    fn serial() -> std::sync::MutexGuard<'static, ()> { SERIAL.lock().unwrap_or_else(|e| e.into_inner()) }

    #[test]
    fn a_debug_boot_line_asks_for_everything() {
        let a = decide(b"root=/dev/oxide0 earlycon initcall_debug ignore_loglevel keep_bootcon printk.time=1");
        assert!(a.ignore_loglevel);
        assert!(a.initcall_debug);
        assert!(a.keep_bootcon);
        assert_eq!(a.printk_time, Some(true));
        assert_eq!(a.console_loglevel, None, "ignore_loglevel does not itself move the level");
    }

    #[test]
    fn panic_parameters_ride_the_same_application_step() {
        let _g = serial();
        let a = decide(b"root=/dev/oxide0 panic=30 oops=panic panic_on_warn");
        assert_eq!(a.panic_timeout, Some(30));
        assert!(a.panic_on_oops);
        assert!(a.panic_on_warn);
        install(a);
        assert_eq!(klog::oops::panic_timeout(), 30);
        assert!(klog::oops::panic_on_oops());
        assert!(klog::oops::panic_on_warn());
        install(decide(b"root=/dev/oxide0"));
        assert_eq!(klog::oops::panic_timeout(), klog::oops::PANIC_TIMEOUT_WAIT_FOREVER);
        assert!(!klog::oops::panic_on_oops());
        assert!(!klog::oops::panic_on_warn());
    }

    #[test]
    fn an_out_of_range_timeout_is_clamped_not_wrapped() {
        let _g = serial();
        install(decide(b"panic=99999999999"));
        assert!(klog::oops::panic_timeout() > 0, "a huge timeout must not wrap into restart-immediately");
        install(decide(b"root=/dev/oxide0"));
    }

    #[test]
    fn a_plain_line_changes_nothing() {
        let a = decide(b"BOOT_IMAGE=/oxide root=/dev/oxide0 ro console=ttyS0,115200 console=tty0");
        assert_eq!(a, Applied::default());
    }

    #[test]
    fn quiet_is_honoured_rather_than_ignored() {
        let a = decide(b"root=/dev/oxide0 quiet");
        assert_eq!(a.console_loglevel, Some(printk::CONSOLE_LOGLEVEL_QUIET));
    }

    #[test]
    fn installing_moves_the_klog_knobs_and_restores() {
        let _g = serial();
        install(decide(b"initcall_debug ignore_loglevel printk.time=0"));
        assert!(klog::initcall::enabled());
        assert!(klog::ignore_loglevel());
        assert!(!klog::printk_time());
        install(decide(b"printk.time=1"));
        assert!(!klog::initcall::enabled(), "a line without the parameter turns tracing back off");
        assert!(!klog::ignore_loglevel());
        assert!(klog::printk_time());
    }
}
