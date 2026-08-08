use crate::printk::*;

#[test]
fn quiet_and_debug_install_their_levels() {
    assert_eq!(console_loglevel(b"root=/dev/oxide0 quiet"), Some(CONSOLE_LOGLEVEL_QUIET));
    assert_eq!(console_loglevel(b"root=/dev/oxide0 debug"), Some(CONSOLE_LOGLEVEL_DEBUG));
}

#[test]
fn absent_verbosity_keeps_the_build_default() {
    assert_eq!(console_loglevel(b"root=/dev/oxide0 ro"), None);
}

#[test]
fn explicit_loglevel_wins_over_an_earlier_quiet() {
    assert_eq!(console_loglevel(b"quiet loglevel=7"), Some(7));
    assert_eq!(console_loglevel(b"loglevel=7 quiet"), Some(CONSOLE_LOGLEVEL_QUIET));
}

#[test]
fn a_malformed_loglevel_is_not_installed() {
    // A blind 0 silences the console; a typo must not be the way you get there.
    assert_eq!(console_loglevel(b"loglevel=seven"), None);
    assert_eq!(console_loglevel(b"loglevel="), None);
}

#[test]
fn quiet_must_be_a_bare_flag() {
    assert_eq!(console_loglevel(b"systemd.quiet=1"), None);
    assert_eq!(console_loglevel(b"quiet=1"), None);
}

#[test]
fn ignore_loglevel_is_a_bare_flag() {
    assert!(ignore_loglevel(b"quiet ignore_loglevel"));
    assert!(!ignore_loglevel(b"quiet"));
    assert!(!ignore_loglevel(b"ignore_loglevel_extra"));
}

#[test]
fn printk_time_takes_the_boolean_spellings() {
    assert_eq!(printk_time(b"printk.time=1"), Some(true));
    assert_eq!(printk_time(b"printk.time=y"), Some(true));
    assert_eq!(printk_time(b"printk.time=on"), Some(true));
    assert_eq!(printk_time(b"printk.time=0"), Some(false));
    assert_eq!(printk_time(b"printk.time=n"), Some(false));
    assert_eq!(printk_time(b"printk.time=maybe"), None);
    assert_eq!(printk_time(b"root=/dev/oxide0"), None);
}

#[test]
fn devkmsg_mode_decodes_all_three_values() {
    assert_eq!(devkmsg_mode(b"printk.devkmsg=on"), Some(DevkmsgMode::On));
    assert_eq!(devkmsg_mode(b"printk.devkmsg=off"), Some(DevkmsgMode::Off));
    assert_eq!(devkmsg_mode(b"printk.devkmsg=ratelimit"), Some(DevkmsgMode::Ratelimit));
    assert_eq!(devkmsg_mode(b"printk.devkmsg=yes"), None);
    assert_eq!(devkmsg_mode(b"root=/dev/oxide0"), None);
}

#[test]
fn initcall_debug_accepts_flag_and_boolean_forms() {
    assert!(initcall_debug(b"quiet initcall_debug"));
    assert!(initcall_debug(b"initcall_debug=1"));
    assert!(!initcall_debug(b"initcall_debug=0"));
    assert!(!initcall_debug(b"quiet"));
}

#[test]
fn a_recognised_but_unhonoured_parameter_is_named() {
    // The defect this guards is a knob that parses and does nothing. Each of
    // these must produce a boot-time line saying which subsystem it needs.
    for p in [&b"softlockup_panic"[..], b"nmi_watchdog", b"hung_task_panic",
              b"log_buf_len", b"no_console_suspend", b"slub_debug", b"page_poison",
              b"debug_pagealloc", b"boot_delay"] {
        assert!(unsupported_parameter(p).is_some(), "parameter must announce that it is inert");
    }
    for p in [&b"earlycon"[..], b"loglevel", b"panic_on_warn", b"panic", b"oops", b"initcall_debug"] {
        assert_eq!(unsupported_parameter(p), None, "an implemented parameter must not be announced as inert");
    }
}

#[test]
fn unsupported_scan_finds_them_on_a_real_line() {
    let line = b"root=/dev/oxide0 earlycon initcall_debug panic_on_warn=1 nmi_watchdog=1 slub_debug=P";
    let mut n = 0;
    for _ in unsupported_in(line) { n += 1; }
    assert_eq!(n, 2, "both inert knobs on the line get named, and only those — panic_on_warn is honoured");
}
