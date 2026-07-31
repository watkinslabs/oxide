// Syscall-user-dispatch contract, encoded so the range inversion and the
// selector ladder can be re-checked without reading the dispatch head.

use super::*;

const SEL: u64 = 0x7fff_0000_1000;

#[test]
fn off_rejects_every_non_zero_tail_argument() {
    assert_eq!(classify_set(PR_SYS_DISPATCH_OFF, 0, 0, 0),
               Ok(Config { on: false, offset: 0, len: 0, selector: 0 }));
    for (o, l, s) in [(1, 0, 0), (0, 1, 0), (0, 0, 1), (1, 1, 1)] {
        assert_eq!(classify_set(PR_SYS_DISPATCH_OFF, o, l, s), Err(Errno::Einval));
    }
}

#[test]
fn unknown_mode_is_einval() {
    for mode in [3, 4, u64::MAX] {
        assert_eq!(classify_set(mode, 0, 0, SEL), Err(Errno::Einval));
    }
}

#[test]
fn exclusive_allows_zero_offset_with_any_length_and_rejects_wrap() {
    // offset == 0 skips the overflow test entirely, so even a length that
    // would wrap is accepted.
    assert_eq!(classify_set(PR_SYS_DISPATCH_EXCLUSIVE_ON, 0, u64::MAX, SEL),
               Ok(Config { on: true, offset: 0, len: u64::MAX, selector: SEL }));
    assert_eq!(classify_set(PR_SYS_DISPATCH_EXCLUSIVE_ON, 0x1000, 0, SEL),
               Err(Errno::Einval), "zero length wraps to offset itself");
    assert_eq!(classify_set(PR_SYS_DISPATCH_EXCLUSIVE_ON, u64::MAX, 2, SEL),
               Err(Errno::Einval));
    assert_eq!(classify_set(PR_SYS_DISPATCH_EXCLUSIVE_ON, 0x1000, 0x100, SEL),
               Ok(Config { on: true, offset: 0x1000, len: 0x100, selector: SEL }));
}

#[test]
fn inclusive_rejects_zero_length_and_stores_the_inverted_range() {
    assert_eq!(classify_set(PR_SYS_DISPATCH_INCLUSIVE_ON, 0x1000, 0, SEL),
               Err(Errno::Einval));
    assert_eq!(classify_set(PR_SYS_DISPATCH_INCLUSIVE_ON, u64::MAX, 1, SEL),
               Err(Errno::Einval));
    let cfg = classify_set(PR_SYS_DISPATCH_INCLUSIVE_ON, 0x1000, 0x100, SEL).unwrap();
    assert_eq!(cfg.offset, 0x1100);
    assert_eq!(cfg.len, 0x100u64.wrapping_neg());
}

#[test]
fn exclusive_exempts_inside_the_window_and_inclusive_exempts_outside_it() {
    let excl = classify_set(PR_SYS_DISPATCH_EXCLUSIVE_ON, 0x1000, 0x100, SEL).unwrap();
    assert!(pc_is_exempt(&excl, 0x1000));
    assert!(pc_is_exempt(&excl, 0x10ff));
    assert!(!pc_is_exempt(&excl, 0x0fff));
    assert!(!pc_is_exempt(&excl, 0x1100));

    // The SAME window under INCLUSIVE_ON exempts precisely the complement:
    // syscalls issued from inside it are the ones handed to userspace.
    let incl = classify_set(PR_SYS_DISPATCH_INCLUSIVE_ON, 0x1000, 0x100, SEL).unwrap();
    assert!(!pc_is_exempt(&incl, 0x1000));
    assert!(!pc_is_exempt(&incl, 0x10ff));
    assert!(pc_is_exempt(&incl, 0x0fff));
    assert!(pc_is_exempt(&incl, 0x1100));
}

#[test]
fn selector_byte_ladder() {
    let cfg = classify_set(PR_SYS_DISPATCH_EXCLUSIVE_ON, 0x1000, 0x100, SEL).unwrap();
    // Inside the exempt range the selector is never even consulted.
    assert_eq!(decide(&cfg, 0x1000, None), Action::Run);
    assert_eq!(decide(&cfg, 0x2000, Some(SYSCALL_DISPATCH_FILTER_ALLOW)), Action::Run);
    assert_eq!(decide(&cfg, 0x2000, Some(SYSCALL_DISPATCH_FILTER_BLOCK)), Action::Dispatch);
    // Any other selector value is a fatal SIGSYS, not a dispatch.
    assert_eq!(decide(&cfg, 0x2000, Some(2)), Action::KillSigsys);
    assert_eq!(decide(&cfg, 0x2000, Some(0xff)), Action::KillSigsys);
    // An unreadable selector is a fatal SIGSEGV.
    assert_eq!(decide(&cfg, 0x2000, None), Action::KillSigsegv);
}

#[test]
fn null_selector_dispatches_unconditionally_outside_the_range() {
    let cfg = classify_set(PR_SYS_DISPATCH_EXCLUSIVE_ON, 0x1000, 0x100, 0).unwrap();
    assert_eq!(cfg.selector, 0);
    // A null selector is NOT "always allow": the byte check is skipped and
    // every non-exempt syscall dispatches.
    assert_eq!(decide(&cfg, 0x2000, None), Action::Dispatch);
    assert_eq!(decide(&cfg, 0x1000, None), Action::Run);
}

#[test]
fn dispatch_off_runs_everything() {
    let cfg = classify_set(PR_SYS_DISPATCH_OFF, 0, 0, 0).unwrap();
    assert_eq!(decide(&cfg, 0, None), Action::Run);
    assert_eq!(decide(&cfg, u64::MAX, Some(SYSCALL_DISPATCH_FILTER_BLOCK)), Action::Run);
}

#[test]
fn install_arms_and_clear_disarms_the_live_record() {
    let live = SyscallUserDispatch::new();
    assert_eq!(live.armed(), None);
    let cfg = classify_set(PR_SYS_DISPATCH_EXCLUSIVE_ON, 0x1000, 0x100, SEL).unwrap();
    live.install(&cfg);
    assert_eq!(live.armed(), Some(cfg));
    assert!(!live.take_on_dispatch());
    live.set_on_dispatch();
    assert!(live.take_on_dispatch(), "read-and-clear reports the rollback once");
    assert!(!live.take_on_dispatch());
    live.clear();
    assert_eq!(live.armed(), None, "execve and fork start with dispatch off");
    // Re-installing OFF also clears a latched rollback.
    live.install(&cfg);
    live.set_on_dispatch();
    live.install(&classify_set(PR_SYS_DISPATCH_OFF, 0, 0, 0).unwrap());
    assert!(!live.take_on_dispatch());
}
