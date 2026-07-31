// Verified `epoll_ctl(2)` admission contract: which errno, and which one wins
// when a call trips several conditions at once.

use super::*;

const EPOLLIN: u32 = vfs::POLL_IN;
const EPOLLPRI: u32 = vfs::POLL_PRI;
const EPOLLERR: u32 = vfs::POLL_ERR;
const EPOLLHUP: u32 = vfs::POLL_HUP;

fn plain() -> CtlTarget { CtlTarget { can_poll: true, is_epoll: false, is_self: false } }

#[test]
fn a_target_without_a_readiness_op_is_eperm_not_einval() {
    let t = CtlTarget { can_poll: false, ..plain() };
    for op in [EPOLL_CTL_ADD, EPOLL_CTL_MOD, EPOLL_CTL_DEL] {
        assert_eq!(ctl_precheck(op, true, t, EPOLLIN, true), Err(Errno::Eperm),
                   "op {op}: a regular file / directory target is EPERM");
    }
}

#[test]
fn eperm_outranks_every_einval_condition() {
    // Non-pollable AND the epoll file itself AND a bad op AND an illegal
    // exclusive mask: Linux still answers EPERM, because file_can_poll is the
    // first statement of do_epoll_ctl_file.
    let t = CtlTarget { can_poll: false, is_epoll: true, is_self: true };
    assert_eq!(ctl_precheck(9999, false, t, EPOLLEXCLUSIVE | EPOLLPRI, false), Err(Errno::Eperm));
}

#[test]
fn adding_or_deleting_the_epoll_file_to_itself_is_always_einval() {
    let t = CtlTarget { is_self: true, is_epoll: true, can_poll: true };
    // The self-check is not conditional on the operation: DEL of the epoll fd
    // on itself is EINVAL, never the ENOENT an ordinary unwatched fd gets.
    for op in [EPOLL_CTL_ADD, EPOLL_CTL_MOD, EPOLL_CTL_DEL] {
        assert_eq!(ctl_precheck(op, true, t, EPOLLIN, true), Err(Errno::Einval), "op {op}");
    }
}

#[test]
fn an_epfd_that_is_not_an_epoll_file_is_einval() {
    assert_eq!(ctl_precheck(EPOLL_CTL_ADD, false, plain(), EPOLLIN, true), Err(Errno::Einval));
    assert_eq!(ctl_precheck(EPOLL_CTL_DEL, false, plain(), 0, true), Err(Errno::Einval));
}

#[test]
fn epollwakeup_is_dropped_without_cap_block_suspend_never_rejected() {
    let got = ctl_precheck(EPOLL_CTL_ADD, true, plain(), EPOLLIN | EPOLLWAKEUP, false).unwrap();
    assert_eq!(got & EPOLLWAKEUP, 0, "the bit is stripped, the call still succeeds");
    assert_eq!(got & EPOLLIN, EPOLLIN, "the rest of the mask survives");
    let kept = ctl_precheck(EPOLL_CTL_ADD, true, plain(), EPOLLIN | EPOLLWAKEUP, true).unwrap();
    assert_eq!(kept & EPOLLWAKEUP, EPOLLWAKEUP, "CAP_BLOCK_SUSPEND keeps it");
}

#[test]
fn add_and_mod_always_store_err_and_hup() {
    for op in [EPOLL_CTL_ADD, EPOLL_CTL_MOD] {
        let got = ctl_precheck(op, true, plain(), EPOLLIN, true).unwrap();
        assert_eq!(got & (EPOLLERR | EPOLLHUP), EPOLLERR | EPOLLHUP,
                   "op {op}: an interest reports ERR/HUP whether or not it asked");
    }
    assert_eq!(ctl_precheck(EPOLL_CTL_DEL, true, plain(), 0, true), Ok(0),
               "DEL carries no event at all");
}

#[test]
fn exclusive_is_rejected_on_mod_and_on_a_nested_epoll_target() {
    assert_eq!(ctl_precheck(EPOLL_CTL_MOD, true, plain(), EPOLLIN | EPOLLEXCLUSIVE, true),
               Err(Errno::Einval), "EPOLLEXCLUSIVE registers only at ADD time");
    let nested = CtlTarget { is_epoll: true, ..plain() };
    assert_eq!(ctl_precheck(EPOLL_CTL_ADD, true, nested, EPOLLIN | EPOLLEXCLUSIVE, true),
               Err(Errno::Einval), "nested exclusive wakeups are unsupported");
    assert!(ctl_precheck(EPOLL_CTL_ADD, true, nested, EPOLLIN, true).is_ok(),
            "a nested epoll target is fine without EPOLLEXCLUSIVE");
}

#[test]
fn epollpri_is_not_an_exclusive_ok_bit() {
    assert_eq!(EPOLLEXCLUSIVE_OK_BITS & EPOLLPRI, 0);
    assert_eq!(ctl_precheck(EPOLL_CTL_ADD, true, plain(), EPOLLEXCLUSIVE | EPOLLPRI, true),
               Err(Errno::Einval));
    assert!(ctl_precheck(EPOLL_CTL_ADD, true, plain(),
                         EPOLLEXCLUSIVE | EPOLLIN | EPOLLET | EPOLLWAKEUP, true).is_ok());
}

#[test]
fn epollwakeup_is_stripped_before_the_exclusive_mask_test() {
    // Same call, no capability: WAKEUP leaves the mask first, so the
    // EPOLLEXCLUSIVE_OK_BITS test sees a mask that is still legal.
    let got = ctl_precheck(EPOLL_CTL_ADD, true, plain(),
                           EPOLLEXCLUSIVE | EPOLLIN | EPOLLWAKEUP, false).unwrap();
    assert_eq!(got & EPOLLWAKEUP, 0);
    assert_eq!(got & EPOLLEXCLUSIVE, EPOLLEXCLUSIVE);
}

#[test]
fn an_unknown_op_is_einval_but_only_after_the_target_is_vetted() {
    assert_eq!(ctl_precheck(0, true, plain(), 0, true), Err(Errno::Einval));
    assert_eq!(ctl_precheck(4, true, plain(), 0, true), Err(Errno::Einval));
    // ... and the non-pollable target still wins, proving the op check is last.
    let t = CtlTarget { can_poll: false, ..plain() };
    assert_eq!(ctl_precheck(4, true, t, 0, true), Err(Errno::Eperm));
}

#[test]
fn nesting_counts_both_directions_against_the_same_budget() {
    assert!(nesting_admits(0, 0), "one epoll watching one plain epoll");
    assert!(nesting_admits(3, 0), "a 4-deep chain below the target still fits");
    assert!(!nesting_admits(4, 0), "5 deep does not");
    assert!(nesting_admits(0, 3));
    assert!(!nesting_admits(0, 4), "the chain above the destination counts too");
    assert!(nesting_admits(2, 1), "2 + 1 + 1 == EP_MAX_NESTS");
    assert!(!nesting_admits(2, 2), "2 + 1 + 2 exceeds it — a downward-only check misses this");
    assert_eq!(EP_MAX_NESTS, 4);
}

#[test]
fn op_has_event_is_false_only_for_del() {
    assert!(op_has_event(EPOLL_CTL_ADD));
    assert!(op_has_event(EPOLL_CTL_MOD));
    assert!(!op_has_event(EPOLL_CTL_DEL));
    assert!(op_has_event(0), "an unknown op still reads the event, hence EFAULT first");
}

#[test]
fn epoll_params_validation_matches_the_ioctl_contract() {
    assert_eq!(validate_epoll_params(0, 0, 0, 0, false), Ok(()));
    assert_eq!(validate_epoll_params(0, 0, 0, 1, false), Err(Errno::Einval), "pad byte must be zero");
    assert_eq!(validate_epoll_params(i32::MAX as u32, 0, 0, 0, false), Ok(()));
    assert_eq!(validate_epoll_params(i32::MAX as u32 + 1, 0, 0, 0, false), Err(Errno::Einval));
    assert_eq!(validate_epoll_params(0, 0, 2, 0, false), Err(Errno::Einval), "prefer_busy_poll is a bool");
    assert_eq!(validate_epoll_params(0, NAPI_POLL_WEIGHT, 0, 0, false), Ok(()));
    assert_eq!(validate_epoll_params(0, NAPI_POLL_WEIGHT + 1, 0, 0, false), Err(Errno::Eperm));
    assert_eq!(validate_epoll_params(0, NAPI_POLL_WEIGHT + 1, 0, 0, true), Ok(()));
    // Pad is checked before the privileged budget.
    assert_eq!(validate_epoll_params(0, NAPI_POLL_WEIGHT + 1, 0, 1, false), Err(Errno::Einval));
}
