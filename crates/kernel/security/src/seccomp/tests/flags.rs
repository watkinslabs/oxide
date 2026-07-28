// `seccomp_set_mode_filter`'s flag ladder + `do_seccomp`'s per-op flag rule.
// Before B1478 the flags word was read into `_flg` and thrown away, so every
// one of these EINVALs was a silent success.

use crate::seccomp::flags::*;
use crate::seccomp::uapi::*;
use syscall::errno::Errno;

#[test]
fn every_defined_flag_is_accepted_on_its_own() {
    for f in [SECCOMP_FILTER_FLAG_TSYNC, SECCOMP_FILTER_FLAG_LOG,
              SECCOMP_FILTER_FLAG_SPEC_ALLOW, SECCOMP_FILTER_FLAG_NEW_LISTENER,
              SECCOMP_FILTER_FLAG_TSYNC_ESRCH] {
        assert_eq!(validate_filter_flags(f), Ok(()), "flag {:#x}", f);
    }
}

#[test]
fn an_undefined_flag_bit_is_rejected() {
    for bit in 6..64 {
        assert_eq!(validate_filter_flags(1u64 << bit), Err(Errno::Einval), "bit {}", bit);
    }
}

// "there's no way to tell whether something succeeded or failed" — NEW_LISTENER
// returns an fd, TSYNC returns a tid, so the combination needs TSYNC_ESRCH.
#[test]
fn tsync_with_new_listener_needs_tsync_esrch() {
    let combo = SECCOMP_FILTER_FLAG_TSYNC | SECCOMP_FILTER_FLAG_NEW_LISTENER;
    assert_eq!(validate_filter_flags(combo), Err(Errno::Einval));
    assert_eq!(validate_filter_flags(combo | SECCOMP_FILTER_FLAG_TSYNC_ESRCH), Ok(()));
}

#[test]
fn wait_killable_recv_needs_new_listener() {
    assert_eq!(validate_filter_flags(SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV), Err(Errno::Einval));
    assert_eq!(validate_filter_flags(SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
                                     | SECCOMP_FILTER_FLAG_NEW_LISTENER), Ok(()));
}

#[test]
fn strict_mode_takes_neither_flags_nor_an_argument() {
    assert_eq!(validate_op_flags(SECCOMP_SET_MODE_STRICT, 0, 0), Ok(()));
    assert_eq!(validate_op_flags(SECCOMP_SET_MODE_STRICT, 1, 0), Err(Errno::Einval));
    assert_eq!(validate_op_flags(SECCOMP_SET_MODE_STRICT, 0, 0x1000), Err(Errno::Einval));
}

#[test]
fn the_query_ops_take_no_flags() {
    for op in [SECCOMP_GET_ACTION_AVAIL, SECCOMP_GET_NOTIF_SIZES] {
        assert_eq!(validate_op_flags(op, 0, 0x1000), Ok(()));
        assert_eq!(validate_op_flags(op, SECCOMP_FILTER_FLAG_LOG, 0x1000), Err(Errno::Einval));
    }
}

#[test]
fn an_unknown_operation_is_einval() {
    for op in [4u64, 5, u64::MAX] { assert_eq!(validate_op_flags(op, 0, 0), Err(Errno::Einval)); }
}

#[test]
fn the_flag_mask_matches_the_uapi_header() {
    assert_eq!(SECCOMP_FILTER_FLAG_MASK, 0b11_1111);
}
