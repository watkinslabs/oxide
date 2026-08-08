use crate::mqueue_policy::attr::{
    admit_new_queue, charge_msgqueue, setattr_flags, validate_attr, MqSysctls,
};
use crate::mqueue_policy::limits::{
    DFLT_MSG, DFLT_MSGSIZE, DFLT_QUEUESMAX, HARD_MSGMAX, HARD_MSGSIZEMAX, MSG_MSG_BYTES,
    MSG_TREE_NODE_BYTES,
};
use crate::mqueue_policy::open::{O_NONBLOCK, O_RDWR};
use syscall::errno::Errno;

fn ns() -> MqSysctls { MqSysctls::linux_defaults() }

#[test]
fn no_attr_takes_the_namespace_defaults() {
    let c = validate_attr(None, &ns(), false).expect("defaults are legal");
    assert_eq!((c.maxmsg, c.msgsize), (DFLT_MSG, DFLT_MSGSIZE));
    // `mq_bytes` = maxmsg*msgsize + maxmsg*sizeof(msg_msg)
    //            + min(maxmsg, MQ_PRIO_MAX)*sizeof(posix_msg_tree_node).
    let want = (DFLT_MSG * DFLT_MSGSIZE + DFLT_MSG * MSG_MSG_BYTES
                + DFLT_MSG * MSG_TREE_NODE_BYTES) as u64;
    assert_eq!(c.mq_bytes, want);
}

#[test]
fn a_zero_or_negative_field_is_einval() {
    assert_eq!(validate_attr(Some((0, 8192)), &ns(), false), Err(Errno::Einval));
    assert_eq!(validate_attr(Some((10, 0)), &ns(), false), Err(Errno::Einval));
    assert_eq!(validate_attr(Some((-1, 8192)), &ns(), false), Err(Errno::Einval));
    assert_eq!(validate_attr(Some((10, -1)), &ns(), false), Err(Errno::Einval));
}

#[test]
fn over_the_sysctl_ceiling_is_einval_not_a_silent_clamp() {
    // The pre-audit implementation CLAMPED an out-of-range request back to the
    // default and reported success; Linux rejects it.
    assert_eq!(validate_attr(Some((11, 8192)), &ns(), false), Err(Errno::Einval));
    assert_eq!(validate_attr(Some((10, 8193)), &ns(), false), Err(Errno::Einval));
    // At the ceiling exactly is legal.
    assert!(validate_attr(Some((10, 8192)), &ns(), false).is_ok());
}

#[test]
fn cap_sys_resource_lifts_the_sysctl_ceiling_to_the_hard_one() {
    assert!(validate_attr(Some((11, 8193)), &ns(), true).is_ok());
    assert!(validate_attr(Some((HARD_MSGMAX, 8192)), &ns(), true).is_ok());
    assert_eq!(validate_attr(Some((HARD_MSGMAX + 1, 8192)), &ns(), true), Err(Errno::Einval));
    assert_eq!(validate_attr(Some((10, HARD_MSGSIZEMAX + 1)), &ns(), true), Err(Errno::Einval));
}

#[test]
fn a_raised_sysctl_is_what_an_uncapable_caller_is_measured_against() {
    let raised = MqSysctls { msg_max: 100, msgsize_max: 65_536, ..ns() };
    assert!(validate_attr(Some((100, 65_536)), &raised, false).is_ok());
    assert_eq!(validate_attr(Some((101, 65_536)), &raised, false), Err(Errno::Einval));
}

#[test]
fn the_product_overflow_is_eoverflow() {
    let wide = MqSysctls { msg_max: HARD_MSGMAX, msgsize_max: HARD_MSGSIZEMAX, ..ns() };
    // Under the hard caps the product cannot overflow, so reach EOVERFLOW the
    // only way Linux can: a capable caller at both hard ceilings still fits,
    // but a sysctl raised past them does not.
    assert!(validate_attr(Some((HARD_MSGMAX, HARD_MSGSIZEMAX)), &wide, true).is_ok());
    let absurd = MqSysctls { msg_max: i64::MAX, msgsize_max: i64::MAX, ..ns() };
    assert_eq!(validate_attr(Some((i64::MAX, i64::MAX)), &absurd, false), Err(Errno::Eoverflow));
}

#[test]
fn queues_max_is_enospc_and_cap_sys_resource_bypasses_it() {
    assert_eq!(admit_new_queue(0, DFLT_QUEUESMAX, false), Ok(()));
    assert_eq!(admit_new_queue(DFLT_QUEUESMAX - 1, DFLT_QUEUESMAX, false), Ok(()));
    assert_eq!(admit_new_queue(DFLT_QUEUESMAX, DFLT_QUEUESMAX, false), Err(Errno::Enospc));
    assert_eq!(admit_new_queue(DFLT_QUEUESMAX, DFLT_QUEUESMAX, true), Ok(()));
}

#[test]
fn the_msgqueue_rlimit_is_emfile_when_exceeded() {
    // A namespace already at its RLIMIT_MSGQUEUE cap returns EMFILE, not EAGAIN and not ENOMEM.
    assert_eq!(charge_msgqueue(0, 100, 100), Ok(100));
    assert_eq!(charge_msgqueue(0, 101, 100), Err(Errno::Emfile));
    assert_eq!(charge_msgqueue(60, 41, 100), Err(Errno::Emfile));
    assert_eq!(charge_msgqueue(60, 40, 100), Ok(100));
    // RLIM_INFINITY never denies; the u64 sum overflowing does.
    assert_eq!(charge_msgqueue(1, 1, u64::MAX), Ok(2));
    assert_eq!(charge_msgqueue(u64::MAX, 1, u64::MAX), Err(Errno::Emfile));
}

#[test]
fn a_default_rlimit_affords_the_linux_number_of_default_queues() {
    // RLIMIT_MSGQUEUE default is 819200 bytes; a default queue costs
    // 10*8192 + 10*48 + 10*48 = 82880, so nine fit and the tenth does not.
    const RLIM: u64 = 819_200;
    let cost = validate_attr(None, &ns(), false).expect("defaults legal").mq_bytes;
    assert_eq!(cost, 82_880);
    let mut acc = 0u64;
    for _ in 0..9 { acc = charge_msgqueue(acc, cost, RLIM).expect("nine queues fit"); }
    assert_eq!(charge_msgqueue(acc, cost, RLIM), Err(Errno::Emfile));
}

#[test]
fn only_o_nonblock_may_be_set_through_mq_setattr() {
    assert_eq!(setattr_flags(0), Ok(false));
    assert_eq!(setattr_flags(O_NONBLOCK as i64), Ok(true));
    assert_eq!(setattr_flags(O_RDWR as i64), Err(Errno::Einval));
    assert_eq!(setattr_flags(O_NONBLOCK as i64 | 1), Err(Errno::Einval));
    assert_eq!(setattr_flags(-1), Err(Errno::Einval));
}

#[test]
fn a_sysctl_raised_past_the_hard_cap_cannot_wrap_the_charge() {
    // `/proc/sys/fs/mqueue/msg_max` is bounded to HARD_MSGMAX, but
    // `validate_attr` must not depend on that: a huge `maxmsg` with a tiny
    // `msgsize` passes the `msgsize > ULONG_MAX/maxmsg` gate, so the tree
    // overhead is where the wrap would happen.
    let absurd = MqSysctls { msg_max: i64::MAX, msgsize_max: i64::MAX, ..ns() };
    assert_eq!(validate_attr(Some((i64::MAX, 1)), &absurd, false), Err(Errno::Eoverflow));
    assert_eq!(validate_attr(Some((i64::MAX / 8, 1)), &absurd, false), Err(Errno::Eoverflow));
}
