use super::*;
use crate::io_uring_abi::ops::{IORING_OP_EPOLL_CTL, IORING_OP_EPOLL_WAIT};

fn ctl() -> Sqe { Sqe { opcode: IORING_OP_EPOLL_CTL, fd: 3, len: 1, off: 5, addr: 0x900, ..Sqe::default() } }
fn wait() -> Sqe { Sqe { opcode: IORING_OP_EPOLL_WAIT, fd: 3, addr: 0x900, len: 64, ..Sqe::default() } }

#[test]
fn a_control_entry_refuses_the_fields_it_does_not_read() {
    assert!(prep_ctl(&ctl()).is_ok());
    let mut a = ctl(); a.buf_index = 1;
    assert_eq!(prep_ctl(&a), Err(Errno::Einval));
    let mut b = ctl(); b.splice_fd_in = 1;
    assert_eq!(prep_ctl(&b), Err(Errno::Einval));
}

#[test]
fn a_wait_entry_reads_its_array_and_capacity() {
    let w = prep_wait(&wait()).expect("valid");
    assert_eq!(w.events, 0x900);
    assert_eq!(w.maxevents, 64);
}

/// This operation has no timeout. Reading `off` as one — or accepting it and
/// dropping it — would hand a caller an immediate harvest while it believed it
/// had asked to wait.
#[test]
fn a_wait_entry_refuses_a_timeout_it_cannot_honour() {
    let mut s = wait();
    s.off = 1000;
    assert_eq!(prep_wait(&s), Err(Errno::Einval));
}

#[test]
fn a_wait_entry_refuses_the_other_fields_it_does_not_read() {
    for mutate in [
        (|s: &mut Sqe| s.op_flags = 1) as fn(&mut Sqe),
        |s: &mut Sqe| s.buf_index = 1,
        |s: &mut Sqe| s.splice_fd_in = 1,
    ] {
        let mut s = wait();
        mutate(&mut s);
        assert_eq!(prep_wait(&s), Err(Errno::Einval));
    }
}

/// The rung that decides whether an idle epoll set costs a completion per
/// poll or none at all. A harvest of zero must become "not yet" so the engine
/// arms the entry on the set; reporting `0` would end the submission with a
/// completion that told the caller nothing.
#[test]
fn an_empty_harvest_is_not_yet_rather_than_zero() {
    assert_eq!(wait_result(0), -(Errno::Eagain.as_i32() as i64));
}

#[test]
fn a_non_empty_harvest_is_reported_as_its_count() {
    assert_eq!(wait_result(1), 1);
    assert_eq!(wait_result(64), 64);
}
