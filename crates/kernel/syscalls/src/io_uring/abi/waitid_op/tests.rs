use super::*;
use crate::io_uring_abi::ops::IORING_OP_WAITID;

fn sqe() -> Sqe {
    Sqe { opcode: IORING_OP_WAITID, len: 1, fd: 4242, off: 0x7000,
          splice_fd_in: 4, ..Sqe::default() }
}

/// The id type is in `len`, the id in `fd`, the options in `file_index` and
/// the siginfo pointer in `addr2`. Every one of those is a field whose name
/// suggests something else, and every swap between them produces a wait that
/// runs against the wrong child with no error to show for it.
#[test]
fn each_operand_comes_from_its_own_field() {
    let w = prep(&sqe()).expect("valid");
    assert_eq!(w.which, 1);
    assert_eq!(w.id, 4242);
    assert_eq!(w.options, 4);
    assert_eq!(w.infop, 0x7000);
}

#[test]
fn every_field_the_operation_does_not_read_must_be_zero() {
    for mutate in [
        (|s: &mut Sqe| s.addr = 1) as fn(&mut Sqe),
        |s: &mut Sqe| s.buf_index = 1,
        |s: &mut Sqe| s.addr3 = 1,
        |s: &mut Sqe| s.op_flags = 1,
    ] {
        let mut s = sqe();
        mutate(&mut s);
        assert_eq!(prep(&s), Err(Errno::Einval));
    }
}

/// A zero siginfo pointer means "report no siginfo", not an address of zero:
/// the wait engine takes the same convention, so it must survive the decode.
#[test]
fn an_absent_siginfo_pointer_stays_absent() {
    let mut s = sqe();
    s.off = 0;
    assert_eq!(prep(&s).expect("valid").infop, 0);
}

/// A negative id is how a caller names a process group. Reading `fd` unsigned
/// would turn `-1` — "any child" — into a specific pid that does not exist.
#[test]
fn a_negative_id_survives_the_decode() {
    let mut s = sqe();
    s.fd = -1;
    assert_eq!(prep(&s).expect("valid").id, -1);
}
