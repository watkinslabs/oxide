// The receive copy-fault transaction, driven through the real publication.

use super::*;
use alloc::vec::Vec;
use alloc::vec;

use crate::msg_layout::MsgLayout;
use crate::recv_user::IoVec;

const EFAULT: i64 = -(syscall::errno::Errno::Efault.as_i32() as i64);
/// Native `msghdr` offsets the writeback assertions read back.
const NAMELEN_AT: usize = 8;
const CONTROLLEN_AT: usize = 40;
const FLAGS_AT: usize = 48;
/// An address the usercopy range check refuses, whatever it is asked to move.
const UNWRITABLE: u64 = u64::MAX - 63;

/// A receive destination over caller-owned memory. `UNWRITABLE` is the hosted
/// stand-in for user memory that cannot be written: the usercopy range check
/// refuses it before any byte moves.
fn user(msgp: u64, name: u64, namelen: u32, control: u64, controllen: usize,
    iov: Vec<IoVec>) -> RecvUser
{
    let capacity = iov.iter().map(|v| v.len).sum();
    RecvUser { msgp, name, namelen, name_len_ptr: 0, control, controllen, iov, capacity,
        layout: MsgLayout::Native }
}

// A record transport reports EFAULT for a short copy even though a prefix
// reached user memory, and a stream reports the prefix.
#[test]
fn the_transport_decides_what_a_short_payload_copy_reports() {
    assert_eq!(payload_fault(Transport::Record, 0), PayloadFault::Fail);
    assert_eq!(payload_fault(Transport::Record, 7), PayloadFault::Fail);
    assert_eq!(payload_fault(Transport::Stream, 0), PayloadFault::Fail);
    assert_eq!(payload_fault(Transport::Stream, 7), PayloadFault::Deliver(7));
}

// The two transports' answers, as the two receive paths ask for them.
#[test]
fn the_two_transports_answer_a_short_copy_differently() {
    assert_eq!(stream_result(7, EFAULT), Ok(7));
    assert_eq!(stream_result(0, EFAULT), Err(EFAULT));
    assert_eq!(record_result(7, EFAULT), Err(EFAULT));
    assert_eq!(record_result(0, EFAULT), Err(EFAULT));
}

#[test]
fn a_control_fault_publishes_the_prefix_that_landed() {
    assert_eq!(control_len(crate::recv_control::ControlCopy { copied: 32, faulted: true }), 32);
    assert_eq!(control_len(crate::recv_control::ControlCopy { copied: 32, faulted: false }), 32);
}

// The whole publication in order, over a complete msghdr: the control stream
// lands, then the name and its length, then the flags and the control length.
#[test]
fn a_clean_publication_writes_control_then_name_then_both_header_words() {
    let mut msg = [0u8; 56];
    let mut name = [0u8; 16];
    let mut control = [0u8; 64];
    let dest = user(msg.as_mut_ptr() as u64, name.as_mut_ptr() as u64, 16,
        control.as_mut_ptr() as u64, control.len(), Vec::new());
    let mut ctrl = crate::recv_control::Control::new(control.len());
    ctrl.push(1, 2, &[9u8; 4]);
    assert_eq!(publish(&dest, &mut ctrl, &[7u8; 12], 0, 5), 5);
    assert_eq!(u64::from_ne_bytes(control[..8].try_into().unwrap()) as usize, 20);
    assert_eq!(&name[..12], &[7u8; 12]);
    assert_eq!(u32::from_ne_bytes(msg[NAMELEN_AT..NAMELEN_AT + 4].try_into().unwrap()), 12);
    assert_eq!(u64::from_ne_bytes(msg[CONTROLLEN_AT..CONTROLLEN_AT + 8].try_into().unwrap()), 24);
    assert_eq!(u32::from_ne_bytes(msg[FLAGS_AT..FLAGS_AT + 4].try_into().unwrap()), 0);
}

// An unwritable control buffer does not fail the receive: the caller still
// gets its byte count, its address and its flags, with a zero control length.
#[test]
fn an_unwritable_control_buffer_does_not_fail_the_receive() {
    let mut msg = [0u8; 56];
    let mut name = [0u8; 16];
    let dest = user(msg.as_mut_ptr() as u64, name.as_mut_ptr() as u64, 16, UNWRITABLE, 64,
        Vec::new());
    let mut ctrl = crate::recv_control::Control::new(64);
    ctrl.push(1, 2, &[9u8; 4]);
    assert_eq!(publish(&dest, &mut ctrl, &[7u8; 12], net::uapi::MSG_TRUNC as u32, 5), 5);
    assert_eq!(&name[..12], &[7u8; 12]);
    assert_eq!(u64::from_ne_bytes(msg[CONTROLLEN_AT..CONTROLLEN_AT + 8].try_into().unwrap()), 0);
    assert_eq!(u32::from_ne_bytes(msg[FLAGS_AT..FLAGS_AT + 4].try_into().unwrap()),
        net::uapi::MSG_TRUNC as u32);
}

// An unwritable address buffer DOES fail it, and stops the publication there:
// neither header word is written, so a caller cannot read a flags word that
// belongs to a receive it was told failed.
#[test]
fn an_unwritable_name_fails_the_receive_before_either_header_word() {
    let mut msg = [0xa5u8; 56];
    let mut control = [0u8; 64];
    let dest = user(msg.as_mut_ptr() as u64, UNWRITABLE, 16, control.as_mut_ptr() as u64,
        control.len(), Vec::new());
    let mut ctrl = crate::recv_control::Control::new(control.len());
    ctrl.push(1, 2, &[9u8; 4]);
    assert_eq!(publish(&dest, &mut ctrl, &[7u8; 12], 0, 5), EFAULT);
    // The control stream ran first and did land. The true source length is
    // published before the address bytes, so it lands too.
    assert_eq!(u64::from_ne_bytes(control[..8].try_into().unwrap()) as usize, 20);
    assert_eq!(u32::from_ne_bytes(msg[NAMELEN_AT..NAMELEN_AT + 4].try_into().unwrap()), 12);
    assert_eq!(&msg[CONTROLLEN_AT..CONTROLLEN_AT + 8], &[0xa5u8; 8]);
    assert_eq!(&msg[FLAGS_AT..FLAGS_AT + 4], &[0xa5u8; 4]);
}

// An unwritable msghdr fails the receive, after the control stream — which
// lives in its own buffer — has already landed. The address does NOT land:
// its true length is published into the msghdr first, and that is what faults.
#[test]
fn an_unwritable_msghdr_fails_the_receive_after_the_control_stream_lands() {
    let mut name = [0u8; 16];
    let mut control = [0u8; 64];
    let dest = user(UNWRITABLE, name.as_mut_ptr() as u64, 16,
        control.as_mut_ptr() as u64, control.len(), Vec::new());
    let mut ctrl = crate::recv_control::Control::new(control.len());
    ctrl.push(1, 2, &[9u8; 4]);
    assert_eq!(publish(&dest, &mut ctrl, &[7u8; 12], 0, 5), EFAULT);
    assert_eq!(u64::from_ne_bytes(control[..8].try_into().unwrap()) as usize, 20);
    assert_eq!(&name, &[0u8; 16]);
}

// The settled form takes the same two steps in the same order, for the
// families that install descriptors before they publish.
#[test]
fn the_settled_publication_writes_the_name_before_the_header() {
    let mut msg = [0xa5u8; 56];
    let dest = user(msg.as_mut_ptr() as u64, UNWRITABLE, 16, 0, 0, Vec::new());
    assert_eq!(publish_settled(&dest, 24, &[7u8; 12], 0, 5), EFAULT);
    assert_eq!(&msg[FLAGS_AT..FLAGS_AT + 4], &[0xa5u8; 4]);

    let mut msg = [0u8; 56];
    let mut name = [0u8; 16];
    let dest = user(msg.as_mut_ptr() as u64, name.as_mut_ptr() as u64, 16, 0, 0, Vec::new());
    assert_eq!(publish_settled(&dest, 24, &[7u8; 12], net::uapi::MSG_EOR as u32, 5), 5);
    assert_eq!(u64::from_ne_bytes(msg[CONTROLLEN_AT..CONTROLLEN_AT + 8].try_into().unwrap()), 24);
    assert_eq!(u32::from_ne_bytes(msg[FLAGS_AT..FLAGS_AT + 4].try_into().unwrap()),
        net::uapi::MSG_EOR as u32);
}

// A receive with no payload capacity still publishes; the payload rule only
// speaks about a copy that was attempted.
#[test]
fn a_payload_that_landed_whole_is_not_a_fault_at_all() {
    let mut buf = [0u8; 4];
    let dest = user(0, 0, 0, 0, 0, vec![IoVec { base: buf.as_mut_ptr() as u64, len: 4 }]);
    assert_eq!(dest.copy_payload_record(b"abcd"), Ok(4));
    assert_eq!(&buf, b"abcd");
}
