use crate::coredump::socket_protocol::{self, Owner};
use crate::coredump::socket_uapi::{self, Mark};
use alloc::vec::Vec;

fn ack(spare: u32, mask: u64) -> [u8; socket_uapi::WIRE_SIZE_V0] {
    let mut out = [0u8; socket_uapi::WIRE_SIZE_V0];
    out[0..4].copy_from_slice(&socket_uapi::WIRE_SIZE_V0_U32.to_ne_bytes());
    out[4..8].copy_from_slice(&spare.to_ne_bytes());
    out[8..16].copy_from_slice(&mask.to_ne_bytes());
    out
}

#[test]
fn request_advertises_the_complete_version_zero_contract() {
    let request = socket_uapi::request_bytes();
    assert_eq!(u32::from_ne_bytes(request[0..4].try_into().unwrap()), 16);
    assert_eq!(u32::from_ne_bytes(request[4..8].try_into().unwrap()), 16);
    assert_eq!(u64::from_ne_bytes(request[8..16].try_into().unwrap()), 0x0f);
}

#[test]
fn acknowledgement_size_selects_the_required_marker() {
    assert_eq!(socket_protocol::size_mark(15), Some(Mark::MinSize));
    assert_eq!(socket_protocol::size_mark(16), None);
    assert_eq!(socket_protocol::size_mark(17), Some(Mark::MaxSize));
}

#[test]
fn direct_socket_wait_tracks_the_collector_limit() {
    assert!(!socket_protocol::direct_wait(0));
    assert!(socket_protocol::direct_wait(1));
}

#[test]
fn exactly_one_dump_owner_is_accepted_with_optional_wait() {
    let cases = [
        (socket_uapi::MODE_KERNEL, Owner::Kernel, false),
        (socket_uapi::MODE_USERSPACE | socket_uapi::MODE_WAIT, Owner::Userspace, true),
        (socket_uapi::MODE_REJECT, Owner::Reject, false),
    ];
    for (mask, owner, wait) in cases {
        let choice = socket_protocol::validate_ack(&ack(0, mask)).expect("valid choice");
        assert_eq!(choice.owner, owner);
        assert_eq!(choice.wait, wait);
    }
}

#[test]
fn unknown_spare_and_mask_bits_are_unsupported() {
    assert_eq!(socket_protocol::validate_ack(&ack(1, socket_uapi::MODE_KERNEL)),
        Err(Some(Mark::Unsupported)));
    assert_eq!(socket_protocol::validate_ack(&ack(0, socket_uapi::MODE_KERNEL | (1 << 63))),
        Err(Some(Mark::Unsupported)));
}

#[test]
fn missing_or_multiple_dump_owners_are_conflicting() {
    assert_eq!(socket_protocol::validate_ack(&ack(0, socket_uapi::MODE_WAIT)),
        Err(Some(Mark::Conflicting)));
    assert_eq!(socket_protocol::validate_ack(&ack(0,
        socket_uapi::MODE_KERNEL | socket_uapi::MODE_USERSPACE)),
        Err(Some(Mark::Conflicting)));
}

#[test]
fn acknowledgement_size_changed_after_preflight_is_silently_rejected() {
    let mut bytes = ack(0, socket_uapi::MODE_KERNEL);
    bytes[0..4].copy_from_slice(&15u32.to_ne_bytes());
    assert_eq!(socket_protocol::validate_ack(&bytes), Err(None));
}

#[test]
fn markers_are_full_native_u32_values() {
    assert_eq!(socket_uapi::mark_bytes(Mark::RequestAck), 0u32.to_ne_bytes());
    assert_eq!(socket_uapi::mark_bytes(Mark::Conflicting), 4u32.to_ne_bytes());
}

#[test]
fn exchange_sends_request_then_success_marker() {
    let input = ack(0, socket_uapi::MODE_USERSPACE | socket_uapi::MODE_WAIT);
    let mut cursor = 0usize;
    let mut output = Vec::new();
    let choice = socket_protocol::negotiate(|buf| {
        buf.copy_from_slice(&input[cursor..cursor + buf.len()]);
        cursor += buf.len();
        true
    }, |buf| { output.extend_from_slice(buf); true }).expect("successful exchange");
    assert_eq!(choice.owner, Owner::Userspace);
    assert!(choice.wait);
    let mut expected = socket_uapi::request_bytes().to_vec();
    expected.extend_from_slice(&socket_uapi::mark_bytes(Mark::RequestAck));
    assert_eq!(output, expected);
}

#[test]
fn exchange_marks_an_ack_that_is_too_small_without_reading_a_body() {
    let input = 15u32.to_ne_bytes();
    let mut reads = 0usize;
    let mut output = Vec::new();
    assert!(socket_protocol::negotiate(|buf| {
        reads += 1;
        buf.copy_from_slice(&input);
        true
    }, |buf| { output.extend_from_slice(buf); true }).is_none());
    assert_eq!(reads, 1);
    let mut expected = socket_uapi::request_bytes().to_vec();
    expected.extend_from_slice(&socket_uapi::mark_bytes(Mark::MinSize));
    assert_eq!(output, expected);
}
