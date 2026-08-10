use super::*;

/// The frame's four regions tile the drawn buffer with no gap and no overlap,
/// which is what lets a caller find the payload by adding one published
/// length to the buffer's base.
#[test]
fn the_frame_tiles_the_drawn_buffer_in_order() {
    let f = frame(4096, 128, 64).expect("the buffer holds the frame");
    assert_eq!(f.name_off, RECVMSG_OUT_BYTES);
    assert_eq!(f.control_off, RECVMSG_OUT_BYTES + 128);
    assert_eq!(f.payload_off, RECVMSG_OUT_BYTES + 128 + 64);
    assert_eq!(f.hdr_len, f.payload_off);
    assert_eq!(f.payload_len, 4096 - f.hdr_len);
    // No region starts before the one in front of it ends.
    assert_eq!(f.name_off + f.namelen, f.control_off);
    assert_eq!(f.control_off + f.controllen, f.payload_off);
}

/// A header with neither an address nor an ancillary capacity still costs the
/// fixed part: the caller reads the payload length out of it.
#[test]
fn a_frame_with_no_address_and_no_ancillary_still_carries_its_header() {
    let f = frame(64, 0, 0).expect("the buffer holds the header");
    assert_eq!(f.hdr_len, RECVMSG_OUT_BYTES);
    assert_eq!(f.payload_off, RECVMSG_OUT_BYTES);
    assert_eq!(f.payload_len, 64 - RECVMSG_OUT_BYTES);
}

/// A buffer with no room for the header has nowhere to say what happened, so
/// nothing is delivered into it.
#[test]
fn a_buffer_too_small_for_the_frame_is_refused_before_any_delivery() {
    assert_eq!(frame(RECVMSG_OUT_BYTES - 1, 0, 0), Err(Errno::Efault));
    assert_eq!(frame(64, 64, 0), Err(Errno::Efault));
    assert_eq!(frame(64, 32, 32), Err(Errno::Efault));
    // Exactly the frame and no payload room is legal: a zero-length delivery
    // still reports its address and flags.
    let f = frame(64, 32, 16).expect("the buffer holds the frame exactly");
    assert_eq!(f.payload_len, 0);
}

#[test]
fn a_capacity_pair_that_cannot_be_added_is_refused_rather_than_wrapped() {
    assert_eq!(frame(u32::MAX, u32::MAX, 0), Err(Errno::Eoverflow));
    assert_eq!(frame(u32::MAX, 0, u32::MAX), Err(Errno::Eoverflow));
}

/// The result a delivery reports is the whole frame plus what the payload
/// area could hold — the offset of the NEXT frame, not the byte count.
#[test]
fn the_result_counts_the_frame_and_the_payload_it_carried() {
    let f = frame(4096, 128, 0).expect("the buffer holds the frame");
    assert_eq!(f.result(0), f.hdr_len as i64);
    assert_eq!(f.result(100), f.hdr_len as i64 + 100);
    // A payload larger than the area is carried only as far as it fits.
    assert_eq!(f.result(u64::MAX), f.hdr_len as i64 + f.payload_len as i64);
}

/// The header still reports the delivery's true length when the frame could
/// only carry part of it, so a caller can tell a truncated message from a
/// short one.
#[test]
fn the_header_reports_the_true_payload_length_even_when_it_did_not_fit() {
    let f = frame(64, 0, 0).expect("the buffer holds the header");
    assert!(payloadlen(1000) > f.payload_len);
    assert_eq!(payloadlen(1000), 1000);
    assert_eq!(payloadlen(u64::MAX), u32::MAX);
}

/// The defect this placement exists to prevent: a `RECVMSG` carrying
/// `IOSQE_BUFFER_SELECT` delivering to the address in the ENTRY — which on
/// that opcode is the message header — while the completion reports the
/// buffer id the ring drew and retired. The caller reads the buffer it was
/// told about and finds it untouched, and its header has been written over
/// with payload.
#[test]
fn a_selected_receive_delivers_into_the_drawn_buffer_never_the_entry_address() {
    const ENTRY: u64 = 0x1000;   // the entry's `addr`: the caller's msghdr
    const DRAWN: u64 = 0x9_0000; // the buffer the ring drew from the group
    for multishot in [false, true] {
        let s = selected(multishot, DRAWN, 4096, 0, 0, 0).expect("the buffer holds any frame");
        assert!(s.payload.0 >= DRAWN && s.payload.0 < DRAWN + 4096,
                "multishot={multishot}: payload {:#x} is outside the drawn buffer", s.payload.0);
        assert_ne!(s.payload.0, ENTRY, "multishot={multishot}");
        assert!(s.payload.1 > 0);
    }
}

/// A single-shot selected receive uses the whole drawn buffer: its header
/// writebacks still go to the caller's `msghdr`, so nothing is spent inside
/// the buffer.
#[test]
fn a_single_shot_selected_receive_spends_none_of_the_buffer_on_a_header() {
    let s = selected(false, 0x9_0000, 4096, 0, 128, 64).expect("no frame is laid out");
    assert_eq!(s.payload, (0x9_0000, 4096));
    assert_eq!(s.frame, None);
}

/// While armed there is no `msghdr` left to write back into, so the header is
/// spent out of the buffer and the payload starts after it.
#[test]
fn an_armed_selected_receive_spends_the_frame_out_of_the_buffer() {
    let s = selected(true, 0x9_0000, 4096, 0, 128, 64).expect("the buffer holds the frame");
    let f = s.frame.expect("an armed delivery carries its own header");
    assert_eq!(s.payload, (0x9_0000 + f.hdr_len as u64, 4096 - f.hdr_len));
    assert_eq!(f.hdr_len, RECVMSG_OUT_BYTES + 128 + 64);
}

#[test]
fn a_drawn_buffer_too_small_for_the_frame_delivers_nothing() {
    assert_eq!(selected(true, 0x9_0000, 8, 0, 0, 0), Err(Errno::Efault));
    // The same buffer serves a single-shot delivery, which frames nothing.
    assert!(selected(false, 0x9_0000, 8, 0, 0, 0).is_ok());
}

/// The header's single segment caps how much of the drawn buffer one delivery
/// may use; zero means all of it. A run of segments describes a scatter the
/// drawn buffer is not, so it is malformed rather than quietly truncated to
/// its first entry.
#[test]
fn the_header_caps_the_delivery_with_exactly_one_segment_or_none() {
    assert_eq!(cap_from_iovlen(0, None), Ok(0));
    assert_eq!(cap_from_iovlen(1, Some(512)), Ok(512));
    assert_eq!(cap_from_iovlen(2, Some(512)), Err(Errno::Einval));
    assert_eq!(cap_from_iovlen(1024, None), Err(Errno::Einval));
}

#[test]
fn the_cap_shortens_the_drawn_buffer_and_never_lengthens_it() {
    assert_eq!(selected(false, 0x9_0000, 4096, 512, 0, 0).map(|s| s.payload),
               Ok((0x9_0000, 512)));
    // Zero is "all of it", and a cap past the end cannot reach past the end.
    assert_eq!(selected(false, 0x9_0000, 4096, 0, 0, 0).map(|s| s.payload),
               Ok((0x9_0000, 4096)));
    assert_eq!(selected(false, 0x9_0000, 4096, 1 << 40, 0, 0).map(|s| s.payload),
               Ok((0x9_0000, 4096)));
    // A cap that leaves no room for the frame stops the delivery, exactly as a
    // buffer that small would.
    assert_eq!(selected(true, 0x9_0000, 4096, 8, 0, 0), Err(Errno::Efault));
}

/// The two caps are not both live: an entry length beside a header length
/// would be two answers to one question, and the reference reads only the
/// header's on this opcode.
#[test]
fn the_entry_length_does_not_cap_a_message_carrying_receive() {
    use crate::io_uring_abi::ops::{IORING_OP_RECV, IORING_OP_RECVMSG, IORING_OP_READ,
                                   IORING_OP_SEND};
    assert!(!entry_caps_drawn_buffer(IORING_OP_RECVMSG));
    for op in [IORING_OP_RECV, IORING_OP_READ, IORING_OP_SEND] {
        assert!(entry_caps_drawn_buffer(op), "op {op}");
    }
}
