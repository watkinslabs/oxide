// `TCP_ZEROCOPY_RECEIVE` contract: the operand layout, the optlen versioning,
// the errno ordering, and every output-field update rule.

use super::*;

const PAGE: u64 = 4096;

fn query() -> ZcQuery {
    ZcQuery {
        address: 0x1000_0000, length: 8 * PAGE as u32, copybuf_len: 0, flags: 0,
        inq: 0, listening: false, done: false,
        window_end: Some(0x1000_0000 + 8 * PAGE), page: PAGE,
    }
}

// ---- operand layout -------------------------------------------------------

#[test]
fn field_offsets_are_the_published_abi() {
    assert_eq!((OFF_ADDRESS, OFF_LENGTH, OFF_RECV_SKIP_HINT, OFF_INQ), (0, 8, 12, 16));
    assert_eq!((OFF_ERR, OFF_COPYBUF_ADDRESS, OFF_COPYBUF_LEN, OFF_FLAGS), (20, 24, 32, 36));
    assert_eq!((OFF_MSG_CONTROL, OFF_MSG_CONTROLLEN, OFF_MSG_FLAGS, OFF_RESERVED), (40, 48, 56, 60));
    assert_eq!(ZC_SIZE, 64);
}

#[test]
fn end_of_field_lengths_name_each_struct_version() {
    assert_eq!(END_LENGTH, 12);
    assert_eq!(END_RECV_SKIP_HINT, 16);
    assert_eq!(END_INQ, 20);
    assert_eq!(END_ERR, 24);
    assert_eq!(END_COPYBUF_ADDRESS, 32);
    assert_eq!(END_COPYBUF_LEN, 36);
    assert_eq!(END_FLAGS, 40);
    assert_eq!(END_MSG_CONTROL, 48);
    assert_eq!(END_MSG_CONTROLLEN, 56);
    assert_eq!(END_MSG_FLAGS, 60);
}

#[test]
fn round_trip_places_every_field_at_its_offset() {
    let zc = Zc {
        address: 0x1122_3344_5566_7788, length: 0x1111_2222, recv_skip_hint: 0x3333_4444,
        inq: 0x5555_6666, err: -11, copybuf_address: 0x99aa_bbcc_ddee_ff00,
        copybuf_len: -1, flags: ZEROCOPY_FLAG_TLB_CLEAN_HINT,
        msg_control: 0x0102_0304_0506_0708, msg_controllen: 0x1020_3040_5060_7080,
        msg_flags: CMSG_TS, reserved: 0,
    };
    let bytes = zc.to_bytes();
    assert_eq!(Zc::from_bytes(&bytes), zc);
    assert_eq!(u64_at(&bytes, OFF_ADDRESS), zc.address);
    assert_eq!(u32_at(&bytes, OFF_LENGTH), zc.length);
    assert_eq!(u32_at(&bytes, OFF_ERR) as i32, zc.err);
    assert_eq!(u32_at(&bytes, OFF_COPYBUF_LEN) as i32, zc.copybuf_len);
}

#[test]
fn a_short_operand_reads_the_absent_fields_as_zero() {
    let full = Zc { address: 0x4000, length: 0x8000, copybuf_len: 7, flags: 1,
                    msg_flags: CMSG_TS, ..Zc::default() };
    let bytes = full.to_bytes();
    // The oldest accepted version carries only address + length.
    let old = Zc::from_bytes(&bytes[..END_LENGTH]);
    assert_eq!((old.address, old.length), (0x4000, 0x8000));
    assert_eq!((old.copybuf_len, old.flags, old.msg_flags), (0, 0, 0));
    // The version that first carried copybuf_len still misses flags.
    let mid = Zc::from_bytes(&bytes[..END_COPYBUF_LEN]);
    assert_eq!(mid.copybuf_len, 7);
    assert_eq!((mid.flags, mid.msg_flags), (0, 0));
}

// ---- optlen admission -----------------------------------------------------

#[test]
fn optlen_below_the_length_field_is_rejected() {
    assert_eq!(admit_optlen(-1), Err(Errno::Einval));
    assert_eq!(admit_optlen(0), Err(Errno::Einval));
    assert_eq!(admit_optlen(END_LENGTH as i32 - 1), Err(Errno::Einval));
    assert_eq!(admit_optlen(END_LENGTH as i32), Ok(LenPlan::Use(END_LENGTH)));
}

#[test]
fn every_published_version_length_is_accepted_verbatim() {
    for len in [END_LENGTH, END_RECV_SKIP_HINT, END_INQ, END_ERR, END_COPYBUF_ADDRESS,
                END_COPYBUF_LEN, END_FLAGS, END_MSG_CONTROL, END_MSG_CONTROLLEN,
                END_MSG_FLAGS, ZC_SIZE] {
        assert_eq!(admit_optlen(len as i32), Ok(LenPlan::Use(len)), "optlen {}", len);
    }
}

#[test]
fn an_oversized_optlen_clamps_after_its_tail_is_proven_unset() {
    assert_eq!(admit_optlen(ZC_SIZE as i32 + 8),
               Ok(LenPlan::Clamp { tail_off: ZC_SIZE, tail_len: 8 }));
    assert_eq!(admit_optlen(i32::MAX),
               Ok(LenPlan::Clamp { tail_off: ZC_SIZE, tail_len: i32::MAX as usize - ZC_SIZE }));
}

#[test]
fn input_only_fields_are_screened() {
    assert_eq!(validate_input(&Zc::default()), Ok(()));
    assert_eq!(validate_input(&Zc { reserved: 1, ..Zc::default() }), Err(Errno::Einval));
    assert_eq!(validate_input(&Zc { msg_flags: CMSG_TS, ..Zc::default() }), Ok(()));
    assert_eq!(validate_input(&Zc { msg_flags: CMSG_TS | 4, ..Zc::default() }), Err(Errno::Einval));
    // `flags` is not screened: an unknown bit is a hint this kernel ignores.
    assert_eq!(validate_input(&Zc { flags: 0xffff_ffff, ..Zc::default() }), Ok(()));
}

// ---- output staging -------------------------------------------------------

#[test]
fn output_stage_follows_the_operand_version() {
    assert_eq!(output_stage(END_LENGTH), Stage::Out);
    assert_eq!(output_stage(END_RECV_SKIP_HINT), Stage::Out);
    assert_eq!(output_stage(END_INQ), Stage::Inq);
    for len in [END_ERR, END_COPYBUF_ADDRESS, END_COPYBUF_LEN, END_FLAGS,
                END_MSG_CONTROL, END_MSG_CONTROLLEN] {
        assert_eq!(output_stage(len), Stage::SkErr, "optlen {}", len);
    }
    assert_eq!(output_stage(END_MSG_FLAGS), Stage::Cmsg);
    assert_eq!(output_stage(ZC_SIZE), Stage::Cmsg);
}

#[test]
fn a_length_landing_mid_field_publishes_only_the_base_fields() {
    for len in [13, 17, 21, 26, 33, 44, 52, 58] {
        assert_eq!(output_stage(len), Stage::Out, "optlen {}", len);
    }
}

#[test]
fn the_stages_are_cumulative() {
    assert!(Stage::Cmsg > Stage::SkErr && Stage::SkErr > Stage::Inq && Stage::Inq > Stage::Out);
}

// ---- plan: errno ordering -------------------------------------------------

#[test]
fn a_misaligned_address_is_rejected_before_the_socket_state() {
    let q = ZcQuery { address: 0x1000_0001, listening: true, ..query() };
    assert_eq!(plan(&q), Err(Errno::Einval));
    let q = ZcQuery { address: PAGE - 1, ..query() };
    assert_eq!(plan(&q), Err(Errno::Einval));
}

#[test]
fn a_listening_socket_has_no_stream_to_map() {
    let q = ZcQuery { listening: true, inq: 8 * PAGE as u32, ..query() };
    assert_eq!(plan(&q), Err(Errno::Enotconn));
}

#[test]
fn an_ended_stream_with_nothing_queued_reports_end_of_stream() {
    assert_eq!(plan(&ZcQuery { inq: 0, done: true, ..query() }), Err(Errno::Eio));
    // Still open: no error, just nothing to map.
    assert_eq!(plan(&ZcQuery { inq: 0, done: false, ..query() }),
               Ok(ZcAction::Short { recv_skip_hint: 0 }));
}

#[test]
fn a_window_that_covers_no_bytes_is_rejected() {
    let q = ZcQuery { inq: 8 * PAGE as u32, window_end: None, ..query() };
    assert_eq!(plan(&q), Err(Errno::Einval));
    let q = ZcQuery { inq: 8 * PAGE as u32, window_end: Some(0x1000_0000), ..query() };
    assert_eq!(plan(&q), Err(Errno::Einval));
}

// ---- plan: the mapping decision -------------------------------------------

#[test]
fn everything_queued_that_fits_the_copy_buffer_takes_the_copy_path() {
    let q = ZcQuery { inq: 100, copybuf_len: 100, ..query() };
    assert_eq!(plan(&q), Ok(ZcAction::Fallback { bytes: 100 }));
    // One byte past the copy buffer is no longer a fallback.
    let q = ZcQuery { inq: 101, copybuf_len: 100, ..query() };
    assert_eq!(plan(&q), Ok(ZcAction::Short { recv_skip_hint: 101 }));
    // An empty queue never falls back, whatever the copy buffer offers.
    let q = ZcQuery { inq: 0, copybuf_len: 4096, ..query() };
    assert_eq!(plan(&q), Ok(ZcAction::Short { recv_skip_hint: 0 }));
    // A negative copy-buffer length offers nothing.
    let q = ZcQuery { inq: 10, copybuf_len: -1, ..query() };
    assert_eq!(plan(&q), Ok(ZcAction::Short { recv_skip_hint: 10 }));
}

#[test]
fn less_than_a_page_queued_maps_nothing_and_reports_the_whole_queue() {
    let q = ZcQuery { inq: PAGE as u32 - 1, ..query() };
    assert_eq!(plan(&q), Ok(ZcAction::Short { recv_skip_hint: PAGE as u32 - 1 }));
}

#[test]
fn the_mapped_length_is_the_page_floor_of_window_request_and_queue() {
    // Queue is the binding limit.
    let q = ZcQuery { inq: 3 * PAGE as u32 + 100, ..query() };
    assert_eq!(plan(&q), Ok(ZcAction::Map {
        zap_bytes: 3 * PAGE as u32, map_bytes: 3 * PAGE as u32,
        length: 3 * PAGE as u32, recv_skip_hint: 0 }));
    // The caller's requested length is the binding limit.
    let q = ZcQuery { inq: 8 * PAGE as u32, length: 2 * PAGE as u32 + 1, ..query() };
    assert_eq!(plan(&q), Ok(ZcAction::Map {
        zap_bytes: 2 * PAGE as u32, map_bytes: 2 * PAGE as u32,
        length: 2 * PAGE as u32, recv_skip_hint: 0 }));
    // The window is the binding limit.
    let q = ZcQuery { inq: 8 * PAGE as u32, window_end: Some(0x1000_0000 + PAGE), ..query() };
    assert_eq!(plan(&q), Ok(ZcAction::Map {
        zap_bytes: PAGE as u32, map_bytes: PAGE as u32,
        length: PAGE as u32, recv_skip_hint: 0 }));
}

#[test]
fn a_sub_page_window_maps_nothing_and_hands_the_bytes_to_the_copy_path() {
    let q = ZcQuery { inq: 8 * PAGE as u32, window_end: Some(0x1000_0000 + 512), ..query() };
    assert_eq!(plan(&q), Ok(ZcAction::Map {
        zap_bytes: 0, map_bytes: 0, length: 512, recv_skip_hint: 512 }));
}

#[test]
fn the_clean_tlb_hint_never_changes_what_is_mapped() {
    let plain = plan(&ZcQuery { inq: 4 * PAGE as u32, ..query() });
    let hinted = plan(&ZcQuery { inq: 4 * PAGE as u32,
                                 flags: ZEROCOPY_FLAG_TLB_CLEAN_HINT, ..query() });
    assert_eq!(plain, hinted);
    // The window is dropped before the remap either way — a stale translation
    // there would publish the previous call's bytes.
    assert_eq!(hinted, Ok(ZcAction::Map { zap_bytes: 4 * PAGE as u32,
        map_bytes: 4 * PAGE as u32, length: 4 * PAGE as u32, recv_skip_hint: 0 }));
}

// ---- straggler + finish ---------------------------------------------------

#[test]
fn the_copy_buffer_takes_what_could_not_be_mapped() {
    assert_eq!(straggler_bytes(4096, 512), 512);
    assert_eq!(straggler_bytes(200, 512), 200);
    assert_eq!(straggler_bytes(0, 512), 0);
    assert_eq!(straggler_bytes(-3, 512), 0);
    assert_eq!(straggler_bytes(4096, 0), 0);
}

#[test]
fn donation_transfers_pages_and_releases_only_a_rejected_page() {
    let page = PAGE as u32;
    let mut pages = alloc::collections::VecDeque::from([11u64, 22, 33]);
    let mut installed = alloc::vec::Vec::new();
    let mut released = alloc::vec::Vec::new();
    let mapped = donate_pages(3 * page, page, || pages.pop_front(), |off, pa| {
        installed.push((off, pa));
        pa != 22
    }, |pa| released.push(pa));

    assert_eq!(mapped, page);
    assert_eq!(installed, alloc::vec![(0, 11), (PAGE as u64, 22)]);
    assert_eq!(released, alloc::vec![22]);
    assert_eq!(pages, alloc::collections::VecDeque::from([33]));
}

#[test]
fn donation_stops_cleanly_when_the_receive_queue_runs_out() {
    let page = PAGE as u32;
    let mut pages = alloc::collections::VecDeque::from([44u64]);
    assert_eq!(donate_pages(2 * page, page, || pages.pop_front(), |_, _| true, |_| {}), page);
}

#[test]
fn a_fully_mapped_window_retires_the_hint() {
    assert_eq!(finish(4 * PAGE as u32, 4 * PAGE as u32, 0, 0, false),
               Ok(ZcFinish { length: 4 * PAGE as u32, recv_skip_hint: 0, copybuf_len: 0 }));
}

#[test]
fn a_partial_map_keeps_the_hint_for_the_bytes_left_behind() {
    assert_eq!(finish(4 * PAGE as u32, 2 * PAGE as u32, 2 * PAGE as u32, 0, false),
               Ok(ZcFinish { length: 2 * PAGE as u32,
                             recv_skip_hint: 2 * PAGE as u32, copybuf_len: 0 }));
}

#[test]
fn the_straggler_copy_is_subtracted_from_the_hint() {
    assert_eq!(finish(512, 0, 512, 200, false),
               Ok(ZcFinish { length: 0, recv_skip_hint: 312, copybuf_len: 200 }));
}

#[test]
fn moving_no_bytes_over_an_ended_stream_is_the_end_of_stream_report() {
    assert_eq!(finish(0, 0, 0, 0, true), Err(Errno::Eio));
    // Bytes still pending: not the end, even on an ended stream.
    assert_eq!(finish(512, 0, 512, 0, true),
               Ok(ZcFinish { length: 0, recv_skip_hint: 512, copybuf_len: 0 }));
    // Still open: an empty call is not an error.
    assert_eq!(finish(0, 0, 0, 0, false),
               Ok(ZcFinish { length: 0, recv_skip_hint: 0, copybuf_len: 0 }));
}

#[test]
fn a_call_that_only_copied_reports_zero_mapped_length() {
    assert_eq!(finish(512, 0, 512, 512, true),
               Ok(ZcFinish { length: 0, recv_skip_hint: 0, copybuf_len: 512 }));
}
