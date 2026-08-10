use super::*;
use syscall::errno::Errno;
use crate::io_uring_abi::uapi::{
    IORING_SETUP_CLAMP, IORING_SETUP_CQE32, IORING_SETUP_CQE_MIXED, IORING_SETUP_DEFER_TASKRUN,
};

const PAGE: u64 = 4096;
const OK_RING: u32 = IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE32;

fn reg() -> IfqReg {
    IfqReg { if_idx: 0, if_rxq: 0, rq_entries: 4, flags: ZCRX_REG_NODEV,
             area_ptr: 0x1000, region_ptr: 0x2000, offsets: ZcrxOffsets::default(),
             zcrx_id: 0, rx_buf_len: 0, notif_desc: 0, resv: [0; 2] }
}

fn area() -> AreaReg {
    AreaReg { addr: PAGE, len: 8 * PAGE, rq_area_token: 0, flags: 0, dmabuf_fd: 0, resv2: [0; 2] }
}

// ---- record layout -----------------------------------------------------

/// Every record round-trips through its wire form at the size the ABI states.
/// A field that moved would decode as a neighbour's value, which is exactly
/// how a reserved-word check stops catching anything.
#[test]
fn records_round_trip_at_their_abi_sizes() {
    let r = IfqReg { if_idx: 1, if_rxq: 2, rq_entries: 8, flags: ZCRX_REG_NODEV,
                     area_ptr: 0x1111, region_ptr: 0x2222,
                     offsets: ZcrxOffsets { head: 3, tail: 4, rqes: 5, resv2: 0, resv: [0; 2] },
                     zcrx_id: 7, rx_buf_len: 4096, notif_desc: 0x3333, resv: [0; 2] };
    assert_eq!(IfqReg::from_bytes(&r.to_bytes()), r);
    assert_eq!(r.to_bytes().len() as u64, IFQ_REG_BYTES);

    let a = AreaReg { addr: 0x4000, len: 0x8000, rq_area_token: 0, flags: 0,
                      dmabuf_fd: 0, resv2: [0; 2] };
    assert_eq!(AreaReg::from_bytes(&a.to_bytes()), a);
    assert_eq!(a.to_bytes().len() as u64, AREA_REG_BYTES);

    let q = Rqe { off: 0x9000, len: 128, pad: 0 };
    assert_eq!(Rqe::from_bytes(&q.to_bytes()), q);
    assert_eq!(q.to_bytes().len() as u64, RQE_BYTES);
}

/// The offsets are the kernel's, not the caller's, and they are the ones the
/// refill-queue region is actually laid out with.
#[test]
fn the_region_offsets_describe_the_region_that_gets_built() {
    let o = ZcrxOffsets::fill();
    assert_eq!((o.head, o.tail, o.rqes), (0, 4, 64));
    assert_eq!(rq_region_bytes(4), 64 + 16 * 4);
    assert_eq!(admit_rq_region(4, 64 + 16 * 4), Ok(()));
    assert_eq!(admit_rq_region(4, 64 + 16 * 4 - 1), Err(Errno::Einval));
}

// ---- ring flags --------------------------------------------------------

#[test]
fn a_ring_that_cannot_defer_or_cannot_carry_32_byte_completions_is_refused() {
    assert_eq!(admit_ring_flags(OK_RING), Ok(()));
    assert_eq!(admit_ring_flags(IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE_MIXED), Ok(()));
    assert_eq!(admit_ring_flags(IORING_SETUP_CQE32), Err(Errno::Einval));
    assert_eq!(admit_ring_flags(IORING_SETUP_DEFER_TASKRUN), Err(Errno::Einval));
    assert_eq!(admit_ring_flags(0), Err(Errno::Einval));
}

/// Deferral is decided before the completion size: a ring missing both learns
/// about the one it must be BUILT differently for first.
#[test]
fn deferral_is_decided_before_completion_size() {
    assert_eq!(admit_ring_flags(0), Err(Errno::Einval));
    // Both rungs answer EINVAL, so the order is pinned by which rung runs:
    // a CQE32 ring with no deferral still fails.
    assert_eq!(admit_ring_flags(IORING_SETUP_CQE32), Err(Errno::Einval));
}

// ---- registration ------------------------------------------------------

#[test]
fn a_well_formed_device_less_registration_is_admitted() {
    let mut r = reg();
    assert_eq!(admit_ifq_reg(&mut r, OK_RING), Ok(RegKind::NoDev));
    assert_eq!(r.rq_entries, 4);
}

#[test]
fn a_device_registration_reports_the_queue_it_names() {
    let mut r = reg();
    r.flags = 0; r.if_idx = 3; r.if_rxq = 2;
    assert_eq!(admit_ifq_reg(&mut r, OK_RING), Ok(RegKind::Device { if_idx: 3, if_rxq: 2 }));
}

#[test]
fn a_reserved_word_or_a_caller_supplied_id_is_refused_first() {
    let mut r = reg(); r.resv = [1, 0];
    // Every later rung would also fail; the reserved word still answers.
    r.flags = 0xffff_ffff; r.rq_entries = 0;
    assert_eq!(admit_ifq_reg(&mut r, OK_RING), Err(Errno::Einval));
    let mut r = reg(); r.zcrx_id = 1;
    assert_eq!(admit_ifq_reg(&mut r, OK_RING), Err(Errno::Einval));
}

#[test]
fn an_unknown_registration_flag_is_refused() {
    let mut r = reg(); r.flags |= 1 << 4;
    assert_eq!(admit_ifq_reg(&mut r, OK_RING), Err(Errno::Einval));
}

/// The import form is decided before anything about a queue, because an
/// importing caller names no queue at all.
#[test]
fn import_short_circuits_every_queue_rule() {
    let mut r = reg();
    r.flags = ZCRX_REG_IMPORT;
    r.if_rxq = u32::MAX;
    r.rq_entries = 0;
    assert_eq!(admit_ifq_reg(&mut r, OK_RING), Ok(RegKind::Import));
}

#[test]
fn no_queue_named_or_an_empty_refill_queue_is_refused() {
    let mut r = reg(); r.flags = 0; r.if_rxq = u32::MAX;
    assert_eq!(admit_ifq_reg(&mut r, OK_RING), Err(Errno::Einval));
    let mut r = reg(); r.rq_entries = 0;
    assert_eq!(admit_ifq_reg(&mut r, OK_RING), Err(Errno::Einval));
}

/// Naming a device AND asking for no device is a contradiction, not a
/// preference: the reference refuses rather than picking one.
#[test]
fn a_device_named_together_with_nodev_is_refused() {
    let mut r = reg(); r.if_idx = 1;
    assert_eq!(admit_ifq_reg(&mut r, OK_RING), Err(Errno::Einval));
    let mut r = reg(); r.if_rxq = 1;
    assert_eq!(admit_ifq_reg(&mut r, OK_RING), Err(Errno::Einval));
}

#[test]
fn an_oversized_refill_queue_is_clamped_only_when_the_ring_asked_for_it() {
    let mut r = reg(); r.rq_entries = IO_RQ_MAX_ENTRIES + 1;
    assert_eq!(admit_ifq_reg(&mut r, OK_RING), Err(Errno::Einval));
    let mut r = reg(); r.rq_entries = IO_RQ_MAX_ENTRIES + 1;
    assert_eq!(admit_ifq_reg(&mut r, OK_RING | IORING_SETUP_CLAMP), Ok(RegKind::NoDev));
    assert_eq!(r.rq_entries, IO_RQ_MAX_ENTRIES);
}

/// The depth is rewritten so the caller learns what was really built. A caller
/// that kept its own number would mask the ring at the wrong modulus and read
/// entries the kernel never wrote.
#[test]
fn the_refill_queue_depth_is_rounded_up_and_reported_back() {
    let mut r = reg(); r.rq_entries = 5;
    assert_eq!(admit_ifq_reg(&mut r, OK_RING), Ok(RegKind::NoDev));
    assert_eq!(r.rq_entries, 8);
}

// ---- notifications -----------------------------------------------------

#[test]
fn a_notification_descriptor_admits_only_known_types_and_flags() {
    let mut n = NotifDesc::default();
    assert_eq!(admit_notif_desc(&n), Ok(()));
    n.type_mask = ZCRX_NOTIF_TYPE_MASK;
    assert_eq!(admit_notif_desc(&n), Ok(()));
    n.type_mask = 1 << 5;
    assert_eq!(admit_notif_desc(&n), Err(Errno::Einval));
    let mut n = NotifDesc::default(); n.flags = 1 << 3;
    assert_eq!(admit_notif_desc(&n), Err(Errno::Einval));
    let mut n = NotifDesc::default(); n.resv2[8] = 1;
    assert_eq!(admit_notif_desc(&n), Err(Errno::Einval));
}

/// An offset with no flag asking for statistics is refused rather than
/// ignored: ignoring it would leave the caller reading a record nothing
/// writes.
#[test]
fn a_statistics_offset_without_its_flag_is_refused() {
    let mut n = NotifDesc::default();
    n.stats_offset = 128;
    assert_eq!(admit_notif_desc(&n), Err(Errno::Einval));
    n.flags = ZCRX_NOTIF_DESC_FLAG_STATS;
    assert_eq!(admit_notif_desc(&n), Ok(()));
}

#[test]
fn statistics_must_be_aligned_past_the_queue_and_inside_the_region() {
    let region = 4096u64;
    let used = rq_region_bytes(4);
    assert_eq!(admit_notif_stats(used, 4, region), Ok(used));
    assert_eq!(admit_notif_stats(used + 4, 4, region), Err(Errno::Einval));
    assert_eq!(admit_notif_stats(used - 8, 4, region), Err(Errno::Erange));
    assert_eq!(admit_notif_stats(region - 8, 4, region), Err(Errno::Erange));
    assert_eq!(admit_notif_stats(u64::MAX - 7, 4, region), Err(Errno::Erange));
}

// ---- area --------------------------------------------------------------

#[test]
fn a_page_aligned_plain_area_is_admitted() {
    assert_eq!(admit_area_reg(&area(), PAGE), Ok(()));
}

#[test]
fn an_area_flag_token_or_reserved_word_is_refused_before_the_range() {
    let mut a = area(); a.flags = 1 << 4; a.len = 0;
    assert_eq!(admit_area_reg(&a, PAGE), Err(Errno::Einval));
    let mut a = area(); a.rq_area_token = 1;
    assert_eq!(admit_area_reg(&a, PAGE), Err(Errno::Einval));
    let mut a = area(); a.resv2[1] = 1;
    assert_eq!(admit_area_reg(&a, PAGE), Err(Errno::Einval));
}

#[test]
fn an_empty_area_faults_and_an_oversized_one_is_invalid() {
    let mut a = area(); a.len = 0;
    assert_eq!(admit_area_reg(&a, PAGE), Err(Errno::Efault));
    let mut a = area(); a.len = (1u64 << 40) + PAGE;
    assert_eq!(admit_area_reg(&a, PAGE), Err(Errno::Einval));
}

#[test]
fn an_area_whose_end_wraps_overflows() {
    let mut a = area();
    a.addr = u64::MAX & !(PAGE - 1);
    a.len = 8 * PAGE;
    assert_eq!(admit_area_reg(&a, PAGE), Err(Errno::Eoverflow));
}

#[test]
fn an_unaligned_area_is_refused() {
    let mut a = area(); a.addr += 1;
    assert_eq!(admit_area_reg(&a, PAGE), Err(Errno::Einval));
    let mut a = area(); a.len += 1;
    assert_eq!(admit_area_reg(&a, PAGE), Err(Errno::Einval));
}

/// A shared-buffer area is refused BEFORE the descriptor or the address is
/// looked at: those rungs describe a plain memory area, and this description
/// is not one. See `tests_copy.rs` for why the answer is `EINVAL`.
#[test]
fn a_buffer_sharing_area_is_refused_ahead_of_the_plain_area_rungs() {
    let mut a = area(); a.flags = IORING_ZCRX_AREA_DMABUF; a.dmabuf_fd = 5;
    assert_eq!(admit_area_reg(&a, PAGE), Err(Errno::Einval));
    // Address zero would fault a plain area; it does not change this answer.
    a.addr = 0;
    assert_eq!(admit_area_reg(&a, PAGE), Err(Errno::Einval));
}

/// A descriptor named on a PLAIN area is a caller mistake, not an unsupported
/// feature: it says the area is memory but hands a shared-buffer handle.
#[test]
fn a_buffer_descriptor_on_a_plain_area_is_invalid_and_a_null_area_faults() {
    let mut a = area(); a.dmabuf_fd = 5;
    assert_eq!(admit_area_reg(&a, PAGE), Err(Errno::Einval));
    let mut a = area(); a.addr = 0;
    assert_eq!(admit_area_reg(&a, PAGE), Err(Errno::Efault));
}

// ---- buffer length -----------------------------------------------------

#[test]
fn an_unstated_buffer_length_is_one_page() {
    assert_eq!(admit_buf_len(0, 8 * PAGE, true, PAGE), Ok(12));
    assert_eq!(admit_buf_len(0, 8 * PAGE, false, PAGE), Ok(12));
}

#[test]
fn a_buffer_length_must_be_a_power_of_two_no_smaller_than_a_page() {
    assert_eq!(admit_buf_len(3000, 8 * PAGE, true, PAGE), Err(Errno::Einval));
    assert_eq!(admit_buf_len(2048, 8 * PAGE, true, PAGE), Err(Errno::Einval));
    assert_eq!(admit_buf_len(8192, 8 * PAGE, true, PAGE), Ok(13));
}

/// Without a device there is nothing to tell about a buffer size, so asking
/// for one is unsupported rather than invalid.
#[test]
fn a_non_page_buffer_length_needs_a_device() {
    assert_eq!(admit_buf_len(8192, 8 * PAGE, false, PAGE), Err(Errno::Eopnotsupp));
}

#[test]
fn a_buffer_larger_than_the_area_is_out_of_range() {
    assert_eq!(admit_buf_len(16384, 2 * PAGE, true, PAGE), Err(Errno::Erange));
}

// ---- control -----------------------------------------------------------

#[test]
fn control_takes_no_argument_count_and_no_reserved_words() {
    let c = Ctrl::default();
    assert_eq!(admit_ctrl(&c, 0), Ok(()));
    assert_eq!(admit_ctrl(&c, 1), Err(Errno::Einval));
    let mut c = Ctrl::default(); c.resv[1] = 1;
    assert_eq!(admit_ctrl(&c, 0), Err(Errno::Efault));
}

#[test]
fn every_control_operation_checks_its_own_body() {
    let mut c = Ctrl::default();
    c.op = ZCRX_CTRL_FLUSH_RQ;
    assert_eq!(admit_ctrl_op(&c), Ok(ZCRX_CTRL_FLUSH_RQ));
    c.body[8] = 1;
    assert_eq!(admit_ctrl_op(&c), Err(Errno::Einval));

    let mut c = Ctrl::default();
    c.op = ZCRX_CTRL_ARM_NOTIFICATION;
    c.body[0] = ZCRX_NOTIF_COPY as u8;
    assert_eq!(admit_ctrl_op(&c), Ok(ZCRX_CTRL_ARM_NOTIFICATION));
    c.body[0] = ZCRX_NOTIF_TYPE_LAST as u8;
    assert_eq!(admit_ctrl_op(&c), Err(Errno::Einval));
    let mut c = Ctrl::default();
    c.op = ZCRX_CTRL_ARM_NOTIFICATION;
    c.body[47] = 1;
    assert_eq!(admit_ctrl_op(&c), Err(Errno::Einval));

    let mut c = Ctrl::default();
    c.op = ZCRX_CTRL_LAST;
    assert_eq!(admit_ctrl_op(&c), Err(Errno::Eopnotsupp));
}

/// The descriptor an export produces lands in the body's first word, so the
/// caller states nothing there; a body it filled in is a caller writing over
/// the answer.
#[test]
fn an_export_states_nothing_and_reports_its_descriptor_in_the_body() {
    let mut c = Ctrl::default();
    c.op = ZCRX_CTRL_EXPORT;
    assert_eq!(admit_ctrl_op(&c), Ok(ZCRX_CTRL_EXPORT));
    c.body[0] = 7;
    assert_eq!(admit_ctrl_op(&c), Err(Errno::Einval));
    let mut c = Ctrl::default();
    c.op = ZCRX_CTRL_EXPORT;
    c.body[47] = 1;
    assert_eq!(admit_ctrl_op(&c), Err(Errno::Einval));

    let mut c = Ctrl::default();
    c.op = ZCRX_CTRL_EXPORT;
    c.zcrx_id = 3;
    c.set_export_fd(9);
    // The whole record travels back, not just the descriptor: a caller reads
    // its own id out of the copy it gets.
    let back = Ctrl::from_bytes(&c.to_bytes());
    assert_eq!(back, c);
    assert_eq!(back.body[0], 9);
    assert_eq!(back.zcrx_id, 3);
    assert_eq!(back.op, ZCRX_CTRL_EXPORT);
}

// ---- adopting another ring's instance -----------------------------------

/// An adoption states only where to find the instance. Everything else was
/// settled by the ring that registered it.
#[test]
fn an_adoption_states_only_the_descriptor() {
    let mut r = IfqReg::default();
    r.flags = ZCRX_REG_IMPORT;
    r.if_idx = 5;
    assert_eq!(admit_ifq_import(&r), Ok(()));
    for spoil in [1usize, 2, 3, 4, 5] {
        let mut r = IfqReg::default();
        r.flags = ZCRX_REG_IMPORT;
        r.if_idx = 5;
        match spoil {
            1 => r.if_rxq = 1,
            2 => r.rq_entries = 1,
            3 => r.area_ptr = 0x1000,
            4 => r.region_ptr = 0x2000,
            _ => r.notif_desc = 0x3000,
        }
        assert_eq!(admit_ifq_import(&r), Err(Errno::Einval));
    }
}

/// The import flag is answered before any of the device-mode geometry, so an
/// adoption never has to state a receive queue it does not have.
#[test]
fn an_adoption_is_recognised_before_the_device_mode_ladder() {
    let mut r = IfqReg::default();
    r.flags = ZCRX_REG_IMPORT;
    // Every device-mode rung below would refuse this: no queue, no entries.
    assert_eq!(admit_ifq_reg(&mut r, OK_RING), Ok(RegKind::Import));
    // …and an unknown flag alongside it is still refused first.
    let mut r = IfqReg::default();
    r.flags = ZCRX_REG_IMPORT | 0x8000_0000;
    assert_eq!(admit_ifq_reg(&mut r, OK_RING), Err(Errno::Einval));
}

// ---- receive preparation ----------------------------------------------

#[test]
fn a_multishot_receive_naming_a_registered_queue_is_admitted() {
    assert_eq!(admit_recvzc_prep(0, 0, 0, true, 0, 2), Ok(()));
    assert_eq!(admit_recvzc_prep(0, 0, 0, true, 0, 3), Ok(()));
}

#[test]
fn a_receive_carrying_an_address_is_refused() {
    assert_eq!(admit_recvzc_prep(1, 0, 0, true, 0, 2), Err(Errno::Einval));
    assert_eq!(admit_recvzc_prep(0, 1, 0, true, 0, 2), Err(Errno::Einval));
    assert_eq!(admit_recvzc_prep(0, 0, 1, true, 0, 2), Err(Errno::Einval));
}

#[test]
fn a_receive_naming_no_registered_queue_is_refused() {
    assert_eq!(admit_recvzc_prep(0, 0, 0, false, 0, 2), Err(Errno::Einval));
}

#[test]
fn a_receive_carrying_message_flags_or_unknown_operation_flags_is_refused() {
    assert_eq!(admit_recvzc_prep(0, 0, 0, true, 1, 2), Err(Errno::Einval));
    assert_eq!(admit_recvzc_prep(0, 0, 0, true, 0, 2 | (1 << 4)), Err(Errno::Einval));
}

/// Single-shot is refused because every byte is reported by an auxiliary
/// completion; a single-shot form would have nothing to report.
#[test]
fn a_receive_that_is_not_multishot_is_refused() {
    assert_eq!(admit_recvzc_prep(0, 0, 0, true, 0, 0), Err(Errno::Einval));
    assert_eq!(admit_recvzc_prep(0, 0, 0, true, 0, 1), Err(Errno::Einval));
}

// ---- refill-queue entries ---------------------------------------------

#[test]
fn a_refill_entry_names_the_area_slot_its_offset_encodes() {
    // Page-sized buffers: slot 3 is at byte offset 3 * 4096.
    let q = Rqe { off: 3 * PAGE, len: 0, pad: 0 };
    assert_eq!(parse_rqe(&q, 12, 8), Some(3));
}

/// A malformed entry is skipped, not reported: userspace writes the ring
/// without the kernel watching, so one bad word must not fail a whole batch.
#[test]
fn a_malformed_refill_entry_is_skipped() {
    let q = Rqe { off: 0, len: 0, pad: 1 };
    assert_eq!(parse_rqe(&q, 12, 8), None);
    // An area other than the one area an instance has.
    let q = Rqe { off: 1u64 << IORING_ZCRX_AREA_SHIFT, len: 0, pad: 0 };
    assert_eq!(parse_rqe(&q, 12, 8), None);
    // A slot past the area's end.
    let q = Rqe { off: 8 * PAGE, len: 0, pad: 0 };
    assert_eq!(parse_rqe(&q, 12, 8), None);
    let q = Rqe { off: 7 * PAGE, len: 0, pad: 0 };
    assert_eq!(parse_rqe(&q, 12, 8), Some(7));
}

/// A tail userspace ran far past the ring must not make the kernel walk
/// further than the ring holds.
#[test]
fn available_entries_are_bounded_by_the_ring_depth() {
    assert_eq!(rq_available(5, 0, 8), 5);
    assert_eq!(rq_available(0, 0, 8), 0);
    assert_eq!(rq_available(100, 0, 8), 8);
    // And a wrapped tail is still a count, not a negative.
    assert_eq!(rq_available(2, u32::MAX, 8), 3);
}

/// The completion's second half carries the area id in the high bits and the
/// byte offset in the low ones — the same encoding a refill entry is read
/// with, so a buffer handed out can be handed back verbatim.
#[test]
fn a_receive_completion_encodes_the_area_and_offset_a_refill_entry_reads_back() {
    let big = zcrx_cqe(0, 3 * PAGE);
    let q = Rqe { off: big[0], len: 0, pad: 0 };
    assert_eq!(parse_rqe(&q, 12, 8), Some(3));
    assert_eq!(big[1], 0);
}
