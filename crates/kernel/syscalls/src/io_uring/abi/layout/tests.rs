use super::*;

/// A default-shaped setup request: no flags, nothing reserved set.
fn req(flags: u32) -> Params {
    let mut p = Params::default();
    p.flags = flags;
    p
}

#[test]
fn zero_entries_is_einval() {
    // Linux io_uring_fill_params(): `if (!entries) return -EINVAL;`
    assert_eq!(prepare(&mut req(0), 0), Err(Errno::Einval));
}

#[test]
fn oversized_entries_need_clamp() {
    // Linux io_uring_fill_params(): past the max it is EINVAL unless CLAMP.
    assert_eq!(prepare(&mut req(0), MAX_ENTRIES + 1), Err(Errno::Einval));
    let mut p = req(IORING_SETUP_CLAMP);
    let g = prepare(&mut p, u32::MAX).expect("CLAMP clamps instead of failing");
    assert_eq!(g.sq_entries, MAX_ENTRIES);
    assert_eq!(p.sq_entries, MAX_ENTRIES);
}

#[test]
fn entries_round_up_to_a_power_of_two() {
    for (asked, got) in [(1u32, 1u32), (2, 2), (3, 4), (5, 8), (33, 64)] {
        let mut p = req(0);
        let g = prepare(&mut p, asked).unwrap();
        assert_eq!(g.sq_entries, got, "entries={asked}");
        // Linux overcommits the CQ ring 2:1 when CQSIZE is absent.
        assert_eq!(g.cq_entries, 2 * got);
    }
}

#[test]
fn cqsize_sizes_the_cq_ring_and_rejects_a_short_one() {
    let mut p = req(IORING_SETUP_CQSIZE);
    p.cq_entries = 0;
    assert_eq!(prepare(&mut p, 4), Err(Errno::Einval), "CQSIZE with 0 cq_entries");

    let mut p = req(IORING_SETUP_CQSIZE);
    p.cq_entries = 2;
    assert_eq!(prepare(&mut p, 8), Err(Errno::Einval), "cq_entries < sq_entries");

    let mut p = req(IORING_SETUP_CQSIZE);
    p.cq_entries = 9;
    let g = prepare(&mut p, 8).unwrap();
    assert_eq!((g.sq_entries, g.cq_entries), (8, 16), "cq rounds up to a power of two");

    let mut p = req(IORING_SETUP_CQSIZE);
    p.cq_entries = MAX_CQ_ENTRIES + 1;
    assert_eq!(prepare(&mut p, 8), Err(Errno::Einval), "oversized cq needs CLAMP");

    let mut p = req(IORING_SETUP_CQSIZE | IORING_SETUP_CLAMP);
    p.cq_entries = u32::MAX;
    assert_eq!(prepare(&mut p, 8).unwrap().cq_entries, MAX_CQ_ENTRIES);
}

#[test]
fn nonzero_resv_is_einval_before_any_other_check() {
    // Linux io_uring_setup(): the resv[] check runs before io_uring_create().
    let mut p = req(0);
    p.resv[1] = 1;
    assert_eq!(prepare(&mut p, 0), Err(Errno::Einval),
               "resv must be rejected even though entries==0 would also fail");
}

#[test]
fn unknown_setup_bits_are_einval() {
    // Linux io_uring_sanitise_params(): `flags & ~IORING_SETUP_FLAGS`.
    assert_eq!(prepare(&mut req(1 << 21), 4), Err(Errno::Einval));
    assert_eq!(prepare(&mut req(1 << 31), 4), Err(Errno::Einval));
}

// The per-flag verdicts this used to spot-check now live in
// `every_setup_flag_is_either_implemented_or_refused` and its two companions
// at the end of this file, which cover every bit rather than a chosen ten.

#[test]
fn linux_flag_combination_rules_hold() {
    // Each of these is EINVAL in io_uring_sanitise_params() for a reason that
    // has nothing to do with what oxide implements.
    assert_eq!(prepare(&mut req(IORING_SETUP_REGISTERED_FD_ONLY), 4), Err(Errno::Einval));
    // TASKRUN_FLAG needs one of the two task-run modes alongside it, and
    // DEFER_TASKRUN needs SINGLE_ISSUER — neither is refused for being
    // unimplemented, so the pairing rules are what these check.
    assert_eq!(prepare(&mut req(IORING_SETUP_TASKRUN_FLAG), 4), Err(Errno::Einval));
    assert!(prepare(&mut req(IORING_SETUP_TASKRUN_FLAG | IORING_SETUP_COOP_TASKRUN), 4).is_ok());
    assert_eq!(prepare(&mut req(IORING_SETUP_DEFER_TASKRUN), 4), Err(Errno::Einval));
    assert!(prepare(&mut req(IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_SINGLE_ISSUER), 4).is_ok());
    // HYBRID_IOPOLL is implemented, so what this pins is the PAIRING rule: it
    // is a way of driving a poll, and a ring that does not poll has none to
    // drive. Alone it is EINVAL; with IOPOLL it is admitted.
    assert_eq!(prepare(&mut req(IORING_SETUP_HYBRID_IOPOLL), 4), Err(Errno::Einval));
    assert!(prepare(&mut req(IORING_SETUP_HYBRID_IOPOLL | IORING_SETUP_IOPOLL), 4).is_ok());
    assert_eq!(prepare(&mut req(IORING_SETUP_SQ_REWIND), 4), Err(Errno::Einval));
}

#[test]
fn supported_flags_are_admitted() {
    for f in [0, IORING_SETUP_CLAMP, IORING_SETUP_NO_SQARRAY, IORING_SETUP_SUBMIT_ALL,
              IORING_SETUP_CLAMP | IORING_SETUP_NO_SQARRAY | IORING_SETUP_SUBMIT_ALL] {
        assert!(prepare(&mut req(f), 4).is_ok(), "flag {f:#x}");
    }
}

#[test]
fn reported_offsets_are_the_ones_io_uring_enter_uses() {
    let mut p = req(0);
    let g = prepare(&mut p, 8).unwrap();
    assert_eq!(p.sq_off.head, RING_SQ_HEAD);
    assert_eq!(p.sq_off.tail, RING_SQ_TAIL);
    assert_eq!(p.sq_off.ring_mask, RING_SQ_RING_MASK);
    assert_eq!(p.sq_off.ring_entries, RING_SQ_RING_ENTRIES);
    assert_eq!(p.sq_off.flags, RING_SQ_FLAGS);
    assert_eq!(p.sq_off.dropped, RING_SQ_DROPPED);
    assert_eq!(p.sq_off.array, g.sq_array_off);
    assert_eq!(p.cq_off.head, RING_CQ_HEAD);
    assert_eq!(p.cq_off.tail, RING_CQ_TAIL);
    assert_eq!(p.cq_off.ring_mask, RING_CQ_RING_MASK);
    assert_eq!(p.cq_off.ring_entries, RING_CQ_RING_ENTRIES);
    assert_eq!(p.cq_off.overflow, RING_CQ_OVERFLOW);
    assert_eq!(p.cq_off.cqes, RING_CQES);
    assert_eq!(p.cq_off.flags, RING_CQ_FLAGS);
    assert_eq!((p.sq_off.resv1, p.sq_off.user_addr), (0, 0));
    assert_eq!((p.cq_off.resv1, p.cq_off.user_addr), (0, 0));
}

/// The old single-page layout put the SQ index array at 0x10 and the CQ header
/// at 0x100, so a 64-entry ring's SQ array (0x10..0x110) overlapped the CQ
/// header. Nothing may overlap, and the SQ index array starts on its own
/// cacheline.
#[test]
fn no_region_overlaps_at_any_geometry() {
    for e in [1u32, 2, 4, 8, 16, 32, 64, 1024, MAX_ENTRIES] {
        for flags in [0, IORING_SETUP_NO_SQARRAY] {
            let mut p = req(flags);
            let g = prepare(&mut p, e).unwrap();
            let cqes_end = RING_CQES + g.cq_entries * CQE_SIZE as u32;
            let aligned = (cqes_end + SMP_CACHE_BYTES - 1) & !(SMP_CACHE_BYTES - 1);
            if g.sq_array_off == NO_SQ_ARRAY {
                assert_eq!(g.rings_bytes, aligned);
            } else {
                assert_eq!(g.sq_array_off, aligned, "SQ array starts on its own cacheline");
                assert!(g.sq_array_off >= cqes_end, "sq array overlaps the CQE array");
                assert_eq!(g.rings_bytes, g.sq_array_off + g.sq_entries * 4);
            }
            assert!(cqes_end > RING_CQ_OVERFLOW, "CQE array must clear the header");
            assert_eq!(RING_CQES, 0x40, "header is 64 bytes");
            assert_eq!(g.sqes_bytes, g.sq_entries * SQE_SIZE as u32);
        }
    }
}

/// The entries ceiling is the reference's, and it is no longer a function of
/// one page: the deepest ring's SQE region is 2 MiB.
#[test]
fn the_entries_ceiling_is_the_reference_bound() {
    assert_eq!(MAX_ENTRIES, 32768);
    assert_eq!(MAX_CQ_ENTRIES, 2 * MAX_ENTRIES);
    let mut p = req(0);
    let g = prepare(&mut p, MAX_ENTRIES).unwrap();
    assert_eq!(g.sq_entries, MAX_ENTRIES);
    assert_eq!(g.cq_entries, MAX_CQ_ENTRIES);
    assert_eq!(g.sqes_bytes, MAX_ENTRIES * SQE_SIZE as u32);
    assert!(g.sqes_bytes > 4096 * 100, "a deep ring is many pages, not one");
}

/// A region is `bytes` rounded to whole pages, held in a contiguous run of
/// `2^order` pages. Only the page-aligned bytes are exposed to `mmap(2)`.
#[test]
fn region_plan_rounds_bytes_to_pages_and_pages_to_a_run() {
    for (bytes, map_bytes, pages, order) in [
        (1u32,     4096u64, 1u64, 0u8),
        (4096,     4096,    1,    0),
        (4097,     8192,    2,    1),
        (3 * 4096, 12288,   3,    2),   // 3 pages need an order-2 run
        (4 * 4096, 16384,   4,    2),
        (0,        4096,    1,    0),   // never a zero-page region
    ] {
        let plan = region_plan(bytes, 4096).unwrap();
        assert_eq!((plan.map_bytes, plan.pages, plan.order), (map_bytes, pages, order),
                   "bytes={bytes}");
        assert!(plan.map_bytes <= (1u64 << plan.order) * 4096,
                "the run must cover every exposed byte");
        assert!(plan.map_bytes >= bytes as u64, "every requested byte must be mappable");
    }
}

/// Both arches' page size, and the refusal past the structural ceiling.
#[test]
fn region_plan_is_page_size_generic_and_bounded() {
    assert_eq!(region_plan(4096, 16384).unwrap().map_bytes, 16384);
    assert_eq!(region_plan(65537, 65536).unwrap().pages, 2);
    assert_eq!(region_plan(u32::MAX, 4096), Err(Errno::Eoverflow));
    assert_eq!(region_plan(8192, 3000), Err(Errno::Einval));
}

/// Every admitted geometry must fit a region this kernel can actually
/// allocate — the entries ladder, not a page, is what bounds it.
#[test]
fn every_admitted_geometry_has_a_region_plan() {
    for e in [1u32, 8, 1024, MAX_ENTRIES] {
        for flags in [0, IORING_SETUP_NO_SQARRAY, IORING_SETUP_CLAMP] {
            let mut p = req(flags);
            let g = prepare(&mut p, e).unwrap();
            for page in [4096u64, 16384] {
                let rings = region_plan(g.rings_bytes, page).expect("rings region must be allocatable");
                let sqes = region_plan(g.sqes_bytes, page).expect("SQE region must be allocatable");
                assert!(rings.map_bytes >= g.rings_bytes as u64);
                assert!(sqes.map_bytes >= g.sqes_bytes as u64);
                assert!(rings.pages <= MAX_REGION_PAGES && sqes.pages <= MAX_REGION_PAGES);
            }
        }
    }
}

#[test]
fn no_sqarray_reports_no_index_array() {
    let mut p = req(IORING_SETUP_NO_SQARRAY);
    let g = prepare(&mut p, 8).unwrap();
    assert_eq!(g.sq_array_off, NO_SQ_ARRAY);
    assert_eq!(p.sq_off.array, 0);
}

#[test]
fn mmap_offsets_select_the_right_region() {
    assert_eq!(mmap_region(IORING_OFF_SQ_RING), MmapRegion::Rings);
    // SINGLE_MMAP: the CQ offset maps the same region as the SQ offset.
    assert_eq!(mmap_region(IORING_OFF_CQ_RING), MmapRegion::Rings);
    assert_eq!(mmap_region(IORING_OFF_SQES), MmapRegion::Sqes);
    // Low bits are part of the region, not the selector.
    assert_eq!(mmap_region(IORING_OFF_SQES + 0x40), MmapRegion::Sqes);
    assert_eq!(mmap_region(IORING_OFF_PBUF_RING), MmapRegion::Invalid);
    assert_eq!(mmap_region(0x1800_0000), MmapRegion::Invalid);
}

#[test]
fn features_claim_only_what_the_ring_actually_does() {
    // Reporting 0 (the old behaviour) makes a caller mmap IORING_OFF_CQ_RING
    // separately and treat the returned CQ offsets as relative to THAT
    // mapping — they are relative to the rings mapping.
    assert_ne!(REPORTED_FEATURES & IORING_FEAT_SINGLE_MMAP, 0);
    // Each of these names behaviour the ring really has: an overflow backlog,
    // the current-position offset escape, the extended wait argument, tagged
    // resources, silent success, and link-order file resolution.
    for f in [IORING_FEAT_NODROP, IORING_FEAT_SUBMIT_STABLE, IORING_FEAT_RW_CUR_POS,
              IORING_FEAT_CUR_PERSONALITY, IORING_FEAT_EXT_ARG, IORING_FEAT_RSRC_TAGS,
              IORING_FEAT_CQE_SKIP, IORING_FEAT_LINKED_FILE,
              IORING_FEAT_FAST_POLL, IORING_FEAT_NATIVE_WORKERS, IORING_FEAT_POLL_32BITS] {
        assert_ne!(REPORTED_FEATURES & f, 0, "feature {f:#x}");
    }
    // A submission-poll thread now exists and borrows the creating task's
    // descriptor table, so an entry naming an ordinary descriptor works;
    // `io_uring_register` accepts a registered-ring index.
    for f in [IORING_FEAT_SQPOLL_NONFIXED, IORING_FEAT_REG_REG_RING] {
        assert_ne!(REPORTED_FEATURES & f, 0, "feature {f:#x}");
    }
    // No feature bit outside the UAPI's own set.
    assert_eq!(REPORTED_FEATURES & !((1u32 << 14) - 1), 0);
}

/// Every `IORING_SETUP_*` bit, in exactly one of two states: implemented, or
/// refused with `EINVAL`. There is no third column — a bit accepted without
/// its behaviour is a hang the caller cannot diagnose, since the flag it asked
/// for came back set in `p->flags`.
///
/// The list is exhaustive by construction: the loop walks bits 0..=20 and the
/// assertion below proves the mask has no bit outside that range, so a flag
/// added to the UAPI without a verdict here fails this test rather than
/// silently inheriting one.
#[test]
fn every_setup_flag_is_either_implemented_or_refused() {
    // (bit, implemented?, why)
    const TABLE: &[(u32, bool, &str)] = &[
        (IORING_SETUP_IOPOLL,             true,  "abi::iopoll + BlockDevice::poll_completions"),
        (IORING_SETUP_SQPOLL,             true,  "io_uring/sqpoll.rs poll thread"),
        (IORING_SETUP_SQ_AFF,             true,  "poll thread pinned to p->sq_thread_cpu"),
        (IORING_SETUP_CQSIZE,             true,  "fill_entries"),
        (IORING_SETUP_CLAMP,              true,  "fill_entries"),
        (IORING_SETUP_ATTACH_WQ,          false, "no second ring's work queue to join"),
        (IORING_SETUP_R_DISABLED,         true,  "ctx::state::DISABLED"),
        (IORING_SETUP_SUBMIT_ALL,         true,  "submit::submit_sqes"),
        (IORING_SETUP_COOP_TASKRUN,       true,  "no task work is ever queued at the submitter"),
        (IORING_SETUP_TASKRUN_FLAG,       true,  "IORING_SQ_TASKRUN correctly never raised"),
        (IORING_SETUP_SQE128,             true,  "sqe_size sizes and strides the SQE array at 128 bytes"),
        (IORING_SETUP_CQE32,              true,  "cqe_size sizes and indexes the CQE array at 32 bytes"),
        (IORING_SETUP_SINGLE_ISSUER,      true,  "abi::issuer records the submitter at setup"),
        (IORING_SETUP_DEFER_TASKRUN,      true,  "vacuous, and the RESIZE_RINGS gate"),
        (IORING_SETUP_NO_MMAP,            false, "no path adopts caller pages as the ring"),
        (IORING_SETUP_REGISTERED_FD_ONLY, false, "only reachable with NO_MMAP"),
        (IORING_SETUP_NO_SQARRAY,         true,  "rings_size + IoUring::sq_index"),
        (IORING_SETUP_HYBRID_IOPOLL,      true,  "abi::iopoll::hybrid_sleep_ns + the ring's service-time estimate"),
        (IORING_SETUP_CQE_MIXED,          true,  "abi::cqe_slot: a 32-byte completion takes two 16-byte slots"),
        (IORING_SETUP_SQE_MIXED,          true,  "abi::sqe_slot: a 128-byte entry takes two 64-byte slots"),
        (IORING_SETUP_SQ_REWIND,          false, "userspace could rewind over entries already read"),
    ];

    assert_eq!(IORING_SETUP_FLAGS, (1u32 << TABLE.len()) - 1,
               "a setup flag was added to the UAPI without a verdict in this table");
    let mut seen = 0u32;
    for (bit, implemented, why) in TABLE {
        assert_eq!(seen & bit, 0, "duplicate row for {bit:#x}");
        seen |= bit;
        assert_eq!(SUPPORTED_SETUP_FLAGS & bit != 0, *implemented,
                   "flag {bit:#x} verdict disagrees with SUPPORTED_SETUP_FLAGS ({why})");
    }
    assert_eq!(seen, IORING_SETUP_FLAGS, "the table must name every bit exactly once");
}

/// The refused half of the table, exercised through the real admission ladder
/// rather than against the mask — a bit could be absent from
/// `SUPPORTED_SETUP_FLAGS` and still be admitted by an earlier rule.
#[test]
fn every_unimplemented_setup_flag_is_refused_by_setup_itself() {
    for bit in [IORING_SETUP_ATTACH_WQ,
                IORING_SETUP_NO_MMAP, IORING_SETUP_REGISTERED_FD_ONLY,
                IORING_SETUP_SQ_REWIND] {
        assert_eq!(prepare(&mut req(bit), 8), Err(Errno::Einval), "flag {bit:#x} must be refused");
    }
    // And a bit outside the UAPI's own set, which no kernel accepts.
    assert_eq!(prepare(&mut req(1 << 21), 8), Err(Errno::Einval));
}

/// The implemented half: setup admits it and reports it back, so a caller can
/// tell "the ring has this" from "the kernel dropped it on the floor".
#[test]
fn every_implemented_setup_flag_is_admitted_and_reported_back() {
    // Combination rules force some flags to travel with a companion.
    for extra in [0, IORING_SETUP_SQPOLL, IORING_SETUP_SQ_AFF | IORING_SETUP_SQPOLL,
                  IORING_SETUP_CQSIZE, IORING_SETUP_CLAMP, IORING_SETUP_R_DISABLED,
                  IORING_SETUP_SUBMIT_ALL, IORING_SETUP_COOP_TASKRUN,
                  IORING_SETUP_TASKRUN_FLAG | IORING_SETUP_COOP_TASKRUN,
                  IORING_SETUP_SINGLE_ISSUER,
                  IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_SINGLE_ISSUER,
                  IORING_SETUP_NO_SQARRAY, IORING_SETUP_IOPOLL,
                  IORING_SETUP_SQE128, IORING_SETUP_CQE32,
                  IORING_SETUP_CQE_MIXED, IORING_SETUP_SQE_MIXED,
                  IORING_SETUP_SQE128 | IORING_SETUP_CQE32,
                  IORING_SETUP_SQE_MIXED | IORING_SETUP_CQE_MIXED,
                  IORING_SETUP_HYBRID_IOPOLL | IORING_SETUP_IOPOLL] {
        let mut p = req(extra);
        if extra & IORING_SETUP_CQSIZE != 0 { p.cq_entries = 8; }
        let g = prepare(&mut p, 8).unwrap_or_else(|e| panic!("flags {extra:#x} refused: {e:?}"));
        assert_eq!(g.flags & extra, extra, "flags {extra:#x} must survive admission");
        assert_eq!(p.flags & extra, extra, "and be reported back to the caller");
    }
}

/// SQPOLL's combination rules, which the reference checks before any of the
/// per-flag work.
#[test]
fn sqpoll_refuses_the_flags_that_contradict_it() {
    for bad in [IORING_SETUP_COOP_TASKRUN, IORING_SETUP_TASKRUN_FLAG,
                IORING_SETUP_DEFER_TASKRUN] {
        assert_eq!(prepare(&mut req(IORING_SETUP_SQPOLL | bad), 8), Err(Errno::Einval),
                   "a signalling flag {bad:#x} means nothing to a ring nobody signals");
    }
    // SQ_REWIND is refused outright, but the reference refuses it with SQPOLL
    // for its own reason too, so neither ordering can admit the pair.
    assert_eq!(prepare(&mut req(IORING_SETUP_SQPOLL | IORING_SETUP_SQ_REWIND
                                | IORING_SETUP_NO_SQARRAY), 8), Err(Errno::Einval));
}

/// A 32-byte ring sizes and strides its CQE array at 32 bytes, and a plain
/// ring is untouched. The rings region has to GROW by exactly the extra 16
/// bytes per entry: a stride that outran the sizing would have the last CQEs
/// land past the region.
#[test]
fn cqe32_doubles_the_completion_stride_and_the_array_it_sizes() {
    let plain = prepare(&mut req(0), 8).unwrap();
    let big = prepare(&mut req(IORING_SETUP_CQE32), 8).unwrap();
    assert_eq!(plain.cqe_size, 16);
    assert_eq!(big.cqe_size, 32);
    assert_eq!(plain.cq_entries, big.cq_entries);
    assert_eq!(big.rings_bytes - plain.rings_bytes, 16 * big.cq_entries);
}

/// `CQE32` and `CQE_MIXED` together are refused, and so are `SQE128` and
/// `SQE_MIXED`: a ring that fixes every entry at the wide size cannot also
/// carry narrow ones, so asking for both states two contradictory shapes.
#[test]
fn a_fixed_wide_ring_and_a_mixed_one_are_contradictory() {
    assert_eq!(prepare(&mut req(IORING_SETUP_CQE32 | IORING_SETUP_CQE_MIXED), 8), Err(Errno::Einval));
    assert_eq!(prepare(&mut req(IORING_SETUP_SQE128 | IORING_SETUP_SQE_MIXED), 8), Err(Errno::Einval));
}

/// A 128-byte ring sizes and strides its SQE array at 128 bytes; the rings
/// region is untouched, because the SQEs live in a region of their own.
#[test]
fn sqe128_doubles_the_submission_stride_and_the_array_it_sizes() {
    let plain = prepare(&mut req(0), 8).unwrap();
    let big = prepare(&mut req(IORING_SETUP_SQE128), 8).unwrap();
    assert_eq!(plain.sqe_size, 64);
    assert_eq!(big.sqe_size, 128);
    assert_eq!(plain.sq_entries, big.sq_entries);
    assert_eq!(big.sqes_bytes, 2 * plain.sqes_bytes);
    assert_eq!(big.rings_bytes, plain.rings_bytes);
}

/// A mixed ring keeps the narrow stride on BOTH sides: mixed means a wide
/// entry spans two slots, not that the array grows. A region sized for a
/// doubled stride would waste half of itself; one strided at 32 while sized at
/// 16 would run its last entries past the region.
#[test]
fn a_mixed_ring_keeps_the_narrow_stride_and_the_narrow_size() {
    let plain = prepare(&mut req(0), 8).unwrap();
    let mixed = prepare(&mut req(IORING_SETUP_SQE_MIXED | IORING_SETUP_CQE_MIXED), 8).unwrap();
    assert_eq!((mixed.sqe_size, mixed.cqe_size), (64, 16));
    assert_eq!(mixed.sqes_bytes, plain.sqes_bytes);
    assert_eq!(mixed.rings_bytes, plain.rings_bytes);
}

/// A mixed ring must be able to hold ONE of the wide entries it exists to
/// carry. A single-slot ring never could, so it is refused at sizing rather
/// than admitted as a ring on which every wide entry fails.
#[test]
fn a_mixed_ring_shallower_than_one_wide_entry_is_refused() {
    assert_eq!(prepare(&mut req(IORING_SETUP_SQE_MIXED), 1), Err(Errno::Eoverflow));
    // Two entries is the shallowest that works.
    assert!(prepare(&mut req(IORING_SETUP_SQE_MIXED), 2).is_ok());
    // The CQ ring is overcommitted 2:1, so it reaches two first; state the
    // rule against a caller-sized CQ ring, where one entry is reachable.
    let mut p = req(IORING_SETUP_CQE_MIXED | IORING_SETUP_CQSIZE);
    p.cq_entries = 1;
    assert_eq!(prepare(&mut p, 1), Err(Errno::Eoverflow));
    let mut p = req(IORING_SETUP_CQE_MIXED | IORING_SETUP_CQSIZE);
    p.cq_entries = 2;
    assert!(prepare(&mut p, 1).is_ok());
}

/// The deepest ring of every shape still fits a region, so no admitted
/// geometry can be built and then fail to allocate for a reason the ladder
/// should have caught.
#[test]
fn the_deepest_wide_ring_still_fits_a_region() {
    let g = prepare(&mut req(IORING_SETUP_SQE128 | IORING_SETUP_CLAMP), u32::MAX).unwrap();
    assert_eq!(g.sq_entries, MAX_ENTRIES);
    region_plan(g.sqes_bytes, 4096).expect("the deepest 128-byte SQE array fits a region");
    region_plan(g.rings_bytes, 4096).expect("and so does its rings region");
}
