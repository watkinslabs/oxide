// `io_uring_setup(2)` admission ladder + oxide's SQ/CQ/SQE region geometry.
//
// The Linux stages every rule below mirrors:
//   sanitise params  — flag mask + rejected flag combinations
//   fill params      — the entries ladder
//   rings size       — region sizing
//   prepare config   — sq_off/cq_off writeback
//   allocate urings  — ring header seeding
//
// Two regions, exactly like Linux: a "rings" region (SQ/CQ headers, the CQE
// array, and the SQ index array) and a separate "SQEs" region. They are
// distinct mmap targets (`IORING_OFF_SQ_RING`/`IORING_OFF_CQ_RING` vs
// `IORING_OFF_SQES`), so they cannot share one page.

use syscall::errno::Errno;

use super::uapi::*;

/// `IORING_MAX_ENTRIES`: deepest SQ ring a caller may ask for. Past it the
/// ladder is `EINVAL`, or a clamp under `IORING_SETUP_CLAMP`.
pub const MAX_ENTRIES: u32 = 32768;
/// `IORING_MAX_CQ_ENTRIES` — twice the SQ ceiling.
pub const MAX_CQ_ENTRIES: u32 = 2 * MAX_ENTRIES;

/// Cacheline the CQE array's tail is padded to before the SQ index array, so
/// the two never share a line.
pub const SMP_CACHE_BYTES: u32 = 64;

/// Largest run one region may occupy, in pages. The entries ladder already
/// bounds every geometry well under this (the deepest ring needs 512 pages per
/// region); the constant is the structural ceiling the sizing refuses past.
pub const MAX_REGION_PAGES: u64 = 1024;

/// How a region's byte size becomes a physical allocation: `bytes` rounded up
/// to whole pages, held in one contiguous refcounted run of `2^order` pages.
///
/// The run is contiguous because the mapping is a `VmaBacking::KernelFrame`,
/// whose fault path resolves the page at VMA offset `O` to `base_pa + O` and
/// takes one reference per installed PTE. Only `map_bytes` is exposed to
/// `mmap(2)`; the pages the order-rounding adds past it are never mapped.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RegionPlan {
    /// Page-aligned bytes userspace may map — the region's real size.
    pub map_bytes: u64,
    /// Pages those bytes occupy.
    pub pages: u64,
    /// Buddy order of the run that holds them (`2^order >= pages`).
    pub order: u8,
}

/// Plan one region's allocation at page size `page`. # C: O(1)
pub fn region_plan(bytes: u32, page: u64) -> Result<RegionPlan, Errno> {
    if page == 0 || !page.is_power_of_two() { return Err(Errno::Einval); }
    let map_bytes = (bytes as u64).checked_add(page - 1).ok_or(Errno::Eoverflow)? & !(page - 1);
    let pages = core::cmp::max(map_bytes / page, 1);
    if pages > MAX_REGION_PAGES { return Err(Errno::Eoverflow); }
    let order = (pages.next_power_of_two().trailing_zeros()) as u8;
    Ok(RegionPlan { map_bytes: core::cmp::max(map_bytes, page), pages, order })
}

/// Rings-region field offsets. These are the values reported in
/// `p->sq_off`/`p->cq_off`, so userspace and `io_uring_enter` agree by
/// construction.
pub const RING_SQ_HEAD:         u32 = 0x00;
pub const RING_SQ_TAIL:         u32 = 0x04;
pub const RING_CQ_HEAD:         u32 = 0x08;
pub const RING_CQ_TAIL:         u32 = 0x0c;
pub const RING_SQ_RING_MASK:    u32 = 0x10;
pub const RING_CQ_RING_MASK:    u32 = 0x14;
pub const RING_SQ_RING_ENTRIES: u32 = 0x18;
pub const RING_CQ_RING_ENTRIES: u32 = 0x1c;
pub const RING_SQ_DROPPED:      u32 = 0x20;
pub const RING_SQ_FLAGS:        u32 = 0x24;
pub const RING_CQ_FLAGS:        u32 = 0x28;
pub const RING_CQ_OVERFLOW:     u32 = 0x2c;
/// First CQE. Header is padded to 64 bytes so the CQE array is cacheline-aligned.
pub const RING_CQES:            u32 = 0x40;

/// `p->sq_off.array == NO_SQ_ARRAY` marks a ring built with
/// `IORING_SETUP_NO_SQARRAY` (SQ head/tail index the SQE array directly).
pub const NO_SQ_ARRAY: u32 = u32::MAX;

/// Setup flags this kernel implements. Every other bit is refused with
/// `EINVAL` — the same answer a kernel that predates the flag gives, because
/// the bit is simply absent from its own mask.
///
/// No bit is ever accepted and ignored. A flag names behaviour a caller builds
/// on; accepting one without the behaviour turns a refusal the caller can
/// handle into a hang it cannot. Every bit is therefore in exactly one of two
/// states, with the reason recorded here and pinned by `layout/tests.rs`:
///
/// | flag | verdict | why |
/// |---|---|---|
/// | `IOPOLL` | implemented | [`super::iopoll`] + `block::BlockDevice::poll_completions`: the ring admits only the opcodes a poll can complete, a transfer must be direct and land on a pollable backend, and `IORING_ENTER_GETEVENTS` drives the backend's poll instead of sleeping. |
/// | `SQPOLL` | implemented | `io_uring/sqpoll.rs` + [`super::sqpoll`]. |
/// | `SQ_AFF` | implemented | the poll thread is pinned to `p->sq_thread_cpu`. |
/// | `CQSIZE` | implemented | `fill_entries`. |
/// | `CLAMP` | implemented | `fill_entries`. |
/// | `ATTACH_WQ` | refused | one poll thread and one worker pool per ring; there is no second ring's work queue to join. |
/// | `R_DISABLED` | implemented | `ctx::state::DISABLED`. |
/// | `SUBMIT_ALL` | implemented | `submit::submit_sqes`. |
/// | `COOP_TASKRUN` | implemented | vacuously: an entry finishes inside the submission that issued it or on a worker that posts its own completion, so no task work is ever queued back at the submitter and no signal is ever needed to run it. |
/// | `TASKRUN_FLAG` | implemented | same reason — `IORING_SQ_TASKRUN` is correctly never raised, because there is never task work pending. |
/// | `SQE128` | refused | the SQE array is sized and indexed at 64 bytes. |
/// | `CQE32` | implemented | `cqe_size` sizes and indexes the CQE array at 32 bytes; `Cqe::big` carries the second half. It is the flag zero-copy receive registration requires, because a receive completion reports a buffer offset alongside its length. |
/// | `SINGLE_ISSUER` | implemented | `ctx::claim_issuer` refuses a second submitter. |
/// | `DEFER_TASKRUN` | implemented | vacuously, per `COOP_TASKRUN`; also the gate `RESIZE_RINGS` requires. |
/// | `NO_MMAP` | refused | ring memory is kernel-allocated; there is no path that adopts a caller's pages as the ring. |
/// | `REGISTERED_FD_ONLY` | refused | it is only reachable with `NO_MMAP`, which is refused. |
/// | `NO_SQARRAY` | implemented | `rings_size` + `IoUring::sq_index`. |
/// | `HYBRID_IOPOLL` | implemented | [`super::iopoll::hybrid_sleep_ns`] + the ring's running service-time estimate: a polled transfer is stamped when it is issued, each poll pass folds the observed service time into the ring's minimum, and the next transfer sleeps for half of it before it starts spinning. |
/// | `CQE_MIXED` | refused | it varies CQE size per completion; the CQE array is fixed at 16 bytes. |
/// | `SQE_MIXED` | refused | it varies SQE size per entry; the SQE array is fixed at 64 bytes. |
/// | `SQ_REWIND` | refused | it lets userspace move the SQ tail backwards over entries the kernel may already have read. |
pub const SUPPORTED_SETUP_FLAGS: u32 =
    IORING_SETUP_CQSIZE | IORING_SETUP_CLAMP | IORING_SETUP_NO_SQARRAY
    | IORING_SETUP_SUBMIT_ALL | IORING_SETUP_R_DISABLED
    | IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_COOP_TASKRUN
    | IORING_SETUP_TASKRUN_FLAG | IORING_SETUP_DEFER_TASKRUN
    | IORING_SETUP_SQPOLL | IORING_SETUP_SQ_AFF | IORING_SETUP_IOPOLL
    | IORING_SETUP_HYBRID_IOPOLL
    | IORING_SETUP_CQE32;

/// `p->features` oxide reports. Claiming a bit we do not implement is a lie
/// liburing acts on, so the set is deliberately small:
///   SINGLE_MMAP    — the CQ ring lives inside the SQ-ring mapping (one
///                    rings region), so liburing must NOT mmap
///                    `IORING_OFF_CQ_RING` separately.
///   SUBMIT_STABLE  — every op runs inline in `io_uring_enter`, so the SQE is
///                    fully consumed before submit returns.
///   NODROP         — a completion is never dropped for want of ring space;
///                    the overflow backlog holds it until the caller reaps.
///   RW_CUR_POS     — `off == -1` means "use the description's position".
///   CUR_PERSONALITY— an entry runs under the submitter's credentials unless
///                    it names a registered personality.
///   EXT_ARG        — `io_uring_enter` accepts the extended wait argument.
///   RSRC_TAGS      — a released tagged resource posts its tag.
///   CQE_SKIP       — a successful entry can ask for no completion.
///   LINKED_FILE    — a linked entry resolves its file in submission order.
///   FAST_POLL      — an operation that would block is armed on its
///                    description's readiness rather than holding a worker.
///   NATIVE_WORKERS — deferred work runs on kernel threads that borrow the
///                    submitter's address space, descriptor table and
///                    credentials.
///   POLL_32BITS    — a poll entry's whole 32-bit event mask is honoured.
///   SQPOLL_NONFIXED— a submission-poll thread runs entries naming ordinary
///                    descriptors, not only registered ones: it borrows the
///                    creating task's descriptor table for its whole life.
///   REG_REG_RING   — `io_uring_register` accepts a registered-ring index in
///                    place of a descriptor
///                    (`IORING_REGISTER_USE_REGISTERED_RING`).
pub const REPORTED_FEATURES: u32 =
    IORING_FEAT_SINGLE_MMAP | IORING_FEAT_NODROP | IORING_FEAT_SUBMIT_STABLE
    | IORING_FEAT_RW_CUR_POS | IORING_FEAT_CUR_PERSONALITY | IORING_FEAT_EXT_ARG
    | IORING_FEAT_RSRC_TAGS | IORING_FEAT_CQE_SKIP | IORING_FEAT_LINKED_FILE
    | IORING_FEAT_FAST_POLL | IORING_FEAT_NATIVE_WORKERS | IORING_FEAT_POLL_32BITS
    | IORING_FEAT_SQPOLL_NONFIXED | IORING_FEAT_REG_REG_RING;

/// Region geometry derived from an admitted `struct io_uring_params`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Geometry {
    pub sq_entries: u32,
    pub cq_entries: u32,
    /// Byte offset of the SQ index array inside the rings region, or
    /// `NO_SQ_ARRAY`.
    pub sq_array_off: u32,
    /// Bytes actually used in the rings region.
    pub rings_bytes: u32,
    /// Bytes actually used in the SQEs region.
    pub sqes_bytes: u32,
    pub flags: u32,
    /// Bytes one CQE occupies: 32 for an `IORING_SETUP_CQE32` ring, 16
    /// otherwise. It is carried rather than re-derived so the ring, the
    /// completion writer and the region sizing cannot disagree about the
    /// stride.
    pub cqe_size: u32,
}

/// Bytes one CQE occupies on a ring built with `flags`. # C: O(1)
pub fn cqe_size(flags: u32) -> u32 {
    if flags & IORING_SETUP_CQE32 != 0 { CQE32_SIZE as u32 } else { CQE_SIZE as u32 }
}

/// Round up to a power of two, saturating (Linux `roundup_pow_of_two`).
/// # C: O(1)
fn roundup_pow2(v: u32) -> u32 {
    if v == 0 { return 1; }
    if v.is_power_of_two() { return v; }
    1u32 << (32 - v.leading_zeros())
}

/// Linux `io_uring_sanitise_params`: unknown bits, then the combination
/// rules, then the bits oxide does not implement. # C: O(1)
fn sanitise(flags: u32) -> Result<(), Errno> {
    if flags & !IORING_SETUP_FLAGS != 0 { return Err(Errno::Einval); }
    if flags & IORING_SETUP_SQ_REWIND != 0
        && (flags & IORING_SETUP_SQPOLL != 0 || flags & IORING_SETUP_NO_SQARRAY == 0) {
        return Err(Errno::Einval);
    }
    // "There is no way to mmap rings without a real fd".
    if flags & IORING_SETUP_REGISTERED_FD_ONLY != 0 && flags & IORING_SETUP_NO_MMAP == 0 {
        return Err(Errno::Einval);
    }
    if flags & IORING_SETUP_SQPOLL != 0
        && flags & (IORING_SETUP_COOP_TASKRUN | IORING_SETUP_TASKRUN_FLAG | IORING_SETUP_DEFER_TASKRUN) != 0 {
        return Err(Errno::Einval);
    }
    if flags & IORING_SETUP_TASKRUN_FLAG != 0
        && flags & (IORING_SETUP_COOP_TASKRUN | IORING_SETUP_DEFER_TASKRUN) == 0 {
        return Err(Errno::Einval);
    }
    if flags & IORING_SETUP_HYBRID_IOPOLL != 0 && flags & IORING_SETUP_IOPOLL == 0 {
        return Err(Errno::Einval);
    }
    if flags & IORING_SETUP_DEFER_TASKRUN != 0 && flags & IORING_SETUP_SINGLE_ISSUER == 0 {
        return Err(Errno::Einval);
    }
    if flags & (IORING_SETUP_CQE32 | IORING_SETUP_CQE_MIXED) == (IORING_SETUP_CQE32 | IORING_SETUP_CQE_MIXED) {
        return Err(Errno::Einval);
    }
    if flags & (IORING_SETUP_SQE128 | IORING_SETUP_SQE_MIXED) == (IORING_SETUP_SQE128 | IORING_SETUP_SQE_MIXED) {
        return Err(Errno::Einval);
    }
    if flags & !SUPPORTED_SETUP_FLAGS != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// Linux `io_uring_fill_params`: `p->sq_entries` carries the caller's
/// `entries` argument on the way in and the built SQ depth on the way out.
/// # C: O(1)
fn fill_entries(p: &mut Params) -> Result<(), Errno> {
    let mut entries = p.sq_entries;
    if entries == 0 { return Err(Errno::Einval); }
    if entries > MAX_ENTRIES {
        if p.flags & IORING_SETUP_CLAMP == 0 { return Err(Errno::Einval); }
        entries = MAX_ENTRIES;
    }
    p.sq_entries = roundup_pow2(entries);
    if p.flags & IORING_SETUP_CQSIZE != 0 {
        if p.cq_entries == 0 { return Err(Errno::Einval); }
        if p.cq_entries > MAX_CQ_ENTRIES {
            if p.flags & IORING_SETUP_CLAMP == 0 { return Err(Errno::Einval); }
            p.cq_entries = MAX_CQ_ENTRIES;
        }
        p.cq_entries = roundup_pow2(p.cq_entries);
        if p.cq_entries < p.sq_entries { return Err(Errno::Einval); }
    } else {
        // Linux overcommits the CQ ring 2:1 so a submitter can outrun the SQ.
        p.cq_entries = 2 * p.sq_entries;
    }
    Ok(())
}

/// Linux `rings_size`: place the CQE array and the SQ index array, and refuse
/// an arithmetic overflow (`-EOVERFLOW`). The region sizes it reports are
/// turned into allocations by `region_plan`; nothing here is capped at one
/// page. # C: O(1)
fn rings_size(flags: u32, sq_entries: u32, cq_entries: u32) -> Result<(u32, u32, u32), Errno> {
    let cqes_bytes = cq_entries.checked_mul(cqe_size(flags)).ok_or(Errno::Eoverflow)?;
    let mut off = RING_CQES.checked_add(cqes_bytes).ok_or(Errno::Eoverflow)?;
    // The SQ index array starts on its own cacheline.
    off = off.checked_add(SMP_CACHE_BYTES - 1).ok_or(Errno::Eoverflow)? & !(SMP_CACHE_BYTES - 1);
    let sq_array_off = if flags & IORING_SETUP_NO_SQARRAY == 0 {
        let at = off;
        off = off.checked_add(sq_entries.checked_mul(4).ok_or(Errno::Eoverflow)?).ok_or(Errno::Eoverflow)?;
        at
    } else {
        NO_SQ_ARRAY
    };
    let sqes_bytes = sq_entries.checked_mul(SQE_SIZE as u32).ok_or(Errno::Eoverflow)?;
    Ok((sq_array_off, off, sqes_bytes))
}

/// Full `io_uring_setup` admission: validate `p` (already read from user),
/// size the regions, and fill in every out-field except `features`, which the
/// caller sets once the regions exist (Linux `io_uring_create`). `entries` is
/// the syscall's first argument; Linux stores it into `p->sq_entries` before
/// `io_uring_create`. # C: O(1)
pub fn prepare(p: &mut Params, entries: u32) -> Result<Geometry, Errno> {
    // Linux `io_uring_setup()` checks `p->resv` before anything else. The
    // check belongs to the syscall, not to the shared config path, so
    // `IORING_REGISTER_RESIZE_RINGS` does not inherit it.
    if p.resv != [0; 3] { return Err(Errno::Einval); }
    p.sq_entries = entries;
    prepare_config(p)
}

/// Flags `IORING_REGISTER_RESIZE_RINGS` lets the caller restate. Every other
/// bit in the request is `EINVAL`.
pub const RESIZE_FLAGS: u32 = IORING_SETUP_CQSIZE | IORING_SETUP_CLAMP;
/// Flags a resize inherits from the ring it resizes: the ones that decide the
/// region LAYOUT, which a resize may not change under the ring's feet.
pub const COPY_FLAGS: u32 =
    IORING_SETUP_NO_SQARRAY | IORING_SETUP_SQE128 | IORING_SETUP_CQE32
    | IORING_SETUP_NO_MMAP | IORING_SETUP_CQE_MIXED | IORING_SETUP_SQE_MIXED;

/// Admission for `IORING_REGISTER_RESIZE_RINGS` (Linux
/// `io_register_resize_rings`' front half): only a ring built with
/// `IORING_SETUP_DEFER_TASKRUN` may be resized, the request may carry only
/// `RESIZE_FLAGS`, and the layout flags come from the ring rather than the
/// request. `p.sq_entries` carries the requested depth in and the built depth
/// out, exactly as at setup. # C: O(1)
pub fn prepare_resize(p: &mut Params, ring_flags: u32) -> Result<Geometry, Errno> {
    if ring_flags & IORING_SETUP_DEFER_TASKRUN == 0 { return Err(Errno::Einval); }
    if p.flags & !RESIZE_FLAGS != 0 { return Err(Errno::Einval); }
    p.flags |= ring_flags & COPY_FLAGS;
    prepare_config(p)
}

/// Linux `io_prepare_config`: sanitise, fill the entries ladder, size the
/// regions, publish the offsets. Shared by setup and resize. # C: O(1)
fn prepare_config(p: &mut Params) -> Result<Geometry, Errno> {
    sanitise(p.flags)?;
    fill_entries(p)?;
    let (sq_array_off, rings_bytes, sqes_bytes) = rings_size(p.flags, p.sq_entries, p.cq_entries)?;

    p.sq_off = SqringOffsets {
        head: RING_SQ_HEAD, tail: RING_SQ_TAIL,
        ring_mask: RING_SQ_RING_MASK, ring_entries: RING_SQ_RING_ENTRIES,
        flags: RING_SQ_FLAGS, dropped: RING_SQ_DROPPED,
        array: if sq_array_off == NO_SQ_ARRAY { 0 } else { sq_array_off },
        resv1: 0, user_addr: 0,
    };
    p.cq_off = CqringOffsets {
        head: RING_CQ_HEAD, tail: RING_CQ_TAIL,
        ring_mask: RING_CQ_RING_MASK, ring_entries: RING_CQ_RING_ENTRIES,
        overflow: RING_CQ_OVERFLOW, cqes: RING_CQES, flags: RING_CQ_FLAGS,
        resv1: 0, user_addr: 0,
    };
    Ok(Geometry {
        sq_entries: p.sq_entries, cq_entries: p.cq_entries,
        sq_array_off, rings_bytes, sqes_bytes, flags: p.flags,
        cqe_size: cqe_size(p.flags),
    })
}

/// Which region an `mmap(2)` offset on the ring fd selects (Linux
/// `io_uring_mmap` switches on `offset & IORING_OFF_MMAP_MASK`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MmapRegion {
    Rings,
    Sqes,
    Param,
    /// The refill queue of one zero-copy receive instance. The id is carried
    /// because the offset is the only thing that names it — a ring may have
    /// many instances, each with its own region.
    Zcrx(u32),
    Invalid,
}

/// Classify an mmap offset. `IORING_OFF_CQ_RING` selects the SAME region as
/// `IORING_OFF_SQ_RING` because oxide reports `IORING_FEAT_SINGLE_MMAP`.
/// `Param` selects a kernel-allocated `IORING_REGISTER_MEM_REGION` region; a
/// caller-provided one is never mappable here (`io_uring_abi::mem_region`).
/// `Zcrx` selects one zero-copy receive instance's refill queue, named by the
/// id the offset carries below the region selector.
/// # C: O(1)
pub fn mmap_region(offset: u64) -> MmapRegion {
    match offset & IORING_OFF_MMAP_MASK {
        IORING_OFF_SQ_RING => MmapRegion::Rings,
        IORING_OFF_CQ_RING => MmapRegion::Rings,
        IORING_OFF_SQES    => MmapRegion::Sqes,
        super::mem_region::IORING_MAP_OFF_PARAM_REGION => MmapRegion::Param,
        super::zcrx::IORING_MAP_OFF_ZCRX_REGION => MmapRegion::Zcrx(super::zcrx::zcrx_mmap_id(offset)),
        _                  => MmapRegion::Invalid,
    }
}

#[cfg(test)]
#[path = "layout/tests.rs"]
mod tests;
