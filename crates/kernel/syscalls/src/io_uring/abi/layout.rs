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

/// Bytes in one region. Both regions are a single refcounted kernel frame
/// (`hal::PAGE_SIZE_BYTES`); `map_kernel_frame` maps ONE frame per VMA, so a
/// region cannot span pages without VMM work.
pub const REGION_BYTES: u32 = 4096;

/// Largest SQ ring oxide builds: one region of 64-byte SQEs, so 64 entries.
/// Linux's `IORING_MAX_ENTRIES` is 32768; oxide's ceiling is lower because a
/// region is one frame (`map_kernel_frame` maps a single frame per VMA). The
/// ladder past the ceiling is Linux's own — `EINVAL`, or clamp under
/// `IORING_SETUP_CLAMP` — so callers see a smaller kernel, not a different
/// contract. Raising it needs a multi-frame `VmaBacking`, not a change here.
pub const MAX_ENTRIES: u32 = REGION_BYTES / SQE_SIZE as u32;
/// Largest CQ ring oxide builds (Linux: `IORING_MAX_CQ_ENTRIES = 2 * max`).
pub const MAX_CQ_ENTRIES: u32 = 2 * MAX_ENTRIES;

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
/// the bit is simply absent from its own mask. Refusing is mandatory:
/// accepting `IORING_SETUP_SQPOLL` without a poll thread would leave the
/// caller spinning on an SQ ring nobody drains.
///
/// The task-work flags are honoured rather than ignored: every entry runs to
/// completion inside the submission that issued it, so there is never deferred
/// work to signal, notify or defer, and the `IORING_SQ_TASKRUN` bit a
/// `TASKRUN_FLAG` ring watches is correctly never raised. `SINGLE_ISSUER` is
/// enforced — a second task submitting to such a ring is refused.
pub const SUPPORTED_SETUP_FLAGS: u32 =
    IORING_SETUP_CQSIZE | IORING_SETUP_CLAMP | IORING_SETUP_NO_SQARRAY
    | IORING_SETUP_SUBMIT_ALL | IORING_SETUP_R_DISABLED
    | IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_COOP_TASKRUN
    | IORING_SETUP_TASKRUN_FLAG | IORING_SETUP_DEFER_TASKRUN;

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
/// NOT claimed, and why: FAST_POLL and NATIVE_WORKERS (no worker pool to
/// retry from), POLL_32BITS (no poll entry), SQPOLL_NONFIXED (no poll
/// thread), REG_REG_RING (no registered-ring array).
pub const REPORTED_FEATURES: u32 =
    IORING_FEAT_SINGLE_MMAP | IORING_FEAT_NODROP | IORING_FEAT_SUBMIT_STABLE
    | IORING_FEAT_RW_CUR_POS | IORING_FEAT_CUR_PERSONALITY | IORING_FEAT_EXT_ARG
    | IORING_FEAT_RSRC_TAGS | IORING_FEAT_CQE_SKIP | IORING_FEAT_LINKED_FILE;

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
/// a geometry that does not fit a region (`-EOVERFLOW`). # C: O(1)
fn rings_size(flags: u32, sq_entries: u32, cq_entries: u32) -> Result<(u32, u32, u32), Errno> {
    let cqes_bytes = cq_entries.checked_mul(CQE_SIZE as u32).ok_or(Errno::Eoverflow)?;
    let mut off = RING_CQES.checked_add(cqes_bytes).ok_or(Errno::Eoverflow)?;
    let sq_array_off = if flags & IORING_SETUP_NO_SQARRAY == 0 {
        let at = off;
        off = off.checked_add(sq_entries.checked_mul(4).ok_or(Errno::Eoverflow)?).ok_or(Errno::Eoverflow)?;
        at
    } else {
        NO_SQ_ARRAY
    };
    let sqes_bytes = sq_entries.checked_mul(SQE_SIZE as u32).ok_or(Errno::Eoverflow)?;
    if off > REGION_BYTES || sqes_bytes > REGION_BYTES { return Err(Errno::Eoverflow); }
    Ok((sq_array_off, off, sqes_bytes))
}

/// Full `io_uring_setup` admission: validate `p` (already read from user),
/// size the regions, and fill in every out-field except `features`, which the
/// caller sets once the regions exist (Linux `io_uring_create`). `entries` is
/// the syscall's first argument; Linux stores it into `p->sq_entries` before
/// `io_uring_create`. # C: O(1)
pub fn prepare(p: &mut Params, entries: u32) -> Result<Geometry, Errno> {
    // Linux `io_uring_setup()` checks `p->resv` before anything else.
    if p.resv != [0; 3] { return Err(Errno::Einval); }
    sanitise(p.flags)?;
    p.sq_entries = entries;
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
    })
}

/// Which region an `mmap(2)` offset on the ring fd selects (Linux
/// `io_uring_mmap` switches on `offset & IORING_OFF_MMAP_MASK`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MmapRegion { Rings, Sqes, Invalid }

/// Classify an mmap offset. `IORING_OFF_CQ_RING` selects the SAME region as
/// `IORING_OFF_SQ_RING` because oxide reports `IORING_FEAT_SINGLE_MMAP`.
/// # C: O(1)
pub fn mmap_region(offset: u64) -> MmapRegion {
    match offset & IORING_OFF_MMAP_MASK {
        IORING_OFF_SQ_RING => MmapRegion::Rings,
        IORING_OFF_CQ_RING => MmapRegion::Rings,
        IORING_OFF_SQES    => MmapRegion::Sqes,
        _                  => MmapRegion::Invalid,
    }
}

#[cfg(test)]
#[path = "layout/tests.rs"]
mod tests;
