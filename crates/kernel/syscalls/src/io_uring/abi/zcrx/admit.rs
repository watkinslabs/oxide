// The zero-copy receive admission ladders, in the reference's order.
//
// Order is the contract, not an implementation detail: when several rungs
// would fail, WHICH errno the caller gets is what tells it what to fix. Each
// ladder below is one reference function's front half, with the copies left to
// the caller so nothing here touches user memory.

use syscall::errno::Errno;

use crate::io_uring_abi::uapi::{
    IORING_SETUP_CLAMP, IORING_SETUP_CQE32, IORING_SETUP_CQE_MIXED, IORING_SETUP_DEFER_TASKRUN,
};

use super::*;

/// 1 TiB — the largest area the reference will pin.
const AREA_MAX_BYTES: u64 = 1 << 40;

/// A ring must be able to deliver a zero-copy receive completion before it may
/// register a queue that produces one: the receive posts auxiliary completions
/// from task context and each carries a 32-byte record.
///
/// | rung | errno |
/// |---|---|
/// | no `IORING_SETUP_DEFER_TASKRUN` | `EINVAL` |
/// | neither `IORING_SETUP_CQE32` nor `IORING_SETUP_CQE_MIXED` | `EINVAL` |
/// # C: O(1)
pub fn admit_ring_flags(ring_flags: u32) -> Result<(), Errno> {
    if ring_flags & IORING_SETUP_DEFER_TASKRUN == 0 { return Err(Errno::Einval); }
    if ring_flags & (IORING_SETUP_CQE32 | IORING_SETUP_CQE_MIXED) == 0 { return Err(Errno::Einval); }
    Ok(())
}

/// What a registration turned into once admitted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RegKind {
    /// Adopt an instance another ring already registered.
    Import,
    /// Bind a device receive queue.
    Device { if_idx: u32, if_rxq: u32 },
    /// No device: every byte is copied into the area.
    NoDev,
}

/// `IORING_REGISTER_ZCRX_IFQ`'s own ladder, up to the point where memory is
/// touched. `reg.rq_entries` is REWRITTEN to the depth that will be built, so
/// the caller and the kernel agree on it before either allocates anything.
///
/// | rung | errno |
/// |---|---|
/// | a reserved word set, or a caller-supplied instance id | `EINVAL` |
/// | an unknown registration flag | `EINVAL` |
/// | `ZCRX_REG_IMPORT` | admitted, and nothing below applies |
/// | no receive queue named, or an empty refill queue | `EINVAL` |
/// | a device named together with `ZCRX_REG_NODEV` | `EINVAL` |
/// | a refill queue past the maximum, on a ring that did not ask to be clamped | `EINVAL` |
/// # C: O(1)
pub fn admit_ifq_reg(reg: &mut IfqReg, ring_flags: u32) -> Result<RegKind, Errno> {
    if reg.resv != [0; 2] || reg.zcrx_id != 0 { return Err(Errno::Einval); }
    if reg.flags & !ZCRX_SUPPORTED_REG_FLAGS != 0 { return Err(Errno::Einval); }
    if reg.flags & ZCRX_REG_IMPORT != 0 { return Ok(RegKind::Import); }

    // `if_rxq == -1` is the reference's "no queue named" sentinel; it arrives
    // as an all-ones `u32`.
    if reg.if_rxq == u32::MAX || reg.rq_entries == 0 { return Err(Errno::Einval); }
    let nodev = reg.flags & ZCRX_REG_NODEV != 0;
    if (reg.if_rxq != 0 || reg.if_idx != 0) && nodev { return Err(Errno::Einval); }
    if reg.rq_entries > IO_RQ_MAX_ENTRIES {
        if ring_flags & IORING_SETUP_CLAMP == 0 { return Err(Errno::Einval); }
        reg.rq_entries = IO_RQ_MAX_ENTRIES;
    }
    reg.rq_entries = roundup_pow2(reg.rq_entries);
    Ok(if nodev { RegKind::NoDev } else { RegKind::Device { if_idx: reg.if_idx, if_rxq: reg.if_rxq } })
}

/// Round up to a power of two, saturating. # C: O(1)
fn roundup_pow2(v: u32) -> u32 {
    if v == 0 { return 1; }
    if v.is_power_of_two() { return v; }
    1u32 << (32 - v.leading_zeros())
}

/// The notification descriptor's ladder.
///
/// | rung | errno |
/// |---|---|
/// | an unknown notification type | `EINVAL` |
/// | an unknown descriptor flag | `EINVAL` |
/// | a statistics offset with no statistics flag | `EINVAL` |
/// | a reserved word set | `EINVAL` |
/// # C: O(1)
pub fn admit_notif_desc(n: &NotifDesc) -> Result<(), Errno> {
    if n.type_mask & !ZCRX_NOTIF_TYPE_MASK != 0 { return Err(Errno::Einval); }
    if n.flags & !ZCRX_NOTIF_DESC_FLAG_STATS != 0 { return Err(Errno::Einval); }
    if n.flags & ZCRX_NOTIF_DESC_FLAG_STATS == 0 && n.stats_offset != 0 {
        return Err(Errno::Einval);
    }
    if n.resv2 != [0; 9] { return Err(Errno::Einval); }
    Ok(())
}

/// Bytes the refill-queue region must hold for `rq_entries` entries.
/// # C: O(1)
pub fn rq_region_bytes(rq_entries: u32) -> u64 {
    ZCRX_RQ_RQES_OFF as u64 + RQE_BYTES * rq_entries as u64
}

/// Whether the region the caller described is big enough for the refill queue
/// that will be built in it. # C: O(1)
pub fn admit_rq_region(rq_entries: u32, region_bytes: u64) -> Result<(), Errno> {
    if rq_region_bytes(rq_entries) > region_bytes { return Err(Errno::Einval); }
    Ok(())
}

/// Where the notification statistics live inside the refill-queue region.
///
/// | rung | errno |
/// |---|---|
/// | misaligned for the record | `EINVAL` |
/// | inside the refill queue's own bytes | `ERANGE` |
/// | the record would run past the region | `ERANGE` |
/// # C: O(1)
pub fn admit_notif_stats(stats_off: u64, rq_entries: u32, region_bytes: u64)
    -> Result<u64, Errno>
{
    if stats_off % 8 != 0 { return Err(Errno::Einval); }
    let used = rq_region_bytes(rq_entries);
    if stats_off < used { return Err(Errno::Erange); }
    let end = stats_off.checked_add(NOTIF_STATS_BYTES).ok_or(Errno::Erange)?;
    if end > region_bytes { return Err(Errno::Erange); }
    Ok(stats_off)
}

/// The area descriptor's ladder — Linux `io_import_area`.
///
/// | rung | errno |
/// |---|---|
/// | an unknown area flag | `EINVAL` |
/// | a caller-supplied area token | `EINVAL` |
/// | a reserved word set | `EINVAL` |
/// | an empty area | `EFAULT` |
/// | an area past 1 TiB | `EINVAL` |
/// | an area whose end wraps | `EOVERFLOW` |
/// | an address or length that is not page-aligned | `EINVAL` |
/// | a buffer-sharing descriptor named on a plain area | `EINVAL` |
/// | a plain area at address zero | `EFAULT` |
/// | `IORING_ZCRX_AREA_DMABUF` | `EOPNOTSUPP` |
/// # C: O(1)
pub fn admit_area_reg(a: &AreaReg, page: u64) -> Result<(), Errno> {
    if a.flags & !IO_ZCRX_AREA_SUPPORTED_FLAGS != 0 { return Err(Errno::Einval); }
    if a.rq_area_token != 0 { return Err(Errno::Einval); }
    if a.resv2 != [0; 2] { return Err(Errno::Einval); }

    if a.len == 0 { return Err(Errno::Efault); }
    if a.len > AREA_MAX_BYTES { return Err(Errno::Einval); }
    let acct = a.len.checked_add(page - 1).ok_or(Errno::Eoverflow)? & !(page - 1);
    a.addr.checked_add(acct).ok_or(Errno::Eoverflow)?;
    if a.addr & (page - 1) != 0 || a.len & (page - 1) != 0 { return Err(Errno::Einval); }

    if a.flags & IORING_ZCRX_AREA_DMABUF != 0 {
        // Recognised, and refused for the whole mechanism rather than per
        // field: there is no buffer-sharing framework to import from, so an
        // accepted descriptor would name memory this kernel cannot reach.
        return Err(Errno::Eopnotsupp);
    }
    if a.dmabuf_fd != 0 { return Err(Errno::Einval); }
    if a.addr == 0 { return Err(Errno::Efault); }
    Ok(())
}

/// Buffer size one area slot spans, and the shift that indexes it.
///
/// | rung | errno |
/// |---|---|
/// | a size that is not a power of two, or below one page | `EINVAL` |
/// | a size other than one page asked of a registration with no device | `EOPNOTSUPP` |
/// | a size larger than the area itself | `ERANGE` |
/// # C: O(1)
pub fn admit_buf_len(rx_buf_len: u32, area_len: u64, has_dev: bool, page: u64)
    -> Result<u32, Errno>
{
    let page_shift = page.trailing_zeros();
    let shift = if rx_buf_len == 0 {
        page_shift
    } else {
        if !(rx_buf_len as u64).is_power_of_two() || (rx_buf_len as u64) < page {
            return Err(Errno::Einval);
        }
        (rx_buf_len as u64).trailing_zeros()
    };
    if !has_dev && shift != page_shift { return Err(Errno::Eopnotsupp); }
    if (1u64 << shift) > area_len { return Err(Errno::Erange); }
    Ok(shift)
}

/// `IORING_REGISTER_ZCRX_CTRL`'s ladder, before the instance is looked up.
///
/// | rung | errno |
/// |---|---|
/// | a non-zero argument count | `EINVAL` |
/// | a reserved word set | `EFAULT` |
///
/// The second rung really is `EFAULT` in the reference and not `EINVAL`; a
/// caller told `EINVAL` there would look for a bad opcode it does not have.
/// # C: O(1)
pub fn admit_ctrl(c: &Ctrl, nr_args: u32) -> Result<(), Errno> {
    if nr_args != 0 { return Err(Errno::Einval); }
    if c.resv != [0; 2] { return Err(Errno::Efault); }
    Ok(())
}

/// A control operation's own body ladder, once the instance is resolved.
/// # C: O(1)
pub fn admit_ctrl_op(c: &Ctrl) -> Result<u32, Errno> {
    match c.op {
        ZCRX_CTRL_FLUSH_RQ => {
            if !c.flush_resv_clear() { return Err(Errno::Einval); }
            Ok(ZCRX_CTRL_FLUSH_RQ)
        }
        ZCRX_CTRL_ARM_NOTIFICATION => {
            let (ty, resv_clear) = c.arm_notif();
            if ty >= ZCRX_NOTIF_TYPE_LAST { return Err(Errno::Einval); }
            if !resv_clear { return Err(Errno::Einval); }
            Ok(ZCRX_CTRL_ARM_NOTIFICATION)
        }
        ZCRX_CTRL_EXPORT => Ok(ZCRX_CTRL_EXPORT),
        _ => Err(Errno::Eopnotsupp),
    }
}

/// `IORING_OP_RECV_ZC`'s preparation ladder — Linux `io_recvzc_prep`.
///
/// | rung | errno |
/// |---|---|
/// | `addr`, `addr2` or `addr3` set | `EINVAL` |
/// | an instance id naming no registered queue | `EINVAL` |
/// | any message flag | `EINVAL` |
/// | a per-operation flag other than poll-first or multishot | `EINVAL` |
/// | multishot not asked for | `EINVAL` |
///
/// The last rung is not a limitation: every byte a zero-copy receive delivers
/// is reported by an auxiliary completion, so a single-shot form would have
/// nothing to put in its own completion.
/// # C: O(1)
pub fn admit_recvzc_prep(addr: u64, addr2: u64, addr3: u64, ifq_known: bool,
                         msg_flags: u32, op_flags: u16) -> Result<(), Errno> {
    use crate::io_uring_abi::ops::{IORING_RECVSEND_POLL_FIRST, IORING_RECV_MULTISHOT};
    if addr != 0 || addr2 != 0 || addr3 != 0 { return Err(Errno::Einval); }
    if !ifq_known { return Err(Errno::Einval); }
    if msg_flags != 0 { return Err(Errno::Einval); }
    let known = IORING_RECVSEND_POLL_FIRST | IORING_RECV_MULTISHOT;
    if op_flags as u32 & !known != 0 { return Err(Errno::Einval); }
    if op_flags as u32 & IORING_RECV_MULTISHOT == 0 { return Err(Errno::Einval); }
    Ok(())
}

/// Decode one refill-queue entry into the area slot it names — Linux
/// `io_parse_rqe`. A padding word that is set, an area other than the one
/// area an instance has, or a slot past the area's end is a malformed entry:
/// it is SKIPPED rather than reported, because the entry came from a ring
/// userspace writes without the kernel watching, and a receive path cannot
/// fail a whole batch on one bad word. # C: O(1)
pub fn parse_rqe(rqe: &Rqe, niov_shift: u32, num_niovs: u32) -> Option<u32> {
    if rqe.pad != 0 { return None; }
    let area_idx = rqe.off >> IORING_ZCRX_AREA_SHIFT;
    if area_idx != 0 { return None; }
    let niov_idx = (rqe.off & !IORING_ZCRX_AREA_MASK) >> niov_shift;
    if niov_idx >= num_niovs as u64 { return None; }
    Some(niov_idx as u32)
}

/// Entries the refill queue holds, bounded by its depth so a tail userspace
/// ran past cannot make the kernel walk further than the ring. # C: O(1)
pub fn rq_available(tail: u32, cached_head: u32, nr_entries: u32) -> u32 {
    core::cmp::min(tail.wrapping_sub(cached_head), nr_entries)
}
