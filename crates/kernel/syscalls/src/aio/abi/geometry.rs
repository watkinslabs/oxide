// `io_setup(2)` sizing: how a requested `nr_events` becomes a ring page count
// and the (larger) slot count userspace actually sees, plus the system-wide
// `fs.aio-max-nr` admission. Pure arithmetic so the rounding — which userspace
// observes through `aio_ring.nr` — is unit-tested rather than boot-tested.

use syscall::errno::Errno;

use super::uapi::{AIO_RING_HDR_SIZE, IOEV_SIZE};

/// `fs.aio-max-nr` default: the system-wide ceiling on the SUM of every live
/// context's requested `nr_events`.
pub const AIO_MAX_NR_DEFAULT: u64 = 0x10000;

/// Ceiling on the doubled slot count: a ring may not describe more than
/// 256 MiB worth of `io_event`s.
pub const NR_EVENTS_BYTE_CAP: u64 = 0x1000_0000;

/// Slots the head/tail pair cannot both use — one is structurally required to
/// tell "empty" from "full", the second is slack.
pub const RING_SLACK_SLOTS: u64 = 2;

/// Admitted ring shape for one `io_setup` request.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RingPlan {
    /// The `nr_events` the caller asked for. This — not the rounded-up slot
    /// count — is what charges against `fs.aio-max-nr`.
    pub max_reqs: u32,
    /// Pages the ring region occupies.
    pub nr_pages: u64,
    /// Slots the ring really has, published as `aio_ring.nr`. Always larger
    /// than `max_reqs`: the count is doubled (so per-CPU reservation cannot
    /// starve a submitter), padded, then rounded up to fill whole pages.
    pub nr_events: u32,
}

/// Turn a requested `nr_events` into a ring shape.
///
/// Order of the two rejections is observable: the 256 MiB cap answers `EINVAL`
/// and is tested BEFORE the `EAGAIN` pair (a doubled count that wrapped to
/// zero, and a request above the system ceiling).
/// # C: O(1)
pub fn plan_ring(req: u32, nr_cpus: u32, page_size: u64, aio_max_nr: u64)
    -> Result<RingPlan, Errno>
{
    let max_reqs = req;
    // Half the slots can sit in per-CPU reservations, so double what the caller
    // asked for and never go below a per-CPU floor.
    let floor = nr_cpus.saturating_mul(4);
    let doubled = core::cmp::max(req, floor).wrapping_mul(2);
    if doubled as u64 > NR_EVENTS_BYTE_CAP / IOEV_SIZE { return Err(Errno::Einval); }
    if doubled == 0 || max_reqs as u64 > aio_max_nr { return Err(Errno::Eagain); }
    let padded = doubled as u64 + RING_SLACK_SLOTS;
    let size = AIO_RING_HDR_SIZE + IOEV_SIZE * padded;
    let nr_pages = size.div_ceil(page_size);
    let nr_events = (page_size * nr_pages - AIO_RING_HDR_SIZE) / IOEV_SIZE;
    Ok(RingPlan { max_reqs, nr_pages, nr_events: nr_events as u32 })
}

/// System-wide `aio_nr` admission: the new total, or `EAGAIN` when the request
/// would push past `aio_max_nr` (or wrap).
/// # C: O(1)
pub fn admit_aio_nr(cur: u64, max_reqs: u32, aio_max_nr: u64) -> Result<u64, Errno> {
    let next = match cur.checked_add(max_reqs as u64) { Some(v) => v, None => return Err(Errno::Eagain) };
    if next > aio_max_nr { return Err(Errno::Eagain); }
    Ok(next)
}

/// Smallest buddy order covering `nr_pages`. # C: O(log nr_pages)
pub fn order_for_pages(nr_pages: u64) -> u8 {
    let mut order = 0u8;
    while (1u64 << order) < nr_pages { order += 1; }
    order
}
