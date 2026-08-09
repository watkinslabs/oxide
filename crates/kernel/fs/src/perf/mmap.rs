// `perf_mmap`/`perf_mmap_rb` — attaching a ring buffer to an event fd.
//
// The admission ladder is a pure function over the facts the syscall layer
// gathers, so every `-EINVAL`/`-EPERM`/`-EBUSY`/`-ENOMEM` in the reference's
// order is hosted-testable; only the allocation and the attach touch live
// state.

use alloc::sync::Arc;

use syscall::errno::Errno;

use super::event::PerfEvent;
use super::ring::sizing::{self, MlockCtx};
use super::ring::PerfBuffer;
use super::uapi::attr_bit;

/// What `perf_mmap` needs to know about the caller's request and limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmapCtx {
    /// `vma_pages(vma)` — the whole mapping, control page included.
    pub vma_pages: u64,
    /// `vma->vm_pgoff` — nonzero selects the AUX area.
    pub pgoff:     u64,
    /// `vma->vm_flags & VM_SHARED`.
    pub shared:    bool,
    /// `vma->vm_flags & VM_WRITE` — a writable mapping is a NON-overwrite ring.
    pub writable:  bool,
    pub mlock:     MlockCtx,
}

/// The reference's decision, before anything is allocated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmapPlan {
    pub nr_data_pages: u64,
    pub overwrite:     bool,
    pub charge:        sizing::MlockCharge,
}

/// `perf_mmap` + `perf_mmap_rb`'s admission, in the reference's order.
///
/// `has_buffer`/`buffer_pages` describe an already-attached ring, which a
/// second `mmap` of the same fd may only alias at the identical size.
/// # C: O(1)
pub fn plan(attr_inherit: bool, cpu: i32, has_buffer: bool, buffer_pages: u64,
            watermark_bit: bool, wakeup_watermark: u32, c: &MmapCtx)
    -> Result<MmapPlan, Errno>
{
    // "Don't allow mmap() of inherited per-task counters": every child would
    // scribble the same ring.
    if cpu == -1 && attr_inherit { return Err(Errno::Einval); }
    if !c.shared { return Err(Errno::Einval); }
    if c.vma_pages > sizing::NR_PAGES_MAX { return Err(Errno::Enomem); }
    // The AUX area needs a PMU that produces hardware trace data. oxide
    // registers only software PMUs, so `rb_alloc_aux` has nothing to set up
    // and the reference's `!has_aux(event)` arm applies.
    if c.pgoff != 0 { return Err(Errno::Einval); }
    let nr = sizing::data_pages(c.vma_pages)?;
    if has_buffer {
        if buffer_pages != nr { return Err(Errno::Einval); }
        // Aliasing an existing ring costs the same accounting but allocates
        // nothing; the caller sees `nr_data_pages == buffer_pages` and reuses.
        let charge = sizing::calc_limits(&c.mlock)?;
        return Ok(MmapPlan { nr_data_pages: nr, overwrite: !c.writable, charge });
    }
    let charge = sizing::calc_limits(&c.mlock)?;
    let _ = (watermark_bit, wakeup_watermark);
    Ok(MmapPlan { nr_data_pages: nr, overwrite: !c.writable, charge })
}

/// Attach a ring to `ev`, allocating one if the event has none. Returns the
/// buffer the mapping must publish pages from. # C: O(nr_data_pages)
pub fn attach(ev: &Arc<PerfEvent>, c: &MmapCtx, wakeup_watermark: u32)
    -> Result<Arc<PerfBuffer>, Errno>
{
    let existing = ev.buffer();
    let p = plan(ev.attr.bit(attr_bit::INHERIT), ev.cpu, existing.is_some(),
                 existing.as_ref().map_or(0, |b| b.nr_data_pages()),
                 ev.attr.bit(attr_bit::WATERMARK), wakeup_watermark, c)?;
    if let Some(rb) = existing { return Ok(rb); }
    let ds = sizing::data_size(p.nr_data_pages);
    let wm = sizing::watermark(ds, wakeup_watermark, ev.attr.bit(attr_bit::WATERMARK));
    let rb = PerfBuffer::alloc(p.nr_data_pages, wm, p.overwrite).ok_or(Errno::Enomem)?;
    // `perf_event_update_userpage` right after the attach, so a consumer that
    // maps and immediately reads the control page sees a live snapshot.
    let (count, enabled, running) = ev.read_value();
    rb.update_userpage(count, enabled, running);
    ev.state.lock().buffer = Some(Arc::clone(&rb));
    Ok(rb)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(vma_pages: u64) -> MmapCtx {
        MmapCtx {
            vma_pages, pgoff: 0, shared: true, writable: true,
            mlock: MlockCtx { vma_pages, user_locked: 0,
                              mlock_kb: sizing::MLOCK_KB_DEFAULT, nr_online_cpus: 1,
                              pinned_vm: 0, rlimit_pages: 0, paranoid: true,
                              cap_ipc_lock: false },
        }
    }

    fn ok(c: &MmapCtx) -> Result<MmapPlan, Errno> { plan(false, 0, false, 0, false, 0, c) }

    #[test]
    fn accepts_one_control_page_plus_a_power_of_two() {
        assert_eq!(ok(&ctx(9)).unwrap().nr_data_pages, 8);
        assert_eq!(ok(&ctx(2)).unwrap().nr_data_pages, 1);
        // A control page alone is a valid (permanently paused) ring.
        assert_eq!(ok(&ctx(1)).unwrap().nr_data_pages, 0);
        assert_eq!(ok(&ctx(10)), Err(Errno::Einval));
    }

    #[test]
    fn a_readonly_mapping_is_an_overwrite_ring() {
        let mut c = ctx(5);
        assert!(!ok(&c).unwrap().overwrite);
        c.writable = false;
        assert!(ok(&c).unwrap().overwrite);
    }

    #[test]
    fn private_mapping_and_aux_offset_are_refused() {
        let mut c = ctx(5);
        c.shared = false;
        assert_eq!(ok(&c), Err(Errno::Einval));
        let mut c = ctx(5);
        c.pgoff = 5;
        assert_eq!(ok(&c), Err(Errno::Einval));
    }

    #[test]
    fn an_inherited_per_task_event_cannot_be_mapped() {
        let c = ctx(5);
        assert_eq!(plan(true, -1, false, 0, false, 0, &c), Err(Errno::Einval));
        // A CPU-bound event with `inherit` set is fine — there is no child to
        // share the ring with.
        assert!(plan(true, 0, false, 0, false, 0, &c).is_ok());
        assert!(plan(false, -1, false, 0, false, 0, &c).is_ok());
    }

    #[test]
    fn remapping_an_attached_ring_must_match_its_size() {
        let c = ctx(5);
        assert!(plan(false, 0, true, 4, false, 0, &c).is_ok());
        assert_eq!(plan(false, 0, true, 8, false, 0, &c), Err(Errno::Einval));
    }

    #[test]
    fn the_mlock_ladder_is_applied_before_anything_is_allocated() {
        let limit = sizing::user_lock_limit_pages(sizing::MLOCK_KB_DEFAULT, 1);
        let mut c = ctx(limit + 2);
        // `limit + 1` data pages is not a power of two; pick the next one that is.
        c.vma_pages = limit.next_power_of_two() * 2 + 1;
        c.mlock.vma_pages = c.vma_pages;
        assert_eq!(ok(&c), Err(Errno::Eperm));
        c.mlock.cap_ipc_lock = true;
        assert!(ok(&c).is_ok());
    }
}
