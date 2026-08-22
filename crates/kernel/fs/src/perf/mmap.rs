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
use super::ring::{locked_vm, PerfBuffer};
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
    /// `current_user()` — whose `locked_vm` the mapping is booked against and
    /// whose it is given back to when the last mapping goes away.
    pub uid:       u32,
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
            own_mapped: bool, watermark_bit: bool, wakeup_watermark: u32, c: &MmapCtx)
    -> Result<MmapPlan, Errno>
{
    // "Don't allow mmap() of inherited per-task counters": every child would
    // scribble the same ring.
    if cpu == -1 && attr_inherit { return Err(Errno::Einval); }
    if !c.shared { return Err(Errno::Einval); }
    if c.vma_pages > sizing::NR_PAGES_MAX { return Err(Errno::Enomem); }
    // A nonzero `vm_pgoff` selects the AUX area. The reference reaches
    // `-EINVAL` here for EVERY event whose PMU produces no AUX data, and it
    // does so BEFORE the allocator's `-EOPNOTSUPP` is reachable: the AUX
    // mapping's first two gates read `user_page->aux_offset`/`aux_size`, which
    // only an AUX-capable PMU ever writes, and reject an `aux_offset` below
    // `perf_data_size(rb) + PAGE_SIZE` — which zero always is. An event with no
    // ring at all takes the same `-EINVAL` one line earlier. So this is not a
    // stand-in for absent machinery; it is the outcome, with the same errno, of
    // the reference's own AUX ladder on a kernel whose PMUs declare no AUX
    // capability — which is every PMU oxide registers.
    if c.pgoff != 0 { return Err(Errno::Einval); }
    let nr = sizing::data_pages(c.vma_pages)?;
    if has_buffer {
        if buffer_pages != nr { return Err(Errno::Einval); }
        // A ring this event did not map itself is somebody ELSE's, borrowed by
        // a records redirect. Mapping it through this fd would put two events'
        // consumers on one control page, each overwriting the other's read
        // position, so it is refused as busy rather than admitted.
        if !own_mapped { return Err(Errno::Ebusy); }
        // Aliasing an existing ring allocates nothing, but it is still a
        // mapping and still costs the user its pages: the admission ladder is
        // NOT re-run (so an alias never fails on the allowance itself), yet the
        // whole mapping is charged, which is what makes an alias loop climb the
        // per-user total until the next non-alias mapping is refused. Nothing
        // further is pinned against the mm — the pages are already pinned.
        return Ok(MmapPlan { nr_data_pages: nr, overwrite: !c.writable,
                             charge: sizing::MlockCharge { user_extra: c.vma_pages, extra: 0 } });
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
    let c = &live_mlock(c);
    let own_mapped = ev.state.lock().mmap_count != 0;
    let p = plan(ev.attr.bit(attr_bit::INHERIT), ev.cpu, existing.is_some(),
                 existing.as_ref().map_or(0, |b| b.nr_data_pages()), own_mapped,
                 ev.attr.bit(attr_bit::WATERMARK), wakeup_watermark, c)?;
    if let Some(rb) = existing {
        rb.acct().record(c.uid, p.charge.user_extra, p.charge.extra);
        return Ok(rb);
    }
    let ds = sizing::data_size(p.nr_data_pages);
    let wm = sizing::watermark(ds, wakeup_watermark, ev.attr.bit(attr_bit::WATERMARK));
    let rb = PerfBuffer::alloc(p.nr_data_pages, wm, p.overwrite).ok_or(Errno::Enomem)?;
    // The pages are booked when the VMA opens and given back when the last one
    // closes (`ring::mapping`), so a ring that never gets mapped costs nothing.
    rb.acct().record(c.uid, p.charge.user_extra, p.charge.extra);
    // `perf_event_update_userpage` right after the attach, so a consumer that
    // maps and immediately reads the control page sees a live snapshot.
    let (count, enabled, running) = ev.read_value();
    rb.update_userpage(count, enabled, running);
    ev.state.lock().buffer = Some(Arc::clone(&rb));
    Ok(rb)
}

/// The request with `user->locked_vm` filled in from the live per-user ledger.
///
/// The syscall shim cannot supply this total: it would be a second place the
/// answer lives, and the first version of this path passed a zero placeholder
/// that made the per-user half of the ladder unable to refuse anything.
/// # C: O(N_users)
pub fn live_mlock(c: &MmapCtx) -> MmapCtx {
    let mut c = *c;
    c.mlock.user_locked = locked_vm::charged(c.uid);
    c
}

/// One more VMA maps `rb`. Returns the pages the caller must pin against the
/// mapping mm — nonzero only when this open applied a pending pinned charge.
/// # C: O(N_users)
pub fn vma_opened(ev: &Arc<PerfEvent>, rb: &Arc<PerfBuffer>) -> u64 {
    ev.state.lock().mmap_count += 1;
    rb.acct().opened()
}

/// One VMA mapping `rb` is gone. The last one gives the per-user pages back and
/// detaches the buffer from its event, so the next mapping of the fd allocates
/// a fresh ring and is admitted against a ledger that no longer counts this
/// one. Returns the pinned pages the caller must give back to the mapping mm.
/// # C: O(N_users)
pub fn vma_closed(ev: &Arc<PerfEvent>, rb: &Arc<PerfBuffer>) -> u64 {
    { let mut g = ev.state.lock(); g.mmap_count = g.mmap_count.saturating_sub(1); }
    let (last, pinned) = rb.acct().closed();
    if !last { return 0; }
    let mut st = ev.state.lock();
    if st.buffer.as_ref().is_some_and(|b| Arc::ptr_eq(b, rb)) { st.buffer = None; }
    pinned
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(vma_pages: u64) -> MmapCtx {
        MmapCtx {
            vma_pages, pgoff: 0, shared: true, writable: true, uid: 0,
            mlock: MlockCtx { vma_pages, user_locked: 0,
                              mlock_kb: sizing::MLOCK_KB_DEFAULT, nr_online_cpus: 1,
                              pinned_vm: 0, rlimit_pages: 0, paranoid: true,
                              cap_ipc_lock: false },
        }
    }

    fn ok(c: &MmapCtx) -> Result<MmapPlan, Errno> { plan(false, 0, false, 0, false, false, 0, c) }

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

    /// The AUX offset is refused with EINVAL whether or not a ring is already
    /// attached, and at every size — the reference's AUX ladder cannot get
    /// past its `aux_offset` gates when no PMU ever published an `aux_offset`,
    /// so EINVAL is the answer for a software event, not a placeholder for
    /// machinery that would otherwise return something else.
    #[test]
    fn the_aux_offset_is_einval_at_every_size_and_with_or_without_a_ring() {
        for pages in [1u64, 2, 4, 5, 9] {
            for (has_buffer, buffer_pages) in [(false, 0u64), (true, 4), (true, 8)] {
                let mut c = ctx(pages);
                c.pgoff = pages;
                assert_eq!(plan(false, 0, has_buffer, buffer_pages, true, false, 0, &c),
                           Err(Errno::Einval), "pages {pages} buffered {has_buffer}");
            }
        }
        // It is decided before the ring-size match a re-mmap would otherwise
        // fail on, so the errno cannot depend on which gate ran first.
        let mut c = ctx(5);
        c.pgoff = 1;
        assert_eq!(plan(false, 0, true, 4, true, false, 0, &c), Err(Errno::Einval));
    }

    #[test]
    fn an_inherited_per_task_event_cannot_be_mapped() {
        let c = ctx(5);
        assert_eq!(plan(true, -1, false, 0, false, false, 0, &c), Err(Errno::Einval));
        // A CPU-bound event with `inherit` set is fine — there is no child to
        // share the ring with.
        assert!(plan(true, 0, false, 0, false, false, 0, &c).is_ok());
        assert!(plan(false, -1, false, 0, false, false, 0, &c).is_ok());
    }

    /// A ring borrowed through a records redirect — one this event never
    /// mapped itself — cannot be mapped through this fd.
    #[test]
    fn mapping_a_borrowed_ring_is_busy() {
        let c = ctx(5);
        assert_eq!(plan(false, 0, true, 4, false, false, 0, &c), Err(Errno::Ebusy));
        // Once this event has a mapping of its own, a second one is fine.
        assert!(plan(false, 0, true, 4, true, false, 0, &c).is_ok());
    }

    #[test]
    fn remapping_an_attached_ring_must_match_its_size() {
        let c = ctx(5);
        assert!(plan(false, 0, true, 4, true, false, 0, &c).is_ok());
        assert_eq!(plan(false, 0, true, 8, true, false, 0, &c), Err(Errno::Einval));
    }

    /// The admission ladder must see the user's REAL running total. A zero
    /// placeholder here — what this path shipped with before the ledger
    /// existed — makes the per-user allowance unable to refuse anything, since
    /// every mapping looks like the user's first.
    #[test]
    fn the_ladder_reads_the_live_per_user_total() {
        let u = 0x7200_0001;
        let mut c = ctx(5);
        c.uid = u;
        assert_eq!(live_mlock(&c).mlock.user_locked, 0);
        locked_vm::charge(u, 40);
        assert_eq!(live_mlock(&c).mlock.user_locked, 40);
        // ... and the ladder charges the remainder against that total.
        let limit = sizing::user_lock_limit_pages(sizing::MLOCK_KB_DEFAULT, 1);
        c.vma_pages = limit;
        c.mlock.vma_pages = limit;
        c.mlock.cap_ipc_lock = true;
        let p = plan(false, 0, false, 0, false, false, 0, &live_mlock(&c)).unwrap();
        assert_eq!(p.charge.user_extra, limit - 40, "40 pages are already the user's");
        assert_eq!(p.charge.extra, 40, "the rest spills into the pinned half");
        locked_vm::release(u, 40);
    }

    /// Re-mapping an already-attached ring does not re-run the per-user ladder,
    /// so the alias itself can never be refused on the allowance.
    /// An alias of an attached ring is charged the whole mapping against the
    /// per-user allowance and pins nothing further. Charging it nothing would
    /// make an unbounded alias loop free, which is the hole this pins shut.
    #[test]
    fn aliasing_an_attached_ring_is_charged_but_pins_nothing_further() {
        let c = ctx(5);
        let p = plan(false, 0, true, 4, true, false, 0, &c).unwrap();
        assert_eq!(p.charge, sizing::MlockCharge { user_extra: 5, extra: 0 });
    }

    #[test]
    fn attaching_an_alias_records_the_charge_the_vma_open_applies() {
        use super::super::attr::PerfAttr;
        use super::super::counter::SwSource;

        let ev = PerfEvent::new(PerfAttr::default(), SwSource::Zero, None, 0, None);
        let mut c = ctx(5);
        c.uid = 0x7200_0002;
        let rb = PerfBuffer::hosted(4, 0, false);
        rb.acct().record(c.uid, 5, 0);
        assert_eq!(rb.acct().opened(), 0);
        { let mut st = ev.state.lock(); st.buffer = Some(Arc::clone(&rb)); st.mmap_count = 1; }
        assert_eq!(locked_vm::charged(c.uid), 5);
        let alias = attach(&ev, &c, 0).unwrap();
        assert!(Arc::ptr_eq(&rb, &alias));
        assert_eq!(vma_opened(&ev, &alias), 0);
        assert_eq!(locked_vm::charged(c.uid), 10, "the production alias records its charge");
        assert_eq!(vma_closed(&ev, &alias), 0);
        assert_eq!(vma_closed(&ev, &rb), 0);
        assert_eq!(locked_vm::charged(c.uid), 0);
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
