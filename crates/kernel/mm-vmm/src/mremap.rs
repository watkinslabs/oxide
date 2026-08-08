// `mremap` work fn — split out of address_space.rs to keep both files
// under the repository line cap (`docs/08§7`). The mremap surface is one
// pub method on `AddressSpace`; defining it here in a fresh `impl`
// block keeps the call site (`AddressSpace::mremap`) unchanged.

use alloc::sync::Arc;
use hal::UserVirtAddr;

use crate::address_space::AddressSpace;
use crate::uffd::{UffdContext, UffdEvent, UffdEventKind};
use crate::vma::{VmaBacking, VmaFlags, VmaProt};
use crate::{Error, KResult};

/// A userfaultfd registration that must FOLLOW the mapping it covers, charged
/// for the duration of the move.
///
/// A registration names addresses, so a move that left it behind would aim
/// every later resolve at memory the mapping no longer occupies. A monitor that
/// did not ask to be told about moves gets no watch at all and its registration
/// is dropped with the old mapping — keeping it would silently re-point a
/// barrier the monitor cannot see.
struct RemapWatch {
    ctx: Arc<dyn UffdContext>,
    modes: VmaFlags,
}

impl AddressSpace {
    /// Charge a move against the source's monitor, if it tracks moves.
    /// # C: O(log N)
    fn remap_watch(&self, old: UserVirtAddr) -> Option<RemapWatch> {
        if !self.maybe_uffd() { return None; }
        let hit = self.uffd_vma_at(old)?;
        let ctx = hit.ctx?;
        if !ctx.wants_event(UffdEventKind::Remap) { return None; }
        ctx.change_begin();
        Some(RemapWatch { ctx, modes: hit.modes })
    }

    /// Re-arm the registration over the destination and announce the move,
    /// blocking until the monitor has read it.
    /// # C: O(K log N) + block
    fn remap_done(&self, w: Option<RemapWatch>, from: u64, to: u64, len: u64) {
        let Some(w) = w else { return };
        self.set_uffd(to, to + len, Arc::clone(&w.ctx), w.modes);
        w.ctx.change_complete(UffdEvent::Remap { from, to, len });
    }
}

/// Release a charge for a move that did not happen. # C: O(1)
fn remap_failed(w: Option<RemapWatch>) {
    if let Some(w) = w { w.ctx.change_abort(); }
}

fn rebase_backing(backing: &VmaBacking, delta: u64) -> VmaBacking {
    match backing {
        VmaBacking::File { backing, off } =>
            VmaBacking::File { backing: backing.clone(), off: off + delta },
        VmaBacking::KernelBytes { data, off } =>
            VmaBacking::KernelBytes { data: data.clone(), off: off + delta as usize },
        b => b.clone(),
    }
}

impl AddressSpace {
    /// `mremap` per `mremap(2)`. work fn per `docs/53§3`.
    /// Returns the new mapping address. Behaviour:
    ///   new_size < old_size  → shrink in place, drop tail
    ///   new_size == old_size → no-op, return old
    ///   new_size > old_size  → copy to a new region (MAYMOVE/FIXED)
    /// # C: O(VMA-tree ops + min(old,new) byte copy)
    pub fn mremap(
        &self,
        old: UserVirtAddr,
        old_size: usize,
        new_size: usize,
        maymove: bool,
        fixed: bool,
        new_addr: Option<UserVirtAddr>,
    ) -> KResult<UserVirtAddr> {
        self.mremap_full(old, old_size, new_size, maymove, fixed, false, new_addr)
    }

    /// `mremap` with MREMAP_DONTUNMAP support. Linux semantics
    /// (mremap(2), since Linux 5.7):
    ///   * MREMAP_DONTUNMAP requires MREMAP_MAYMOVE.
    ///   * new_size must equal old_size (no resize).
    ///   * Source VMA must not be VM_DONTEXPAND/VM_PFNMAP.
    ///   * After completion the source range remains mapped (the VMA
    ///     stays) but its PTEs are torn down — subsequent reads
    ///     refault as fresh zero pages. The destination range holds
    ///     the original contents.
    /// Implemented as: install a destination VMA with the source
    /// prot/flags/backing, byte-copy populated writable private data, then
    /// leave source VMA in place for syscall-layer PTE eviction.
    /// # C: O(min(old,new))
    #[allow(clippy::too_many_arguments)]
    pub fn mremap_full(
        &self,
        old: UserVirtAddr,
        old_size: usize,
        new_size: usize,
        maymove: bool,
        fixed: bool,
        dontunmap: bool,
        new_addr: Option<UserVirtAddr>,
    ) -> KResult<UserVirtAddr> {
        if old.as_u64() & (hal::PAGE_SIZE_BYTES - 1) != 0 || new_size == 0 {
            return Err(Error::Inval);
        }
        let old_end = old.as_u64().checked_add(old_size as u64).ok_or(Error::Inval)?;
        let move_or_expand = fixed || dontunmap || new_size > old_size;
        if dontunmap {
            // DONTUNMAP requires MAYMOVE, forbids resize, and is
            // disallowed for VM_DONTEXPAND/VM_PFNMAP mappings. Oxide
            // currently has no such VMA flags, so the source coverage check
            // below is the Linux-relevant gate here.
            if !maymove || new_size != old_size {
                return Err(Error::Inval);
            }
            let src_vma = self.find_vma(old).ok_or(Error::Fault)?;
            if old_size == 0 || old_end > src_vma.end.as_u64() {
                return Err(Error::Fault);
            }
            let delta = old.as_u64() - src_vma.start.as_u64();
            let moved_backing = rebase_backing(&src_vma.backing, delta);
            let hint = new_addr;
            let watch = self.remap_watch(old);
            let new_va = match self.mmap_preserving_prot(
                hint,
                new_size,
                src_vma.prot,
                src_vma.may_prot,
                src_vma.flags,
                moved_backing,
                fixed,
            ) {
                Ok(v) => v,
                Err(e) => { remap_failed(watch); return Err(e); }
            };
            #[cfg(not(test))]
            {
                let dst = new_va.as_u64();
                // SAFETY: caller's AS is active; both ranges live within it. Old pages fault-in on the read, new pages fault-in on the write; size validated by mmap above.
                unsafe {
                    for i in 0..old_size {
                        let v = core::ptr::read_volatile((old.as_u64() + i as u64) as *const u8);
                        core::ptr::write_volatile((dst + i as u64) as *mut u8, v);
                    }
                }
            }
            // Source VMA stays. PTE eviction so future reads refault
            // as zero is performed by the syscall-layer caller (it
            // sits in the mm-pmm crate where the PT walker lives).
            self.remap_done(watch, old.as_u64(), new_va.as_u64(), old_size as u64);
            return Ok(new_va);
        }
        let src_vma = self.find_vma(old).ok_or(Error::Fault)?;
        if move_or_expand {
            let covered_old_len = if new_size < old_size { new_size } else { old_size };
            let covered_end = old.as_u64().checked_add(covered_old_len as u64).ok_or(Error::Inval)?;
            if covered_end > src_vma.end.as_u64() {
                return Err(Error::Fault);
            }
            if old_size == 0
                && !src_vma.flags.intersects(VmaFlags::SHARED) {
                return Err(Error::Inval);
            }
        }
        if new_size < old_size && !fixed {
            let drop_va = old.as_u64() + new_size as u64;
            if let Some(da) = UserVirtAddr::new(drop_va) {
                let _ = self.munmap(da, old_size - new_size);
            }
            return Ok(old);
        }
        if new_size == old_size && !fixed {
            return Ok(old);
        }
        if !maymove && !fixed {
            return Err(Error::NoMem);
        }
        // Linux mremap MOVES the vma: the destination keeps the SOURCE's
        // prot, flags, and backing (file off shifted by the intra-vma
        // delta). Forcing Anonymous|PRIVATE|RW here (the old behavior)
        // dropped file backing (never-faulted moved pages read ZERO instead
        // of file content), dropped EXEC, and broke MAP_SHARED visibility.
        // Linux requires the moved range to lie within one vma — enforce it.
        let delta = old.as_u64() - src_vma.start.as_u64();
        let moved_backing = rebase_backing(&src_vma.backing, delta);
        let hint = if fixed { new_addr.or(Some(old)) } else { None };
        let watch = self.remap_watch(old);
        let new_va = match self.mmap_preserving_prot(
            hint,
            new_size,
            src_vma.prot,
            src_vma.may_prot,
            src_vma.flags,
            moved_backing,
            fixed,
        ) {
            Ok(v) => v,
            Err(e) => { remap_failed(watch); return Err(e); }
        };
        // Migrate DIRTY private data: the dest's own demand-faults refill
        // clean pages from the (preserved) backing, but pages the process
        // already wrote exist only in the source's private frames. Byte-copy
        // through user VAs — only when the mapping is writable (an RO
        // mapping cannot hold private dirty data; writing the dest would
        // fault a read-only PTE at CPL=0).
        if src_vma.prot.contains(VmaProt::WRITE) {
            #[cfg(not(test))]
            {
                let copy_len = core::cmp::min(old_size, new_size);
                let dst = new_va.as_u64();
                // SAFETY: both regions live in the caller's AS, validated by mmap/munmap above; CPL=0 reads/writes through the caller's active PT.
                unsafe {
                    for i in 0..copy_len {
                        let v = core::ptr::read_volatile((old.as_u64() + i as u64) as *const u8);
                        core::ptr::write_volatile((dst + i as u64) as *mut u8, v);
                    }
                }
            }
        }
        let _ = self.munmap(old, old_size);
        // The move is complete before the monitor is told, and the monitor is
        // told before the caller returns: the mapping is never observable at
        // its new address by anyone the monitor has not yet heard about.
        self.remap_done(watch, old.as_u64(), new_va.as_u64(), old_size as u64);
        Ok(new_va)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicI32, AtomicU64, Ordering};

    use crate::uffd::{UffdContext, UffdEvent, UffdEventKind, UffdFaultKind};
    use crate::vma::VmaBacking;

    const REGION: u64 = 0x1_0000;
    const LEN: u64 = 4 * hal::PAGE_SIZE_BYTES;

    /// A monitor that records what it was charged and told.
    struct Mock {
        tracks: bool,
        charged: AtomicI32,
        seen: AtomicI32,
        from: AtomicU64,
        to: AtomicU64,
        len: AtomicU64,
    }

    impl Mock {
        fn new(tracks: bool) -> Arc<Self> {
            Arc::new(Mock { tracks, charged: AtomicI32::new(0), seen: AtomicI32::new(0),
                            from: AtomicU64::new(0), to: AtomicU64::new(0), len: AtomicU64::new(0) })
        }
    }

    impl UffdContext for Mock {
        fn fault(&self, _a: u64, _k: UffdFaultKind, _w: bool, _u: bool) -> bool { true }
        fn wants_event(&self, kind: UffdEventKind) -> bool {
            self.tracks && kind == UffdEventKind::Remap
        }
        fn change_begin(&self) { self.charged.fetch_add(1, Ordering::AcqRel); }
        fn change_complete(&self, ev: UffdEvent) {
            if let UffdEvent::Remap { from, to, len } = ev {
                self.from.store(from, Ordering::Release);
                self.to.store(to, Ordering::Release);
                self.len.store(len, Ordering::Release);
            }
            self.seen.fetch_add(1, Ordering::AcqRel);
            self.charged.fetch_sub(1, Ordering::AcqRel);
        }
        fn change_abort(&self) { self.charged.fetch_sub(1, Ordering::AcqRel); }
    }

    fn mk(tracks: bool) -> (Arc<AddressSpace>, Arc<Mock>) {
        let mm = AddressSpace::new(0).expect("AS::new");
        mm.mmap(Some(UserVirtAddr::new(REGION).expect("va")), LEN as usize,
                VmaProt::READ | VmaProt::WRITE,
                VmaFlags::PRIVATE | VmaFlags::ANONYMOUS,
                VmaBacking::Anonymous, true).expect("mmap");
        let ctx = Mock::new(tracks);
        let dynctx: Arc<dyn UffdContext> = ctx.clone();
        mm.set_uffd(REGION, REGION + LEN, dynctx, VmaFlags::UFFD_MISSING);
        (mm, ctx)
    }

    /// A move tells a tracking monitor WHERE the mapping went, with the length
    /// that moved, and takes the registration to the destination. Announcing
    /// without re-arming leaves every later resolve aimed at memory the mapping
    /// no longer occupies; re-arming without announcing leaves the monitor
    /// resolving at an address it still believes is the mapping's.
    #[test]
    fn a_move_announces_the_destination_and_carries_the_registration_to_it() {
        let (mm, ctx) = mk(true);
        let old = UserVirtAddr::new(REGION).expect("va");
        let new = mm.mremap(old, LEN as usize, (LEN * 2) as usize, true, false, None)
            .expect("mremap");
        assert_eq!(ctx.seen.load(Ordering::Acquire), 1, "exactly one announcement");
        assert_eq!(ctx.from.load(Ordering::Acquire), REGION);
        assert_eq!(ctx.to.load(Ordering::Acquire), new.as_u64());
        assert_eq!(ctx.len.load(Ordering::Acquire), LEN, "the length that moved");
        assert_eq!(ctx.charged.load(Ordering::Acquire), 0, "the charge is released");
        assert!(mm.uffd_for(new).is_some(), "the registration follows the mapping");
    }

    /// A monitor that does not track moves is neither charged nor told, and its
    /// registration is dropped with the old mapping rather than silently
    /// re-pointed at an address it has no record of.
    #[test]
    fn a_move_leaves_a_monitor_that_does_not_track_moves_untouched() {
        let (mm, ctx) = mk(false);
        let old = UserVirtAddr::new(REGION).expect("va");
        let new = mm.mremap(old, LEN as usize, (LEN * 2) as usize, true, false, None)
            .expect("mremap");
        assert_eq!(ctx.seen.load(Ordering::Acquire), 0);
        assert_eq!(ctx.charged.load(Ordering::Acquire), 0);
        assert!(mm.uffd_for(new).is_none());
    }

    /// A move that never happens releases its charge. Without the abandon arm
    /// the context would refuse every later resolve forever, on the strength of
    /// a change that did not occur.
    #[test]
    fn a_move_that_fails_releases_its_charge() {
        let (mm, ctx) = mk(true);
        let old = UserVirtAddr::new(REGION).expect("va");
        // A fixed move onto an address that cannot be placed.
        let huge = usize::MAX / 2;
        let r = mm.mremap(old, LEN as usize, huge, true, false, None);
        assert!(r.is_err(), "the move must fail for this test to mean anything");
        assert_eq!(ctx.seen.load(Ordering::Acquire), 0, "nothing to announce");
        assert_eq!(ctx.charged.load(Ordering::Acquire), 0, "and nothing left charged");
    }

    /// An in-place shrink is not a move: there is no destination to announce
    /// and the registration does not go anywhere.
    #[test]
    fn an_in_place_shrink_announces_nothing() {
        let (mm, ctx) = mk(true);
        let old = UserVirtAddr::new(REGION).expect("va");
        let same = mm.mremap(old, LEN as usize, (LEN / 2) as usize, true, false, None)
            .expect("shrink");
        assert_eq!(same.as_u64(), REGION);
        assert_eq!(ctx.seen.load(Ordering::Acquire), 0);
        assert_eq!(ctx.charged.load(Ordering::Acquire), 0);
    }
}
