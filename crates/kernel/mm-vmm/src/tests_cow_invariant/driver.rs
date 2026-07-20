use super::*;

// ---- harness driver ----

pub(super) struct Xorshift(u64);
impl Xorshift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        self.0 = x; x
    }
    fn pick(&mut self, n: usize) -> usize { (self.next() % n as u64) as usize }
}

#[derive(Clone, Copy, PartialEq)]
pub(super) enum Kind { Anon, FilePriv, FileShared, ShmemAnon, KernelBytes }

pub(super) struct AsSlot {
    pub(super) root: u64,
    pub(super) mm: Arc<AddressSpace>,
}

/// Enumerate a random page VA inside any VMA of `mm`. Returns (va, prot_w).
pub(super) fn pick_page(mm: &AddressSpace, rng: &mut Xorshift) -> Option<(u64, bool)> {
    let tree = mm.vmas_for_test();
    let vmas: Vec<(u64, u64, bool)> = tree.iter()
        .map(|v| (v.start.as_u64(), v.end.as_u64(), v.prot.contains(VmaProt::WRITE)))
        .collect();
    if vmas.is_empty() { return None; }
    let (s, e, w) = vmas[rng.pick(vmas.len())];
    let npages = ((e - s) / PAGE).max(1);
    let va = s + (rng.next() % npages) * PAGE;
    Some((va, w))
}

pub(super) fn pte_at(root: u64, va: u64) -> Option<(u64, u64)> {
    ROOTS.with(|r| r.borrow().get(&root).and_then(|m| m.get(&va).copied()))
}

pub(super) const COW_WRITE: FaultKind = FaultKind::Protection { access: FaultAccess::Write };
pub(super) const DEMAND_WRITE: FaultKind = FaultKind::NotPresent { access: FaultAccess::Write };
pub(super) const DEMAND_READ: FaultKind = FaultKind::NotPresent { access: FaultAccess::Read };

/// Drive one fault (demand or COW) at `va` in the active AS.
pub(super) fn do_fault(mm: &AddressSpace, va: u64, fault: FaultKind) {
    let uva = match hal::UserVirtAddr::new(va) { Some(u) => u, None => return };
    // SAFETY: hosted harness; MultiMmu active root set to `mm`; closures mirror
    // the kernel fault dispatcher's real inc/dec/refcount/alloc/rmap wiring.
    let _ = unsafe {
        mm.handle_page_fault_cow_rmap::<MultiMmu, _, _, _, _, _, _, _, _>(
            uva, fault, 0,
            alloc_frame,
            rc_get,
            rc_dec,
            // A4 set_rmap: record the page's real AnonVma family + mark it
            // born-exclusive (A3), mirroring `set_anon_rmap_for_pa`.
            |pa, av, _idx| {
                RMAP.with(|r| { r.borrow_mut().insert(pa, Arc::clone(av)); });
                EXCL.with(|r| { r.borrow_mut().insert(pa); });
            },
            rc_inc,
            // A3 wp_page_reuse predicate: anon (rmap-tracked) && exclusive &&
            // mapcount==1 — the exact `can_reuse_anon_exclusive` conjuncts.
            |pa| EXCL.with(|e| e.borrow().contains(&pa))
                && MC.with(|m| *m.borrow().get(&pa).unwrap_or(&0)) == 1
                && RMAP.with(|r| r.borrow().contains_key(&pa)),
            || Ok(()),
            || {},
        )
    };
}

/// Model `glue_munmap`: unmap-then-dec each present leaf in [addr,addr+len),
/// then drop the VMA bookkeeping.
pub(super) fn do_munmap(slot: &AsSlot, addr: u64, len: u64) {
    activate(slot.root);
    let pages: Vec<(u64, u64)> = ROOTS.with(|r| {
        r.borrow().get(&slot.root).map(|m| {
            m.iter().filter(|(va, _)| **va >= addr && **va < addr + len)
                .map(|(va, (pa, _))| (*va, *pa & !(PAGE - 1))).collect()
        }).unwrap_or_default()
    });
    for (va, pa) in pages {
        // SAFETY: hosted; unmap-before-dec per glue_munmap leaf order.
        unsafe { MultiMmu::unmap(Va(va), PageSize::P4K); }
        rc_dec(pa);
    }
    if let Some(a) = hal::UserVirtAddr::new(addr) {
        let _ = slot.mm.munmap(a, len as usize);
    }
}

/// Model `as_teardown`: dec every present user leaf, drop the root.
pub(super) fn do_exit(slot: &AsSlot) {
    let pages: Vec<u64> = ROOTS.with(|r| {
        r.borrow().get(&slot.root).map(|m| m.values().map(|(pa, _)| *pa & !(PAGE - 1)).collect())
            .unwrap_or_default()
    });
    for pa in pages { rc_dec(pa); }
    ROOTS.with(|r| { r.borrow_mut().remove(&slot.root); });
}

pub(super) fn map_region(slot: &AsSlot, kind: Kind, len: u64) {
    let (prot, flags, backing) = match kind {
        Kind::Anon => (
            VmaProt::READ | VmaProt::WRITE,
            VmaFlags::PRIVATE | VmaFlags::ANONYMOUS,
            VmaBacking::Anonymous),
        Kind::FilePriv => (
            VmaProt::READ | VmaProt::WRITE,
            VmaFlags::PRIVATE,
            VmaBacking::File { backing: Arc::new(PrivFileBacking), off: 0 }),
        Kind::FileShared => (
            VmaProt::READ | VmaProt::WRITE,
            VmaFlags::SHARED,
            VmaBacking::File { backing: Arc::new(MemfdBacking), off: 0 }),
        // MM5: MAP_SHARED|MAP_ANON as the FIXED mmap builds it — an anonymous
        // shmem backing (Linux `shmem_zero_setup`). SHARED|ANONYMOUS flags +
        // a File backing so `fork_cow_pages` shares the frames (no COW split).
        Kind::ShmemAnon => (
            VmaProt::READ | VmaProt::WRITE,
            VmaFlags::SHARED | VmaFlags::ANONYMOUS,
            VmaBacking::File { backing: Arc::new(MemfdBacking), off: 0 }),
        Kind::KernelBytes => {
            let data: Arc<[u8]> = Arc::from(std::vec![0xABu8; len as usize].into_boxed_slice());
            (VmaProt::READ | VmaProt::WRITE,
             VmaFlags::PRIVATE,
             VmaBacking::KernelBytes { data, off: 0 })
        }
    };
    let _ = slot.mm.mmap(None, len as usize, prot, flags, backing, false);
}

/// The core randomized invariant test. `seed` + `iters` parametrize the run.
pub(super) fn run(seed: u64, iters: usize) {
    reset();
    let mut rng = Xorshift(seed);
    let mut next_root: u64 = 0x1_0000_0000;
    let mut slots: Vec<AsSlot> = Vec::new();

    // Seed with a couple of root ASes carrying a mix of backings.
    for _ in 0..2 {
        let root = next_root; next_root += 0x1000_0000;
        let mm = AddressSpace::new(root).expect("AS::new");
        let s = AsSlot { root, mm };
        map_region(&s, Kind::Anon, 8 * PAGE);
        map_region(&s, Kind::FilePriv, 4 * PAGE);
        map_region(&s, Kind::FileShared, 4 * PAGE);
        map_region(&s, Kind::ShmemAnon, 4 * PAGE);
        map_region(&s, Kind::KernelBytes, 4 * PAGE);
        slots.push(s);
    }

    for i in 0..iters {
        if slots.is_empty() {
            let root = next_root; next_root += 0x1000_0000;
            let mm = AddressSpace::new(root).expect("AS::new");
            let s = AsSlot { root, mm };
            map_region(&s, Kind::Anon, 8 * PAGE);
            slots.push(s);
        }
        let op = rng.pick(100);
        let si = rng.pick(slots.len());
        let root = slots[si].root;
        match op {
            // ---- fault (demand or COW) ----
            0..=44 => {
                activate(root);
                if let Some((va, w)) = pick_page(&slots[si].mm, &mut rng) {
                    match pte_at(root, va) {
                        None => {
                            let f = if w && rng.pick(2) == 0 { DEMAND_WRITE } else { DEMAND_READ };
                            do_fault(&slots[si].mm, va, f);
                        }
                        Some((_, flags)) => {
                            // Present: a write to a W-stripped page triggers COW.
                            let pf = PageFlags::from_bits_truncate(flags);
                            if w && !pf.contains(PageFlags::WRITE) {
                                do_fault(&slots[si].mm, va, COW_WRITE);
                            }
                        }
                    }
                }
            }
            // ---- fork (any AS -> child; covers fork-of-child) ----
            45..=69 => {
                if slots.len() < 64 {
                    activate(root);
                    let child_root = next_root; next_root += 0x1000_0000;
                    if let Ok(child) = slots[si].mm
                        .fork_cow_pages::<MultiMmu, _>(child_root, 0, rc_inc)
                    {
                        slots.push(AsSlot { root: child_root, mm: child });
                    }
                }
            }
            // ---- munmap one page ----
            70..=84 => {
                if let Some((va, _)) = pick_page(&slots[si].mm, &mut rng) {
                    do_munmap(&slots[si], va, PAGE);
                }
            }
            // ---- exit an AS ----
            85..=99 => {
                if slots.len() > 1 {
                    let s = slots.swap_remove(si);
                    do_exit(&s);
                    drop(s.mm);
                }
            }
            _ => unreachable!(),
        }
        check_invariant("op");
        BUG.with(|b| {
            if let Some(msg) = b.borrow().as_ref() {
                panic!("seed={:#x} iter={} op={}: {}", seed, i, op, msg);
            }
        });
    }

    // Drain: exit every remaining AS; invariant must hold at each step and
    // all non-base frames must end freed (refcount 0).
    while let Some(s) = slots.pop() {
        do_exit(&s);
        check_invariant("drain");
        BUG.with(|b| {
            if let Some(msg) = b.borrow().as_ref() { panic!("drain: {}", msg); }
        });
    }
}
