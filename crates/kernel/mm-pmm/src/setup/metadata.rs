use super::*;

static PAGE_META_PTR: core::sync::atomic::AtomicPtr<crate::PageMetaArr>
    = core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

pub fn init_page_meta(pfn_max: u64) {
    use core::sync::atomic::Ordering;
    if pfn_max == 0 { return; }
    if !PAGE_META_PTR.load(Ordering::Acquire).is_null() { return; }
    let n = pfn_max as usize;
    let mut v: alloc::vec::Vec<crate::PageMeta>
        = alloc::vec::Vec::with_capacity(n);
    for _ in 0..n { v.push(crate::PageMeta::new()); }
    let leaked: &'static [crate::PageMeta] =
        alloc::boxed::Box::leak(v.into_boxed_slice());
    let arr = crate::PageMetaArr::new(0, leaked);
    let arr_box = alloc::boxed::Box::new(arr);
    let raw = alloc::boxed::Box::leak(arr_box) as *mut _;
    PAGE_META_PTR.store(raw, Ordering::Release);
    // debug-cow probe 1: size the allocated-frame shadow bitmap to the same
    // [0, pfn_max) span as the PageMeta array, so every frame the buddy can
    // hand out has a tracking bit. Idempotent.
    #[cfg(feature = "debug-cow")]
    alloc_integrity::init(pfn_max);
}

/// F156-rmap: install the AnonVma reference for a frame. Mirrors
/// Linux `page_add_anon_rmap` shape — the page now belongs to that
/// anon-VMA family, with `page_index` as the page offset within the
/// originating VMA. Bumps the AnonVma's strong count via
/// `Arc::into_raw` and stashes the raw pointer in `PageMeta.mapping`.
/// If a previous AnonVma was bound it gets dropped (rare path:
/// re-bind on a recycled frame; the dec_and_maybe_free path normally
/// clears mapping before the frame is reused).
///
/// # SAFETY: `pa` is a live PMM-allocated frame whose PageMeta slot
/// belongs to the caller's mapping; `av` is alive at call time.
/// # C: O(1)
pub unsafe fn set_anon_rmap_for_pa(
    pa: u64,
    av: &alloc::sync::Arc<vmm::AnonVma>,
    page_index: u32,
) {
    let meta = match page_meta() { Some(m) => m, None => return };
    let pfn = hal::Pfn(pa / hal::PAGE_SIZE_BYTES);
    let raw = alloc::sync::Arc::into_raw(alloc::sync::Arc::clone(av)) as *mut ();
    if let Some(prev) = meta.swap_mapping(pfn, raw) {
        if !prev.is_null() {
            // SAFETY: previous slot was set via set_anon_rmap_for_pa's
            // Arc::into_raw; reclaiming and dropping it balances that
            // strong-count bump.
            unsafe { drop(alloc::sync::Arc::from_raw(prev as *const vmm::AnonVma)); }
        }
    }
    let _ = meta.set_page_index(pfn, page_index);
    // F157-A3 (Linux `page_add_new_anon_rmap` -> the folio is born
    // exclusive): `set_anon_rmap_for_pa` is called exactly at the two
    // sites that mint a freshly-owned anon frame — the do_anonymous_page
    // zero-fill and the COW-copy destination — and only for VMAs that
    // carry an anon_vma (`VmaBacking::Anonymous`). Both produce a page
    // mapped by exactly one writable owner, so mark it ANON +
    // ANON_EXCLUSIVE. The exclusivity is revoked later by `inc_ref` the
    // moment a fork shares it.
    let _ = meta.set_flags(pfn, crate::PageFlags::ANON | crate::PageFlags::ANON_EXCLUSIVE);
}

/// Inverse of `set_anon_rmap_for_pa`. Loads the stored raw pointer,
/// stores null, drops the Arc. Idempotent on null. Called from
/// `dec_and_maybe_free_frame` when the refcount hits zero — the
/// frame is about to return to PMM, so we must drop our chain
/// reference first or leak the AnonVma.
///
/// # SAFETY: `pa` is a frame whose mapping slot is owned by the
/// caller's flow (no concurrent reader of the slot's pointee).
/// # C: O(1)
pub unsafe fn clear_anon_rmap_for_pa(pa: u64) {
    let meta = match page_meta() { Some(m) => m, None => return };
    let pfn = hal::Pfn(pa / hal::PAGE_SIZE_BYTES);
    if let Some(prev) = meta.swap_mapping(pfn, core::ptr::null_mut()) {
        if !prev.is_null() {
            // SAFETY: prev was installed via set_anon_rmap_for_pa's
            // Arc::into_raw; we now reclaim ownership and drop.
            unsafe { drop(alloc::sync::Arc::from_raw(prev as *const vmm::AnonVma)); }
        }
    }
    let _ = meta.set_page_index(pfn, 0);
}

/// Snapshot the AnonVma stored at `pa`. Bumps the strong count so
/// the caller's clone is independent. `None` if no anon_vma is
/// bound or pre-init.
/// # C: O(1)
pub fn anon_vma_for_pa(pa: u64) -> Option<alloc::sync::Arc<vmm::AnonVma>> {
    let meta = page_meta()?;
    let pfn = hal::Pfn(pa / hal::PAGE_SIZE_BYTES);
    let raw = meta.mapping(pfn)?;
    if raw.is_null() { return None; }
    // SAFETY: raw was installed via set_anon_rmap_for_pa's into_raw;
    // increment the strong count and reconstruct an owned Arc.
    unsafe {
        alloc::sync::Arc::increment_strong_count(raw as *const vmm::AnonVma);
        Some(alloc::sync::Arc::from_raw(raw as *const vmm::AnonVma))
    }
}

/// Snapshot the page_index stored at `pa`. 0 pre-init or out-of-range.
/// # C: O(1)
pub fn page_index_for_pa(pa: u64) -> u32 {
    page_meta()
        .and_then(|m| m.page_index(hal::Pfn(pa / hal::PAGE_SIZE_BYTES)))
        .unwrap_or(0)
}

/// Count live address spaces OTHER than `exclude_root` that still map VA `va`
/// to physical frame `pa`. Used at every free-to-zero to enforce the
/// never-free-a-mapped-page invariant AUTHORITATIVELY — a frame about to return
/// to PMM while a peer task's PTE still maps it (refcount under-counted by a
/// map-time `inc_ref` that never ran). Works for ALL backings (not just anon,
/// unlike an rmap walk) by enumerating live tasks' address spaces. `hhdm` is the
/// HHDM offset for foreign-PT reads. Production (was debug-fwm): it is the
/// backstop that turns an under-count into a survivable leak instead of a
/// free-while-mapped corruption. Each probe is one 4-level walk per AS.
/// # C: O(N_tasks) — one 4-level PT walk each
#[cfg(feature = "debug-fwm")]
pub fn fwm_peer_maps(va: u64, pa: u64, exclude_root: u64, hhdm: u64) -> usize {
    let target = pa & !(hal::PAGE_SIZE_BYTES - 1);
    let tasks = match sched::registry::try_snapshot() { Some(t) => t, None => return 0 };
    let mut count = 0usize;
    let mut seen: [u64; 96] = [0; 96];
    let mut n_seen = 0usize;
    for t in tasks.iter() {
        // SAFETY: smp=1 debug detector; no other task executes during this
        // teardown, so reading a peer task's mm root is a stable read.
        let root = match unsafe { t.mm_ref() } { Some(mm) => mm.root_pa(), None => continue };
        if root == exclude_root || root == 0 { continue; }
        if seen[..n_seen].contains(&root) { continue; } // dedup threads sharing an mm
        if n_seen < seen.len() { seen[n_seen] = root; n_seen += 1; }
        // SAFETY: read-only foreign-mm PT walk; root is a live AS root frame;
        // HHDM covers page-table memory.
        #[cfg(target_arch = "x86_64")]
        let tr = unsafe { hal::pt_walker::translate_4k_at_root::<hal_x86_64::vmm::PtWalkerX86>(root, va, hhdm) };
        #[cfg(target_arch = "aarch64")]
        let tr = unsafe { hal::pt_walker::translate_4k_at_root::<hal_aarch64::vmm::PtWalkerArm>(root, va, hhdm) };
        if let Some((mapped, _)) = tr {
            if (mapped & !(hal::PAGE_SIZE_BYTES - 1)) == target { count += 1; }
        }
    }
    count
}

/// F156-rmap: drop the rmap edge before the frame returns to PMM.
/// Wraps `dec_and_maybe_free_frame` so callers that don't carry an
/// AnonVma reference still keep the chain consistent. Intended for
/// the COW split + munmap leaf-walk paths.
/// # SAFETY: same as `dec_and_maybe_free_frame`.
/// # C: O(1)
pub unsafe fn rmap_aware_dec_and_maybe_free(pa: u64) {
    // SAFETY: clear_anon_rmap_for_pa drops the Arc bound to this
    // frame's PageMeta.mapping; subsequent dec_ref handles refcount.
    unsafe { clear_anon_rmap_for_pa(pa); }
    // SAFETY: caller asserts the frame's leaf PTE has been removed.
    unsafe { dec_and_maybe_free_frame(pa); }
}

/// F157: compute pfn_max from a `BootInfo`. Used by `kernel_main` to
/// size the per-page metadata array. Same walk as
/// `init_from_boot_info`; lifted here so callers don't have to
/// touch `BootMemRegion` themselves.
/// # C: O(memmap.len)
pub fn pfn_max_from_boot_info(info: &BootInfo) -> u64 {
    if info.memmap_count == 0 { return 0; }
    // SAFETY: caller passed valid memmap_ptr/count per BootInfo contract.
    let regions: &[BootMemRegion] = unsafe {
        core::slice::from_raw_parts(info.memmap_ptr, info.memmap_count as usize)
    };
    let mut pfn_max: u64 = 0;
    for r in regions {
        if r.kind != BootMemKind::Usable { continue; }
        let end_pa = r.base_pa.saturating_add(r.len);
        let end_pfn = end_pa >> PAGE_SHIFT;
        if end_pfn > pfn_max { pfn_max = end_pfn; }
    }
    pfn_max
}

/// debug-cow: identify the current task (Linux pid == kernel tid) and CPU
/// for [COW-CORRUPT] / [COW-LEAK] attribution. Returns (0,0) pre-sched.
/// # C: O(1)
#[cfg(feature = "debug-cow")]
pub(super) fn cow_dbg_who() -> (u32, u32) {
    let tid = sched::current().map(|t| t.tid).unwrap_or(0);
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    let cpu = { use hal::CpuOps; hal_x86_64::X86CpuOps::current_cpu() };
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    let cpu = { use hal::CpuOps; hal_aarch64::ArmCpuOps::current_cpu() };
    #[cfg(not(target_os = "oxide-kernel"))]
    let cpu = 0u32;
    (tid, cpu)
}

/// debug-cow item 2: authoritative "who still maps this frame" report.
/// The O(1) mapcount check can itself be under-counted (the residual-bug
/// hypothesis), so on a [COW-LEAK] hit we walk the frame's anon_vma rmap
/// chain and PTE-verify each candidate, naming a concrete still-mapping
/// (AS-root, VA) pair: `[COW-LEAK]  still-mapped-by root=R va=V`.
/// # C: O(N_chain) page-table walks
#[cfg(feature = "debug-cow")]
pub(super) fn cow_dbg_rmap_report(pa: u64) {
    crate::user_as::rmap_walk_anon_pa(pa, |root, va| {
        klog::write_raw(b"[COW-LEAK]  still-mapped-by root="); klog::write_hex_u64(root);
        klog::write_raw(b" va="); klog::write_hex_u64(va);
        klog::write_raw(b"\n");
    });
}

/// Internal: snapshot the metadata array if installed.
/// debug-atexit: dec context root for [ARMED-DEC]/[FWM-FREE] attribution.
/// Set by as_teardown (the dying root); 0 = use the current task's mm root.
#[cfg(feature = "debug-atexit")]
static DEC_CTX: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// # C: O(1)
#[cfg(feature = "debug-atexit")]
pub fn set_dec_ctx(root: u64) { DEC_CTX.store(root, core::sync::atomic::Ordering::Release); }

/// # C: O(1)
#[cfg(feature = "debug-atexit")]
pub(super) fn dec_ctx_root() -> u64 {
    let t = DEC_CTX.load(core::sync::atomic::Ordering::Acquire);
    if t != 0 { return t; }
    sched::live::current()
        .and_then(|c| unsafe { c.mm_ref() }.map(|m| m.root_pa()))
        .unwrap_or(0)
}

pub(crate) fn page_meta() -> Option<&'static crate::PageMetaArr> {
    let p = PAGE_META_PTR.load(core::sync::atomic::Ordering::Acquire);
    if p.is_null() { return None; }
    // SAFETY: PAGE_META_PTR is set exactly once via Box::leak in
    // init_page_meta; the pointee has 'static lifetime; never freed.
    Some(unsafe { &*p })
}
