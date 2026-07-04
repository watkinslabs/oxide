// --- double-free diagnostic (temporary) --------------------------------
//
// A lock-free ring of (pfn → caller `Location`) for every order-0 frame
// free. `free()` and the free primitives are `#[track_caller]`, so the
// recorded `Location` is the ORIGINAL freeing call-site (teardown leaf vs
// COW dec_ref vs munmap, …), not the buddy method. On a bitmap-detected
// double free we dump the prior free's site(s) for that pfn + the current
// site, so the panic line names BOTH paths that freed the same frame.
// Remove once the teardown double-free is root-caused.

// Real implementation under `debug-pmm`; no-op stubs otherwise (so the
// `free()` call sites stay cfg-free and `loc` is always "used"). Enable with
// `make qemu-x86 FEATURES=debug-pmm` to capture the double-free culprit.

#[cfg(feature = "debug-pmm")]
mod df {
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    /// Free-history ring capacity (recent order-0 frees). # C: const.
    const DF_CAP: usize = 1024;
    static DF_PFN: [AtomicU64; DF_CAP] = [const { AtomicU64::new(u64::MAX) }; DF_CAP];
    static DF_LOC: [AtomicUsize; DF_CAP] = [const { AtomicUsize::new(0) }; DF_CAP];
    static DF_HEAD: AtomicUsize = AtomicUsize::new(0);

    /// Record a frame free: `pfn` freed at `loc` (original caller). # C: O(1).
    pub fn note(pfn: u64, loc: &'static core::panic::Location<'static>) {
        let i = DF_HEAD.fetch_add(1, Ordering::Relaxed) % DF_CAP;
        DF_PFN[i].store(pfn, Ordering::Relaxed);
        DF_LOC[i].store(loc as *const _ as usize, Ordering::Relaxed);
    }

    /// Print one stored `Location` (file:line). # C: O(len).
    fn print_loc(raw: usize) {
        if raw == 0 { klog::write_raw(b"<?>"); return; }
        // SAFETY: raw was stored from a `&'static Location` in note(); the
        // ring only holds 'static Location pointers, valid for the kernel life.
        let loc: &'static core::panic::Location = unsafe { &*(raw as *const core::panic::Location) };
        klog::write_raw(loc.file().as_bytes());
        klog::write_raw(b":");
        klog::write_dec_u64(loc.line() as u64);
    }

    /// Dump every prior recorded free of `pfn` when a double free is caught:
    /// names the FIRST freer (the path that left the frame inconsistent).
    /// # C: O(DF_CAP).
    pub fn dump(pfn: u64, cur: &'static core::panic::Location<'static>) {
        klog::write_raw(b"\n[PMM-DF] DOUBLE FREE of pfn=");
        klog::write_hex_u64(pfn);
        klog::write_raw(b"\n[PMM-DF]   this (2nd) free at: ");
        print_loc(cur as *const _ as usize);
        klog::write_raw(b"\n[PMM-DF]   prior free(s) of this pfn:\n");
        let mut found = false;
        for i in 0..DF_CAP {
            if DF_PFN[i].load(Ordering::Relaxed) == pfn {
                klog::write_raw(b"[PMM-DF]     - ");
                print_loc(DF_LOC[i].load(Ordering::Relaxed));
                klog::write_raw(b"\n");
                found = true;
            }
        }
        if !found { klog::write_raw(b"[PMM-DF]     (none in ring - freed >1024 frees ago)\n"); }
    }
}

/// Record an order-0 frame free into the diagnostic ring (no-op without
/// `debug-pmm`). # C: O(1).
#[inline]
pub(super) fn df_note(pfn: u64, loc: &'static core::panic::Location<'static>) {
    #[cfg(feature = "debug-pmm")]
    df::note(pfn, loc);
    #[cfg(not(feature = "debug-pmm"))]
    { let _ = (pfn, loc); }
}

/// Dump the double-free culprit chain (no-op without `debug-pmm`). # C: O(N).
#[inline]
pub(super) fn df_dump(pfn: u64, cur: &'static core::panic::Location<'static>) {
    #[cfg(feature = "debug-pmm")]
    df::dump(pfn, cur);
    #[cfg(not(feature = "debug-pmm"))]
    { let _ = (pfn, cur); }
}
