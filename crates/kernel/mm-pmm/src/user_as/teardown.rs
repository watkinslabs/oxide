use super::*;

/// Opt-in (`debug-fwm`) free-while-mapped backstop for AS teardown. If a leaf
/// frame with refcount<=1 (the dec below would FREE it) is still mapped by a
/// PEER address space, its refcount was under-counted (a map-time inc_ref that
/// never ran; the frame's own mapcount is 0 too, so the cheap same-frame guard
/// in `release_frame_on_zero` can't see it — only a scan of other ASes can).
/// Repair the counts so the dec lands above zero and the frame SURVIVES until
/// its true last mapper drops, and log the under-count so the missing inc_ref
/// can be root-caused. DIAG ONLY: the scan is one 4-level PT walk per live AS
/// per at-risk leaf — an O(pages·ASes) exit cost — so it is gated off by
/// default. The always-on never-free-a-mapped-page invariant is the cheap
/// own-mapcount check in `release_frame_on_zero`.
/// # C: O(live_ASes) page-table walks
#[cfg(feature = "debug-fwm")]
fn fwm_teardown_backstop(va: u64, pa: u64, root_pa: u64, hhdm: u64) {
    let rc = crate::setup::frame_refcount(pa);
    if rc <= 1 {
        let peers = crate::setup::fwm_peer_maps(va, pa, root_pa, hhdm);
        if peers > 0 {
            klog::write_raw(b"[FWM-REPAIR] under-counted frame still mapped by peer: va=");
            klog::write_hex_u64(va);
            klog::write_raw(b" pa=");     klog::write_hex_u64(pa);
            klog::write_raw(b" rc=");     klog::write_dec_u64(rc as u64);
            klog::write_raw(b" peers=");  klog::write_dec_u64(peers as u64);
            klog::write_raw(b" exiting_root="); klog::write_hex_u64(root_pa);
            klog::write_raw(b" -> counts repaired to "); klog::write_dec_u64((peers + 1) as u64);
            klog::write_raw(b"\n");
            // SAFETY: fwm_peer_maps just proved `peers` other ASes map `pa`.
            unsafe { crate::setup::repair_frame_counts(pa, (peers + 1) as u32); }
        }
    }
}

#[cfg(target_arch = "x86_64")]
pub unsafe extern "C" fn as_teardown(root_pa: u64) {
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    #[cfg(feature = "debug-arm-mprotect")]
    crate::arm_mprotect_trace::checkpoint(root_pa);
    // debug-atexit: the dec context for note_final_free — as_teardown runs
    // in the REAPER's task context, so current-mm is the wrong identity;
    // the dying AS root is the honest one. UP single-threaded teardown.
    #[cfg(feature = "debug-atexit")]
    crate::setup::set_dec_ctx(root_pa);
    // SAFETY: per fn contract; HHDM covers PT memory; root quiesced.
    // F157: leaves go through dec_and_maybe_free so COW-shared frames
    // (multiple AS map them) only release once the last AS drops.
    // Tables (intermediate PT levels) are always per-AS — direct free.
    let mut free_leaf = |_va: u64, pa: u64| {
        // Opt-in free-while-mapped backstop (debug-fwm); the always-on invariant
        // is the cheap own-mapcount check in release_frame_on_zero.
        #[cfg(feature = "debug-fwm")]
        fwm_teardown_backstop(_va, pa, root_pa, hhdm);
        // SAFETY: `pa` was a leaf reachable from this AS's PT; the rmap-aware
        // release keeps a fork-shared frame's anon-vma edge until its final PTE.
        unsafe { crate::setup::rmap_aware_dec_and_maybe_free(pa); }
    };
    // A swapped leaf owns no RAM frame, but it still owns one canonical swap
    // reference and its memcg charge.  AS teardown is the final PTE zap path.
    let mut free_swap = |_va: u64, entry: hal::pt_walker::SwapEntry| {
        vmm::swap_pte_teardown(root_pa);
        let _ = crate::swap::free_page(entry);
    };
    // A migration marker owns neither a RAM PTE reference nor a swap-slot
    // reference.  It only participates in its in-flight transaction; report
    // teardown so that transaction can finish once all markers are gone.
    let mut free_migration = |_va: u64, entry: hal::pt_walker::MigrationEntry| {
        if let Some(pa) = vmm::migration_drop_marker_mapping(entry) {
            // SAFETY: AS teardown removes exactly the PTE represented by this marker.
            unsafe { crate::setup::rmap_aware_dec_and_maybe_free(pa); }
        }
    };
    let mut free_table = |pa: u64| {
        // SAFETY: PT tables are always private to this AS; free directly.
        unsafe { crate::setup::free_one_frame(pa); }
    };
    // SAFETY: per fn contract; HHDM covers PT memory; root quiesced.
    unsafe {
        hal::pt_walker::free_user_tree_leafmap::<hal_x86_64::vmm::PtWalkerX86, _, _, _, _>(
            root_pa, hhdm, &mut free_leaf, &mut free_swap, &mut free_migration, &mut free_table,
        );
    }
    // Free the root frame itself.
    // SAFETY: root_pa is the AS-private root; no longer reachable.
    unsafe { crate::setup::free_one_frame(root_pa); }
    #[cfg(feature = "debug-atexit")]
    crate::setup::set_dec_ctx(0);
}

/// aarch64 mirror of `as_teardown`.
#[cfg(target_arch = "aarch64")]
pub unsafe extern "C" fn as_teardown(root_pa: u64) {
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    #[cfg(feature = "debug-arm-mprotect")]
    crate::arm_mprotect_trace::checkpoint(root_pa);
    // debug-atexit: the dec context for note_final_free — as_teardown runs
    // in the REAPER's task context, so current-mm is the wrong identity;
    // the dying AS root is the honest one. UP single-threaded teardown.
    #[cfg(feature = "debug-atexit")]
    crate::setup::set_dec_ctx(root_pa);
    // SAFETY: per fn contract; HHDM covers PT memory; root quiesced.
    let mut free_leaf = |_va: u64, pa: u64| {
        // Opt-in free-while-mapped backstop (debug-fwm); mirror of x86_64 above.
        #[cfg(feature = "debug-fwm")]
        fwm_teardown_backstop(_va, pa, root_pa, hhdm);
        // SAFETY: leaf was reachable from this AS's PT; preserve rmap until
        // the final fork-shared PTE release, mirroring the x86 path.
        unsafe { crate::setup::rmap_aware_dec_and_maybe_free(pa); }
    };
    // AS teardown owns the final swap-PTE references just as it owns final
    // resident PTE references; release their canonical slots before tables go.
    let mut free_swap = |_va: u64, entry: hal::pt_walker::SwapEntry| {
        vmm::swap_pte_teardown(root_pa);
        let _ = crate::swap::free_page(entry);
    };
    let mut free_migration = |_va: u64, entry: hal::pt_walker::MigrationEntry| {
        if let Some(pa) = vmm::migration_drop_marker_mapping(entry) {
            // SAFETY: mirror of x86 teardown above.
            unsafe { crate::setup::rmap_aware_dec_and_maybe_free(pa); }
        }
    };
    let mut free_table = |pa: u64| {
        // SAFETY: PT tables are always per-AS; direct free.
        unsafe { crate::setup::free_one_frame(pa); }
    };
    // SAFETY: per fn contract; HHDM covers PT memory; root quiesced.
    unsafe {
        hal::pt_walker::free_user_tree_leafmap::<hal_aarch64::vmm::PtWalkerArm, _, _, _, _>(
            root_pa, hhdm, &mut free_leaf, &mut free_swap, &mut free_migration, &mut free_table,
        );
    }
    // SAFETY: root_pa is the AS-private root; no longer reachable.
    unsafe { crate::setup::free_one_frame(root_pa); }
}

/// Convenience wrapper: install `as_teardown` on a freshly-built AS.
/// Boot-anchor + hosted-test code paths SHOULD NOT call this — their
/// roots are either fake (test) or shared kernel state (boot).
/// # C: O(1)
pub fn install_teardown(as_: &Arc<AddressSpace>) {
    as_.set_teardown(as_teardown);
}

/// Translate Linux `PROT_*` bits (per `15§6.2`) to `VmaProt`.
/// # C: O(1)
pub fn prot_from_linux(prot: u64) -> VmaProt {
    let mut p = VmaProt::empty();
    if prot & 0x1 != 0 { p |= VmaProt::READ;  }
    if prot & 0x2 != 0 { p |= VmaProt::WRITE; }
    if prot & 0x4 != 0 { p |= VmaProt::EXEC;  }
    p
}

/// Decode an x86_64 `#PF` error code into a `FaultKind` per Intel
/// SDM Vol. 3 §6.15 / `11§5`. Returns `None` if the fault is not
/// from a user-half VA (kernel-mode fault on user-space data — not
/// a demand-page case here).
/// # C: O(1)
#[cfg(target_arch = "x86_64")]
pub fn classify_x86_pf(err: u64, cr2: u64) -> Option<FaultKind> {
    if cr2 >= USER_VA_END {
        return None;
    }
    // err bit 0 (P): 1 = protection, 0 = not-present.
    // err bit 1 (W): 1 = write, 0 = read.
    // err bit 4 (I): 1 = instruction fetch (exec attempt).
    let access = if err & 0x10 != 0 {
        FaultAccess::Exec
    } else if err & 0x02 != 0 {
        FaultAccess::Write
    } else {
        FaultAccess::Read
    };
    if err & 0x01 == 0 {
        Some(FaultKind::NotPresent { access })
    } else {
        Some(FaultKind::Protection { access })
    }
}

/// Decode an aarch64 ESR for a sync-from-lower-EL data/instruction
/// abort into a `FaultKind` per ARM ARM D13.2.40 / `11§5`. Returns
/// `None` if the fault wasn't from EL0 user space.
/// # C: O(1)
#[cfg(target_arch = "aarch64")]
pub fn classify_arm_abort(esr: u64, far: u64) -> Option<FaultKind> {
    if far >= USER_VA_END {
        return None;
    }
    let ec = (esr >> 26) & 0x3F;
    // EC = 0x24 data-abort-lower-el; 0x20 insn-abort-lower-el.
    // EC = 0x25 data-abort-same-el; 0x21 insn-abort-same-el.
    // Same-EL aborts arrive when the kernel reads/writes a user VA
    // (e.g. write(2) copies user buffer); demand-paging applies the
    // same way as lower-EL aborts.
    let access = match ec {
        0x20 | 0x21 => FaultAccess::Exec,
        0x24 | 0x25 => {
            // ISS bit 6 = WnR: 0=read, 1=write.
            if esr & (1 << 6) != 0 { FaultAccess::Write } else { FaultAccess::Read }
        }
        _ => return None,
    };
    // DFSC (ISS bits 5..0): 0x04..0x07 = translation fault L0..L3.
    let dfsc = esr & 0x3F;
    if (0x04..=0x07).contains(&dfsc) {
        Some(FaultKind::NotPresent { access })
    } else {
        // Permission fault, alignment, etc → protection class.
        Some(FaultKind::Protection { access })
    }
}
