use super::*;

#[cfg(target_arch = "x86_64")]
pub unsafe extern "C" fn as_teardown(root_pa: u64) {
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
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
        // debug-fwm (LIGHT): only check refcount-1 frames in the high
        // library/lock VA window (≥0x7000_0000_0000) — where the free-while-
        // mapped corruption lands (libc/systemd .data, glibc locks). Skipping
        // bulk heap/stack frames keeps teardown cheap (no boot regression).
        #[cfg(feature = "debug-fwm")]
        if _va >= 0x7000_0000_0000 && crate::setup::frame_refcount(pa) == 1 {
            let n = crate::setup::fwm_peer_maps(_va, pa, root_pa, hhdm);
            if n > 0 {
                klog::write_raw(b"[FWM] teardown va="); klog::write_hex_u64(_va);
                klog::write_raw(b" pa=");               klog::write_hex_u64(pa);
                klog::write_raw(b" peers=");            klog::write_dec_u64(n as u64);
                klog::write_raw(b" exiting_root=");     klog::write_hex_u64(root_pa);
                klog::write_raw(b"\n");
            }
        }
        // SAFETY: `pa` was a leaf reachable from this AS's PT; AS root
        // quiesced per fn contract; crate::setup::dec_and_maybe_free drops
        // refcount and frees on zero.
        unsafe { crate::setup::dec_and_maybe_free_frame(pa); }
    };
    let mut free_table = |pa: u64| {
        // SAFETY: PT tables are always private to this AS; free directly.
        unsafe { crate::setup::free_one_frame(pa); }
    };
    // SAFETY: per fn contract; HHDM covers PT memory; root quiesced.
    unsafe {
        hal::pt_walker::free_user_tree_leafmap::<hal_x86_64::vmm::PtWalkerX86, _, _>(
            root_pa, hhdm, &mut free_leaf, &mut free_table,
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
    // debug-atexit: the dec context for note_final_free — as_teardown runs
    // in the REAPER's task context, so current-mm is the wrong identity;
    // the dying AS root is the honest one. UP single-threaded teardown.
    #[cfg(feature = "debug-atexit")]
    crate::setup::set_dec_ctx(root_pa);
    // SAFETY: per fn contract; HHDM covers PT memory; root quiesced.
    let mut free_leaf = |_va: u64, pa: u64| {
        // SAFETY: leaf was reachable from this AS's PT; F157 dec-and-free.
        unsafe { crate::setup::dec_and_maybe_free_frame(pa); }
    };
    let mut free_table = |pa: u64| {
        // SAFETY: PT tables are always per-AS; direct free.
        unsafe { crate::setup::free_one_frame(pa); }
    };
    // SAFETY: per fn contract; HHDM covers PT memory; root quiesced.
    unsafe {
        hal::pt_walker::free_user_tree_leafmap::<hal_aarch64::vmm::PtWalkerArm, _, _>(
            root_pa, hhdm, &mut free_leaf, &mut free_table,
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

/// Per-arch fault handler installed by `kernel_main`. v1 handles
/// only `NotPresent` on Anonymous + KernelBytes VMAs (demand-paging
/// path). Returns true if the fault was resolved (caller retries
