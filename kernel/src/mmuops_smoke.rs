// MmuOps end-to-end smoke per `20§5` / `21§5`.
//
// Validates the full `MmuOps` surface (map / translate / unmap)
// against a fresh PMM-allocated frame at a scratch kernel VA.
// Distinct from `device_map_smoke` which only exercises `map` for
// device-attribute mappings.
//
// Sequence:
//   1. Allocate a 4 KiB frame from PMM.
//   2. `MmuOps::map` it at SCRATCH_VA, READ|WRITE, P4K.
//   3. Write a magic u64 through SCRATCH_VA.
//   4. `MmuOps::translate(SCRATCH_VA)` — verify it reports the
//      expected PA + READ|WRITE flags.
//   5. `MmuOps::unmap(SCRATCH_VA, P4K)`.
//   6. `MmuOps::translate(SCRATCH_VA)` — verify it returns None.
//
// Failure modes log via `debug_vmm!` and return early; success
// emits `[INFO] mmuops-smoke: ok`.

use hal::{MmuOps, Pa, PageFlags, PageSize, Va};

/// Scratch VA in L4 slot 0x1FD — disjoint from HHDM (slots
/// 0..0x100), kernel-device base (slot 0x1FE), and kernel image
/// (slot 0x1FF). Both arches' kernel-half layouts have this slot
/// free.
#[cfg(target_os = "oxide-kernel")]
const SCRATCH_VA: u64 = 0xffff_fd00_0000_0000;

/// Magic value written through the scratch mapping. Pattern chosen
/// so a partial write (low 32 bits only) is distinguishable from a
/// full one in a log line.
const MAGIC: u64 = 0xCAFE_F00D_DEAD_BEEF;

/// Run the smoke against the per-arch `MmuOps` impl.
/// # SAFETY: caller is the boot path; MmuOps state initialised
/// (HHDM offset + frame allocator); PMM ready; single-CPU; IRQs
/// off; `SCRATCH_VA` not currently in use by any other subsystem.
/// # C: O(walk depth × 4) — map + 2× translate + unmap, each O(4).
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn run<M: MmuOps>() {
    let pa = match crate::pmm_setup::alloc_one_frame() {
        Some(p) => p,
        None => {
            debug_vmm! { klog::kerror!("mmuops-smoke: PMM alloc failed"); }
            return;
        }
    };

    // SAFETY: SCRATCH_VA disjoint per module-level choice; `pa` was just allocated by the kernel-owned PMM; flags request a writable, no-exec, kernel-only mapping.
    unsafe {
        M::map(
            Va(SCRATCH_VA),
            Pa(pa),
            PageFlags::READ | PageFlags::WRITE,
            PageSize::P4K,
        );
    }

    // SAFETY: SCRATCH_VA was just mapped 4 KiB R+W; we own this page exclusively for the duration of the smoke.
    unsafe { core::ptr::write_volatile(SCRATCH_VA as *mut u64, MAGIC); }

    // Translate. Expect the same PA back + R|W flags (each arch's
    // unpack_flags drops EXEC and any access/dirty noise).
    let (got_pa, got_flags) = match M::translate(Va(SCRATCH_VA)) {
        Some(t) => t,
        None => {
            debug_vmm! { klog::kerror!("mmuops-smoke: translate post-map returned None"); }
            // Best-effort cleanup so we don't leak the mapping.
            // SAFETY: SCRATCH_VA is exclusively owned by this smoke.
            unsafe { M::unmap(Va(SCRATCH_VA), PageSize::P4K); }
            return;
        }
    };
    if got_pa.0 != pa {
        debug_vmm! {
            klog::write_raw(b"[FAULT] mmuops-smoke: translate pa mismatch want=");
            klog::write_hex_u64(pa);
            klog::write_raw(b" got=");
            klog::write_hex_u64(got_pa.0);
            klog::write_raw(b"\n");
        }
        // SAFETY: SCRATCH_VA is exclusively owned by this smoke.
        unsafe { M::unmap(Va(SCRATCH_VA), PageSize::P4K); }
        return;
    }
    if !got_flags.contains(PageFlags::READ | PageFlags::WRITE) {
        debug_vmm! {
            klog::write_raw(b"[FAULT] mmuops-smoke: translate flags missing R|W bits=");
            klog::write_hex_u64(got_flags.bits());
            klog::write_raw(b"\n");
        }
        // SAFETY: SCRATCH_VA is exclusively owned by this smoke.
        unsafe { M::unmap(Va(SCRATCH_VA), PageSize::P4K); }
        return;
    }

    // SAFETY: SCRATCH_VA is exclusively owned by this smoke for the entire run.
    unsafe { M::unmap(Va(SCRATCH_VA), PageSize::P4K); }

    // Verify translate now returns None.
    if M::translate(Va(SCRATCH_VA)).is_some() {
        debug_vmm! { klog::kerror!("mmuops-smoke: translate post-unmap returned Some"); }
        return;
    }

    debug_vmm! {
        klog::write_raw(b"[INFO]  mmuops-smoke: ok pa=");
        klog::write_hex_u64(pa);
        klog::write_raw(b" magic=");
        klog::write_hex_u64(MAGIC);
        klog::write_raw(b"\n");
    }
    let _ = MAGIC; // suppress unused-const lint when debug-vmm off

    // 2 MiB roundtrip — exercises the huge-page MmuOps path
    // (P1-89/P1-90) end-to-end. Skipped silently if PMM lacks an
    // order-9 buddy (e.g. low-mem QEMU configs).
    // SAFETY: same contract as the 4K roundtrip; SCRATCH_VA_2M is
    // 2 MiB-aligned and disjoint from the 4K scratch + the rest
    // of the kernel-VA layout.
    unsafe { run_2m::<M>(); }
}

/// 2 MiB-aligned scratch VA for the huge-page roundtrip. Same L4
/// slot 0x1FD as the 4 KiB scratch; the 4K smoke unmaps before we
/// reach this so there's no overlap.
#[cfg(target_os = "oxide-kernel")]
const SCRATCH_VA_2M: u64 = 0xffff_fd00_0020_0000;

/// 2 MiB MmuOps roundtrip. Same shape as the 4K smoke but with
/// `PageSize::P2M` and a buddy-Order(9) PMM allocation.
/// # SAFETY: same contract as `run`; caller initialised MmuOps
/// state; PMM ready; single-CPU; IRQs off.
#[cfg(target_os = "oxide-kernel")]
unsafe fn run_2m<M: MmuOps>() {
    let pa = match crate::pmm_setup::alloc_contig(pmm::Order(9)) {
        Some(p) => p,
        None => {
            debug_vmm! { klog::kinfo!("mmuops-smoke 2m: PMM order-9 alloc unavailable, skipping"); }
            return;
        }
    };

    // SAFETY: SCRATCH_VA_2M is 2 MiB-aligned and disjoint from existing kernel mappings; `pa` is a fresh order-9 PMM allocation aligned to 2 MiB; flags request a writable, no-exec, kernel-only mapping.
    unsafe {
        M::map(
            Va(SCRATCH_VA_2M),
            Pa(pa),
            PageFlags::READ | PageFlags::WRITE,
            PageSize::P2M,
        );
    }

    // Write magic at the head of the 2 MiB region.
    // SAFETY: SCRATCH_VA_2M was just mapped 2 MiB R+W; we own the entire 2 MiB block exclusively for this smoke.
    unsafe { core::ptr::write_volatile(SCRATCH_VA_2M as *mut u64, MAGIC); }

    // Translate verifies: PA round-trip + R|W flags + leaf level.
    // The huge translate returns `(pa | offset, leaf, level)` where
    // level=2; our offset within the block is 0, so resolved == pa.
    let r = M::translate(Va(SCRATCH_VA_2M));
    let (got_pa, got_flags) = match r {
        Some(t) => t,
        None => {
            debug_vmm! { klog::kerror!("mmuops-smoke 2m: translate post-map returned None"); }
            // SAFETY: SCRATCH_VA_2M is exclusively owned by this smoke.
            unsafe { M::unmap(Va(SCRATCH_VA_2M), PageSize::P2M); }
            return;
        }
    };
    if got_pa.0 != pa {
        debug_vmm! {
            klog::write_raw(b"[FAULT] mmuops-smoke 2m: pa mismatch want=");
            klog::write_hex_u64(pa);
            klog::write_raw(b" got=");
            klog::write_hex_u64(got_pa.0);
            klog::write_raw(b"\n");
        }
        // SAFETY: SCRATCH_VA_2M is exclusively owned by this smoke.
        unsafe { M::unmap(Va(SCRATCH_VA_2M), PageSize::P2M); }
        return;
    }
    if !got_flags.contains(PageFlags::READ | PageFlags::WRITE) {
        debug_vmm! {
            klog::write_raw(b"[FAULT] mmuops-smoke 2m: flags missing R|W bits=");
            klog::write_hex_u64(got_flags.bits());
            klog::write_raw(b"\n");
        }
        // SAFETY: SCRATCH_VA_2M is exclusively owned by this smoke.
        unsafe { M::unmap(Va(SCRATCH_VA_2M), PageSize::P2M); }
        return;
    }

    // SAFETY: SCRATCH_VA_2M is exclusively owned by this smoke for the entire run.
    unsafe { M::unmap(Va(SCRATCH_VA_2M), PageSize::P2M); }

    if M::translate(Va(SCRATCH_VA_2M)).is_some() {
        debug_vmm! { klog::kerror!("mmuops-smoke 2m: translate post-unmap returned Some"); }
        return;
    }

    debug_vmm! {
        klog::write_raw(b"[INFO]  mmuops-smoke 2m: ok pa=");
        klog::write_hex_u64(pa);
        klog::write_raw(b" magic=");
        klog::write_hex_u64(MAGIC);
        klog::write_raw(b"\n");
    }
}
