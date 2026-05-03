// User-page mapping smoke per `20§5` / `21§5` (P1-95 fix validation).
//
// Validates that the MmuOps surface produces a CPL=3-walkable
// mapping: U=1 on every interior + leaf entry, EXEC honoured (NX
// clear on x86; UXN clear on arm). Distinct from `mmuops_smoke`
// which only exercises kernel-only RW mappings.
//
// Sequence:
//   1. Allocate a 4 KiB frame from PMM.
//   2. `MmuOps::map` at USER_VA, READ|EXEC|USER, P4K.
//   3. `MmuOps::translate(USER_VA)` — verify PA + USER+EXEC flags
//      round-trip.
//   4. `MmuOps::unmap(USER_VA, P4K)`.
//   5. `MmuOps::translate` — verify None.
//
// CPL=3 access from user code lands with P1-82; this smoke runs at
// CPL=0 so it only validates the mapping topology, not the actual
// CPU walk under user privilege.

use hal::{MmuOps, Pa, PageFlags, PageSize, Va};

/// Low-half VA in user space (47-bit canonical, well below the
/// 0x0000_8000_0000_0000 boundary). 0x40_0000 = 4 MiB — typical
/// ELF text base; small enough that the 4-level walk creates only
/// PML4[0]/PDPT[0]/PD[2]/PT[0] entries.
#[cfg(target_os = "oxide-kernel")]
const USER_VA: u64 = 0x0000_0000_0040_0000;

#[cfg(target_os = "oxide-kernel")]
const USER_FLAGS_REQUEST: PageFlags =
    PageFlags::READ.union(PageFlags::EXEC).union(PageFlags::USER);

/// Run the smoke against the per-arch `MmuOps` impl.
/// # SAFETY: caller is the boot path; MmuOps state initialised; PMM
/// ready; single-CPU; IRQs off; `USER_VA` not currently in use.
/// # C: O(walk depth × 4)
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn run<M: MmuOps>() {
    let pa = match crate::pmm_setup::alloc_one_frame() {
        Some(p) => p,
        None => {
            debug_vmm! { klog::kerror!("user-map-smoke: PMM alloc failed"); }
            return;
        }
    };

    // SAFETY: USER_VA is in the user-VA half (CPL=0 access still permitted; U-bit on leaves does not restrict CPL=0); `pa` is a fresh PMM frame; flags request a user-readable executable mapping.
    unsafe {
        M::map(
            Va(USER_VA),
            Pa(pa),
            USER_FLAGS_REQUEST,
            PageSize::P4K,
        );
    }

    let (got_pa, got_flags) = match M::translate(Va(USER_VA)) {
        Some(t) => t,
        None => {
            debug_vmm! { klog::kerror!("user-map-smoke: translate post-map returned None"); }
            // SAFETY: USER_VA is exclusively owned by this smoke.
            unsafe { M::unmap(Va(USER_VA), PageSize::P4K); }
            return;
        }
    };
    if got_pa.0 != pa {
        debug_vmm! {
            klog::write_raw(b"[FAULT] user-map-smoke: pa mismatch want=");
            klog::write_hex_u64(pa);
            klog::write_raw(b" got=");
            klog::write_hex_u64(got_pa.0);
            klog::write_raw(b"\n");
        }
        // SAFETY: USER_VA is exclusively owned by this smoke.
        unsafe { M::unmap(Va(USER_VA), PageSize::P4K); }
        return;
    }
    if !got_flags.contains(PageFlags::USER) {
        debug_vmm! {
            klog::write_raw(b"[FAULT] user-map-smoke: USER flag missing bits=");
            klog::write_hex_u64(got_flags.bits());
            klog::write_raw(b"\n");
        }
        // SAFETY: USER_VA is exclusively owned by this smoke.
        unsafe { M::unmap(Va(USER_VA), PageSize::P4K); }
        return;
    }
    if !got_flags.contains(PageFlags::EXEC) {
        debug_vmm! {
            klog::write_raw(b"[FAULT] user-map-smoke: EXEC flag missing bits=");
            klog::write_hex_u64(got_flags.bits());
            klog::write_raw(b"\n");
        }
        // SAFETY: USER_VA is exclusively owned by this smoke.
        unsafe { M::unmap(Va(USER_VA), PageSize::P4K); }
        return;
    }

    // SAFETY: USER_VA is exclusively owned by this smoke for the entire run.
    unsafe { M::unmap(Va(USER_VA), PageSize::P4K); }

    if M::translate(Va(USER_VA)).is_some() {
        debug_vmm! { klog::kerror!("user-map-smoke: translate post-unmap returned Some"); }
        return;
    }

    debug_vmm! {
        klog::write_raw(b"[INFO]  user-map-smoke: ok pa=");
        klog::write_hex_u64(pa);
        klog::write_raw(b" flags=");
        klog::write_hex_u64(got_flags.bits());
        klog::write_raw(b"\n");
    }
}
