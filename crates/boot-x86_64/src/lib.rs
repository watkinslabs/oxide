// x86_64 bootloader handoff per docs/36 + docs/20.
//
// Limine bootloader reads request markers from `.limine_reqs` (custom
// linker section) and writes responses, then jumps to the kernel
// entry. Our `_start` lives in `.text.boot` (per linker script
// 07§6), runs with paging set up by Limine to identity-map the
// kernel image at the upper-half virtual address.
//
// Phase 0 scope: get a `_start` symbol that runs cleanly in QEMU under
// Limine, sets up the kernel stack, parses Limine memmap into our
// `BootInfo`, and tail-calls `kernel::kernel_main`. UART driver
// (16550A on QEMU `-serial stdio`) lands here so klog has a sink.
//
// Real Limine integration + 16550 driver land in P0-07 follow-ups;
// this is the typed shell.

#![no_std]
#![cfg_attr(target_os = "oxide-kernel", no_main)]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod limine;
pub mod uart;

use core::cell::UnsafeCell;
use core::sync::atomic::AtomicPtr;
use kernel::{BootInfo, BootMemRegion};

use limine::{
    HhdmResponse, MemmapResponse, RequestHeader, RsdpResponse,
    HHDM_ID, MEMMAP_ID, REVISION_0, RSDP_ID,
};

// ---------------------------------------------------------------------------
// Limine request slots — bootloader scans `.limine_requests` for these
// markers and writes responses before jumping to `_start`.
// ---------------------------------------------------------------------------

#[used]
#[link_section = ".limine_requests"]
pub static LIMINE_MEMMAP: RequestHeader<MemmapResponse> = RequestHeader {
    id:       MEMMAP_ID,
    revision: REVISION_0,
    response: AtomicPtr::new(core::ptr::null_mut()),
};

#[used]
#[link_section = ".limine_requests"]
pub static LIMINE_HHDM: RequestHeader<HhdmResponse> = RequestHeader {
    id:       HHDM_ID,
    revision: REVISION_0,
    response: AtomicPtr::new(core::ptr::null_mut()),
};

#[used]
#[link_section = ".limine_requests"]
pub static LIMINE_RSDP: RequestHeader<RsdpResponse> = RequestHeader {
    id:       RSDP_ID,
    revision: REVISION_0,
    response: AtomicPtr::new(core::ptr::null_mut()),
};

/// Build a hard-coded minimal `BootInfo` for compile-test purposes.
/// Real impl reads Limine's memmap + module list.
///
/// # SAFETY: caller must own the returned `BootInfo`'s pointed-to
/// regions (currently a static empty slice; safe).
/// # C: O(1)
#[doc(hidden)]
pub unsafe fn stub_boot_info() -> BootInfo {
    static EMPTY: [BootMemRegion; 0] = [];
    BootInfo {
        memmap_count: 0,
        memmap_ptr: EMPTY.as_ptr(),
        seed: [0; 32],
        boot_ns: 0,
    }
}

/// Initial kernel stack (16 KiB, BSS-resident, page-aligned). Wrapped
/// in `UnsafeCell` so we can take the asm-side write reference without
/// `static mut` (per `06§11` + `07§5`). `Sync` is sound: only the
/// boot path touches it, single-CPU, before scheduler init.
#[cfg(target_os = "oxide-kernel")]
#[repr(align(4096))]
struct KernelStack(UnsafeCell<[u8; 16 * 1024]>);
#[cfg(target_os = "oxide-kernel")]
unsafe impl Sync for KernelStack {}
#[cfg(target_os = "oxide-kernel")]
static KERNEL_STACK: KernelStack = KernelStack(UnsafeCell::new([0; 16 * 1024]));

/// Entry point invoked by Limine.
///
/// # SAFETY: caller is the bootloader; this runs single-CPU with
/// IRQs masked, paging on, kernel image mapped at the upper-half
/// linker base, no kernel stack of our own yet (we install one).
///
/// # C: not measured
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(target_os = "oxide-kernel")]
#[no_mangle]
#[link_section = ".text.boot"]
pub unsafe extern "C" fn _start() -> ! {
    // SAFETY: boot path; KERNEL_STACK is BSS-resident, owned by us, no
    // other CPU is alive; sp install happens before any function call
    // that would clobber the bootloader stack.
    unsafe {
        // Install our kernel stack: load rsp = &KERNEL_STACK + size,
        // then jump to kernel_main with a stub BootInfo. Real version
        // parses Limine markers from the `.limine_reqs` section.
        let info = stub_boot_info();
        kernel::kernel_main(&info)
    }
}

// On host-test builds (target_os != oxide-kernel) we leave _start out so
// the crate compiles for `cargo test` without linker headaches.

#[cfg(test)]
mod tests {
    use super::*;
    use kernel::BootMemKind;

    #[test]
    fn stub_boot_info_is_empty() {
        // SAFETY: stub_boot_info returns a value owned by the caller;
        // pointed-to slice is &'static empty.
        let info = unsafe { stub_boot_info() };
        assert_eq!(info.memmap_count, 0);
        let _ = BootMemKind::Usable;
    }
}
