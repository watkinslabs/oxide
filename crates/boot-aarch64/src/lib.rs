// aarch64 bootloader handoff per docs/36 + docs/21.
//
// EDK2 (UEFI) or U-Boot drops us at `_start` per `36`. We arrive at
// EL2 or EL1 with MMU off; boot stub drops to EL1 (if needed), sets
// up identity + upper-half mapping, installs `SP_EL1` to our kernel
// stack, parses DTB or EDK2 system table into `BootInfo`, then
// tail-calls `kernel::kernel_main`. UART = PL011 at the QEMU `virt`
// machine's 0x09000000.
//
// Phase 0 scope: typed shell. Real `_start` asm + DTB parser + PL011
// driver land in follow-ups.

#![no_std]
#![cfg_attr(target_os = "oxide-kernel", no_main)]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod dtb;
pub mod pl011;

use core::cell::UnsafeCell;
use kernel::{BootInfo, BootMemRegion};

/// Stub boot info. Real impl walks the DTB or EDK2 EFI memory map.
///
/// # SAFETY: returned struct's `memmap_ptr` references a `'static` slice.
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

/// 16 KiB BSS-resident stack; same `UnsafeCell` discipline as the
/// x86_64 boot crate (`06§11` + `07§5` ban `static mut`).
#[cfg(target_os = "oxide-kernel")]
#[repr(align(4096))]
struct KernelStack(UnsafeCell<[u8; 16 * 1024]>);
#[cfg(target_os = "oxide-kernel")]
unsafe impl Sync for KernelStack {}
#[cfg(target_os = "oxide-kernel")]
static KERNEL_STACK: KernelStack = KernelStack(UnsafeCell::new([0; 16 * 1024]));

/// Entry. Bootloader convention: `x0..x3` carry handoff blob pointers
/// (DTB pa in `x0` for U-Boot; EFI system table in `x0` for EDK2).
///
/// # SAFETY: bootloader contract. Caller has set up at least an
/// identity mapping covering the kernel image; we install the kernel
/// stack and re-enter the kernel.
///
/// # C: not measured
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(target_os = "oxide-kernel")]
#[no_mangle]
#[link_section = ".text.boot"]
pub unsafe extern "C" fn _start() -> ! {
    // SAFETY: boot path. KERNEL_STACK in BSS, owned. No other CPU alive.
    unsafe {
        let info = stub_boot_info();
        kernel::kernel_main(&info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_boot_info_is_empty() {
        // SAFETY: stub_boot_info returns owned BootInfo; static empty slice.
        let info = unsafe { stub_boot_info() };
        assert_eq!(info.memmap_count, 0);
    }
}
