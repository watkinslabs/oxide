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

/// Limine base-revision marker per Limine v12 protocol. Limine scans
/// `.limine_requests` for this 3-word magic and requires revision ≥ 6
/// on aarch64; revision 0 is rejected. Values are protocol-stable
/// across Limine 9..12.
#[used]
#[link_section = ".limine_requests"]
static LIMINE_BASE_REVISION: [u64; 3] = [
    0xf9562b2d5c95a6c8,
    0x6a7b384944536bdc,
    6,
];

use klog::Uart;
use sync::{Spinlock, Tty as UartClass};

use pl011::{Pl011, PL011_VIRT_BASE};

// ---------------------------------------------------------------------------
// Boot-time UART sink for klog. Single instance behind `Spinlock` so the
// `klog::LogSink` thunk can drive it without `static mut` (`07§5`).
// ---------------------------------------------------------------------------

static BOOT_UART: Spinlock<Pl011, UartClass>
    = Spinlock::new(Pl011::new(PL011_VIRT_BASE));

/// klog `LogSink` adapter — drives `BOOT_UART` for every byte slice
/// klog emits. Registered via `klog::set_byte_sink` from
/// `_start_rust` after `BOOT_UART::init()`.
/// # C: O(len)
fn boot_emit(bytes: &[u8]) {
    let mut g = BOOT_UART.lock();
    g.write_bytes(bytes);
}

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
const STACK_SIZE: usize = 16 * 1024;
#[cfg(target_os = "oxide-kernel")]
#[repr(align(4096))]
struct KernelStack(UnsafeCell<[u8; STACK_SIZE]>);
#[cfg(target_os = "oxide-kernel")]
unsafe impl Sync for KernelStack {}
#[cfg(target_os = "oxide-kernel")]
static KERNEL_STACK: KernelStack = KernelStack(UnsafeCell::new([0; STACK_SIZE]));

/// DTB physical address as handed to us in `x0` by U-Boot / EDK2.
/// Stored by `_start` before the stack swap so `_start_rust` can
/// reach it from the new stack. Validation happens inside
/// `_start_rust`; if `parse_header` rejects the blob we fall back
/// to an empty BootInfo.
static DTB_PHYS_ADDR: core::sync::atomic::AtomicU64
    = core::sync::atomic::AtomicU64::new(0);

/// Build a `BootInfo` from the DTB pointer. v1 validates the header
/// only; the `/memory` property walk that fills BootMemRegions
/// rides alongside the PMM init that consumes them.
///
/// # SAFETY: caller is the boot path; DTB_PHYS_ADDR was written by
/// `_start` from the bootloader-provided x0 register.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
unsafe fn build_boot_info() -> BootInfo {
    let dtb_pa = DTB_PHYS_ADDR.load(core::sync::atomic::Ordering::Acquire);
    if dtb_pa == 0 {
        // SAFETY: stub_boot_info returns an owned BootInfo with a
        // static empty memmap slice.
        return unsafe { stub_boot_info() };
    }
    // SAFETY: bootloader handed `x0 == dtb_pa`; we trust the
    // `36§4` invariant that the blob is reachable + readable. The
    // first 40 bytes are the FDT header; we read those plus
    // `totalsize` bytes total via the slice below.
    let header_view: &[u8] = unsafe {
        core::slice::from_raw_parts(dtb_pa as *const u8, 40)
    };
    if dtb::parse_header(header_view).is_err() {
        // SAFETY: stub_boot_info returns an owned BootInfo whose
        // memmap_ptr references a `&'static` empty slice; trivial.
        return unsafe { stub_boot_info() };
    }
    // /memory property walk lands when the PMM init consumer does;
    // for now hand kernel_main an empty memmap with a valid DTB
    // pointer reachable via a future BootInfo extension.
    // SAFETY: stub_boot_info returns an owned empty BootInfo.
    unsafe { stub_boot_info() }
}

/// Rust-side boot continuation. Runs on the kernel stack we
/// installed in `_start`; reads the DTB pointer stashed in
/// `DTB_PHYS_ADDR`, builds a `BootInfo`, tail-calls `kernel_main`.
///
/// # SAFETY: called only from the asm `_start` after `sp` has been
/// swapped to `KERNEL_STACK`'s top. Single-CPU, IRQ-off.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(target_os = "oxide-kernel")]
#[no_mangle]
unsafe extern "C" fn _start_rust() -> ! {
    // SAFETY: PL011 owned by us pre-init; no other CPU alive; `init`
    // programs the UART for 115200-8N1 + FIFO. After this call any
    // klog emit will land on the QEMU virt console.
    unsafe { BOOT_UART.lock().init(); }
    klog::set_byte_sink(boot_emit);
    // SAFETY: single-CPU boot, IRQs masked; install_default_vbar writes VBAR_EL1 to a kernel-owned 0x800-aligned vector table. Subsequent exceptions vector to oxide_default_vector_handler which halts.
    unsafe { hal_aarch64::install_default_vbar(); }
    // SAFETY: boot path; build_boot_info reads bootloader-owned
    // static state and produces an owned BootInfo.
    let info = unsafe { build_boot_info() };
    // SAFETY: kernel_main's contract is satisfied by the boot env
    // we just established (kernel stack installed, IRQs masked).
    unsafe { kernel::kernel_main(&info) }
}

/// Entry. Bootloader convention: `x0..x3` carry handoff blob pointers
/// (DTB pa in `x0` for U-Boot; EFI system table in `x0` for EDK2).
/// We save x0 to `DTB_PHYS_ADDR`, swap to `KERNEL_STACK`, and tail-
/// call `_start_rust`.
///
/// # SAFETY: bootloader contract. Caller has set up at least an
/// identity mapping covering the kernel image.
///
/// # C: not measured
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(target_os = "oxide-kernel")]
#[no_mangle]
#[link_section = ".text.boot"]
pub unsafe extern "C" fn _start(dtb_phys: u64) -> ! {
    // Save x0 before any function call clobbers it.
    DTB_PHYS_ADDR.store(dtb_phys, core::sync::atomic::Ordering::Release);
    // SAFETY: KERNEL_STACK is BSS-resident, owned by us, single-CPU.
    let stack_top = unsafe {
        (KERNEL_STACK.0.get() as *mut u8).add(STACK_SIZE)
    };
    // SAFETY: stack_top is one past KERNEL_STACK; install via `mov sp` before any call gives us a valid kernel stack of STACK_SIZE bytes growing down. `_start_rust` is extern "C" + noreturn; `brk` after the call hard-guards accidental return.
    unsafe {
        core::arch::asm!(
            "mov sp, {sp}",
            "bl  {next}",
            "brk #0",
            sp   = in(reg) stack_top,
            next = sym _start_rust,
            options(noreturn),
        );
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
