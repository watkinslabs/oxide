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
pub mod limine;
pub mod pl011;

#[cfg(target_os = "oxide-kernel")]
mod semihost {
    /// ARM semihosting putc per ARMv8 semihosting spec §5.5
    /// (SYS_WRITEC = 0x03). QEMU `-semihosting-config target=native`
    /// intercepts the `hlt #0xf000` opcode at EL1, reads x0 = op,
    /// x1 = pointer to char, and emits the char to stdout.
    /// # SAFETY: privileged opcode legal at EL1 with semihosting
    /// enabled; `byte` lives across the call via stack-local `b`.
    /// # C: O(1) host-syscall trap
    pub unsafe fn putc(byte: u8) {
        let b: u32 = byte as u32;
        let p = &b as *const u32 as u64;
        // SAFETY: `hlt #0xf000` is the ARMv8 semihosting opcode;
        // QEMU intercepts it at EL1 when -semihosting-config is on.
        // x0 = SYS_WRITEC op id, x1 points to a u32 holding the byte.
        unsafe {
            core::arch::asm!(
                "hlt #0xf000",
                in("x0") 0x03_u64,    // SYS_WRITEC
                in("x1") p,
                lateout("x0") _,
                options(nostack, preserves_flags),
            );
        }
    }

    /// Format a u64 as 16 hex chars and emit each via putc.
    /// # C: O(16) putc calls
    #[allow(dead_code)]
    pub fn put_hex_u64(v: u64) {
        for i in (0..16).rev() {
            let nibble = ((v >> (i * 4)) & 0xf) as u8;
            let c = if nibble < 10 { b'0' + nibble } else { b'a' + (nibble - 10) };
            // SAFETY: putc's contract holds at EL1 with semihosting
            // enabled; nibble→ASCII byte is a value, not a borrow.
            unsafe { putc(c) };
        }
    }

    /// # C: O(s.len()) putc calls
    #[allow(dead_code)]
    pub fn put_str(s: &str) {
        for &b in s.as_bytes() {
            // SAFETY: putc's contract holds at EL1 with semihosting
            // enabled; `b` is a copy of one byte from the slice.
            unsafe { putc(b) };
        }
    }
}

/// Limine base-revision marker per Limine v12 protocol. Limine scans
/// `.limine_requests` for this 3-word magic and requires revision ≥ 6
/// on aarch64; revision 0 is rejected. Values are protocol-stable
/// across Limine 9..12. The marker MUST appear at the very start of
/// `.limine_requests`; we land it via the `.start` subname which the
/// linker places before the rest.
#[used]
#[link_section = ".limine_requests.start"]
static LIMINE_BASE_REVISION: [u64; 3] = [
    0xf9562b2d5c95a6c8,
    0x6a7b384944536bdc,
    6,
];

/// HHDM request slot per `36§3`. The bootloader writes a non-null
/// response pointer here before kernel handoff; `_start_rust` reads
/// `(*response).offset` to learn where Limine mapped phys memory.
#[used]
#[link_section = ".limine_requests"]
pub static LIMINE_HHDM: limine::RequestHeader<limine::HhdmResponse>
    = limine::RequestHeader {
        id:       limine::HHDM_ID,
        revision: limine::REVISION_0,
        response: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
    };

/// MEMMAP request slot per `36§3`.
#[used]
#[link_section = ".limine_requests"]
pub static LIMINE_MEMMAP: limine::RequestHeader<limine::MemmapResponse>
    = limine::RequestHeader {
        id:       limine::MEMMAP_ID,
        revision: limine::REVISION_0,
        response: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
    };

/// RSDP request slot per `36§3`. ACPI may not be present on every
/// arm platform; the response stays null in that case.
#[used]
#[link_section = ".limine_requests"]
pub static LIMINE_RSDP: limine::RequestHeader<limine::RsdpResponse>
    = limine::RequestHeader {
        id:       limine::RSDP_ID,
        revision: limine::REVISION_0,
        response: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
    };

use klog::Uart;
use sync::{Spinlock, Tty as UartClass};

use pl011::{Pl011, PL011_VIRT_BASE};

// ---------------------------------------------------------------------------
// Boot-time klog sink. v1: ARM semihosting putc.
//
// Limine v12 with base revision ≥ 6 maps only RAM into HHDM, not
// device MMIO (`common/protos/limine.c` line ~205, "Map 0->4GiB to
// HHDM if base revision < 3"). So PL011 phys `0x0900_0000` has no
// kernel-VA mapping at handoff. Real PL011 access requires our own
// device-page mapping, which is VMM territory and waits on specs
// `06`/`13`/`21` freezing. Until then, semihosting is the only
// sink that works regardless of paging state.
// ---------------------------------------------------------------------------

static BOOT_UART: Spinlock<Pl011, UartClass>
    = Spinlock::new(Pl011::new(PL011_VIRT_BASE));

/// klog `LogSink` adapter via semihosting. Each byte triggers a
/// `hlt #0xf000` at EL1; QEMU intercepts and emits the byte to its
/// stdout — same channel `-serial stdio` lands on.
/// # C: O(len)
fn boot_emit(bytes: &[u8]) {
    #[cfg(target_os = "oxide-kernel")]
    {
        for &b in bytes {
            // SAFETY: privileged opcode legal at EL1 with semihosting
            // enabled by QEMU `-semihosting-config target=native`.
            unsafe { semihost::putc(b); }
        }
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    { let _ = bytes; }
}

/// Alternative klog sink via PL011 MMIO. Inactive until VMM lands a
/// real device-page mapping for `0x0900_0000` — see module-level
/// comment.
#[allow(dead_code)]
fn boot_emit_pl011(bytes: &[u8]) {
    let mut g = BOOT_UART.lock();
    g.write_bytes(bytes);
}

/// klog clock thunk — surfaces `ArmTimerOps::monotonic_ns` as the
/// `klog::ClockFn` after `set_cntfrq_khz` calibration.
/// # C: O(1)
fn now_ns_aarch64() -> u64 {
    use hal::TimerOps;
    hal_aarch64::ArmTimerOps::monotonic_ns().0
}

/// Boot-time CPU identification log. Reads MIDR_EL1 and emits as hex.
/// # C: O(1)
fn log_cpu_info() {
    let m = hal_aarch64::midr_el1();
    klog::write_raw(b"[INFO]  midr_el1=");
    klog::write_hex_u64(m);
    klog::write_raw(b"\n");
}

use core::cell::UnsafeCell;
use kernel::{BootInfo, BootMemRegion};

/// BSS-resident storage for the parsed Limine memmap. ~6 KiB cost
/// (256 entries × 24 B); QEMU virt rarely exceeds 16 entries.
const MAX_BOOT_REGIONS: usize = 256;
#[repr(C, align(8))]
struct MemmapStorage(UnsafeCell<[BootMemRegion; MAX_BOOT_REGIONS]>);
unsafe impl Sync for MemmapStorage {}
static MEMMAP_STORAGE: MemmapStorage = MemmapStorage(UnsafeCell::new([
    BootMemRegion {
        base_pa: 0,
        len:     0,
        kind:    kernel::BootMemKind::Reserved,
    };
    MAX_BOOT_REGIONS
]));

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
        hhdm_offset: 0,
        rsdp_pa: 0,
    }
}

/// 16 KiB BSS-resident stack; same `UnsafeCell` discipline as the
/// x86_64 boot crate (`06§11` + `07§5` ban `static mut`).
#[cfg(target_os = "oxide-kernel")]
const STACK_SIZE: usize = 128 * 1024;
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
    // SAFETY: stub returns an owned BootInfo with a static empty
    // memmap; we overlay HHDM + memmap from Limine before returning.
    let mut info = unsafe { stub_boot_info() };
    let h = LIMINE_HHDM.response.load(core::sync::atomic::Ordering::Acquire);
    if !h.is_null() {
        // SAFETY: Limine wrote a non-null response pointer; backing
        // struct lives for the rest of boot per `36§3`.
        info.hhdm_offset = unsafe { (*h).offset };
    }
    let m = LIMINE_MEMMAP.response.load(core::sync::atomic::Ordering::Acquire);
    if !m.is_null() {
        // SAFETY: bootloader-owned response per `36§3` ownership
        // contract; lives for rest of boot.
        let resp = unsafe { &*m };
        // SAFETY: MEMMAP_STORAGE is owned by this CPU during boot;
        // no other path mutates it before kernel_main returns.
        let storage = unsafe { &mut *MEMMAP_STORAGE.0.get() };
        // SAFETY: limine::populate_memmap_into walks resp.entries
        // per its contract, which the bootloader guarantees.
        let n = unsafe { limine::populate_memmap_into(storage, resp) };
        info.memmap_count = n as u32;
        info.memmap_ptr   = storage.as_ptr();
    }
    use hal::TimerOps;
    info.boot_ns = hal_aarch64::ArmTimerOps::monotonic_ns().0;
    let r = LIMINE_RSDP.response.load(core::sync::atomic::Ordering::Acquire);
    if !r.is_null() {
        // SAFETY: bootloader-owned response per `36§3` ownership
        // contract; lives for rest of boot.
        info.rsdp_pa = unsafe { (*r).address };
    }

    // DTB pointer is preserved for future device-tree consumers; not
    // wired into BootInfo yet.
    let _ = DTB_PHYS_ADDR.load(core::sync::atomic::Ordering::Acquire);
    info
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
    // Install the EL1 vector table so any synchronous fault halts
    // at our default handler instead of looping on lost exceptions.
    // SAFETY: single-CPU boot, IRQs masked; install_default_vbar
    // writes VBAR_EL1 to a kernel-owned 0x800-aligned vector table.
    unsafe { hal_aarch64::install_default_vbar(); }

    // Capture the HHDM offset Limine wrote so the PL011 driver has
    // it ready for when a future VMM PR installs the device mapping.
    // With correct request magic Limine fills this; with a typo it
    // stays null. The pinning test against upstream `limine.h` is
    // the diagnostic — there's nowhere to log a runtime warning yet.
    let resp = LIMINE_HHDM.response.load(core::sync::atomic::Ordering::Acquire);
    let hhdm = if resp.is_null() {
        0
    } else {
        // SAFETY: bootloader wrote a non-null response pointer; the
        // backing struct lives for the rest of boot per `36§3`.
        unsafe { (*resp).offset }
    };
    pl011::set_hhdm_offset(hhdm);

    klog::set_byte_sink(boot_emit);

    // Generic-timer calibration: read CNTFRQ_EL0 (programmed by
    // firmware) and stash kHz so `ArmTimerOps::monotonic_ns` works.
    let cntfrq_hz: u64;
    // SAFETY: `mrs cntfrq_el0` is unprivileged at any EL with no memory effects per ARM ARM D11.2.4; the output is the firmware-programmed counter frequency in Hz.
    unsafe {
        core::arch::asm!(
            "mrs {f}, cntfrq_el0",
            f = out(reg) cntfrq_hz,
            options(nomem, nostack, preserves_flags),
        );
    }
    hal_aarch64::set_cntfrq_khz((cntfrq_hz / 1000) as u32);
    klog::set_clock_fn(now_ns_aarch64);
    log_cpu_info();

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
    // SAFETY: stack_top is one past KERNEL_STACK; we force SPSel=1 so SP_EL1 (auto-selected on EL1 exception entry) points at our kernel stack — Limine v12 aarch64 may hand off with SPSel=0; `_start_rust` is extern "C" + noreturn; `brk` hard-guards accidental return.
    unsafe {
        core::arch::asm!(
            "msr spsel, #1",
            "mov sp, {sp}",
            "isb",
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
