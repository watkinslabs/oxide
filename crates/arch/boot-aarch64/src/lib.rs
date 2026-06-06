// aarch64 bootloader handoff per docs/36 + docs/21 — Limine-free.
//
// Both live arm boot paths enter through the arm64 Image protocol
// trampoline in `selfboot.rs`:
//   - GRUB `linux` / UEFI LoadImage: MMU on, x0=EFI handle, x1=systab;
//     the EFI stub finds the DTB + ACPI RSDP in the firmware config
//     table, ExitBootServices, drops the MMU, then runs the trampoline.
//   - QEMU `-kernel` / U-Boot `booti`: MMU off, x0=DTB phys.
// The trampoline drops EL2->EL1 (if needed), builds identity + higher-
// half + HHDM page tables, enables the MMU, jumps to the kernel's
// higher-half VMA, then tail-calls the shared `_start` (which installs
// SP_EL1 and tail-calls `_start_rust`). `_start_rust` parses the DTB
// `/memory` node into a `BootInfo` memmap and tail-calls
// `kmain::kernel_main`. UART = PL011 at the QEMU `virt` machine's
// 0x09000000, reachable via the trampoline-installed HHDM device block.

#![no_std]
#![cfg_attr(target_os = "oxide-kernel", no_main)]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod dtb;
pub mod pl011;
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub mod selfboot;

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
}

// Per `04§4.0` (R06): every klog::* call site in this crate sits
// behind `debug-boot` — UART sink install, CPU/MMU dump, byte
// emit. Default builds emit zero log bytes; the call sites are
// absent from the binary, not "filtered at runtime".
#[cfg(feature = "debug-boot")]
macro_rules! debug_boot { ($($t:tt)*) => { $($t)* } }
#[cfg(not(feature = "debug-boot"))]
macro_rules! debug_boot { ($($t:tt)*) => {} }

#[cfg(feature = "debug-boot")]
use klog::Uart;
#[cfg(feature = "debug-boot")]
use sync::{Spinlock, Tty as UartClass};

#[cfg(feature = "debug-boot")]
use pl011::{Pl011, PL011_VIRT_BASE};

// ---------------------------------------------------------------------------
// Boot-time klog sink. The self-bootstrap trampoline maps an HHDM
// device block over phys 0, so the PL011 at `0x0900_0000` is reachable
// at `ARM_SELFBOOT_HHDM + 0x0900_0000`; `boot_emit_pl011` drives it.
// ARM semihosting putc (`boot_emit`) remains as a paging-agnostic
// fallback sink for environments where the device block is absent.
// ---------------------------------------------------------------------------

#[cfg(feature = "debug-boot")]
static BOOT_UART: Spinlock<Pl011, UartClass>
    = Spinlock::new(Pl011::new(PL011_VIRT_BASE));

/// klog `LogSink` adapter via semihosting. Each byte triggers a
/// `hlt #0xf000` at EL1; QEMU intercepts and emits the byte to its
/// stdout — same channel `-serial stdio` lands on.
/// # C: O(len)
#[cfg(feature = "debug-boot")]
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

/// Alternative klog sink via PL011 MMIO over the trampoline-installed
/// HHDM device block. Uses `lock_irqsave` per `06§3.1` for symmetry
/// with the x86 path: any IRQ-context klog (timer, fault, panic) needs
/// the IRQ-off window to avoid deadlock against a kernel-mode holder.
#[cfg(feature = "debug-boot")]
fn boot_emit_pl011(bytes: &[u8]) {
    let mut g = BOOT_UART.lock_irqsave::<hal_aarch64::ArmIrqGate>();
    g.write_bytes(bytes);
}

/// klog clock thunk — surfaces `ArmTimerOps::monotonic_ns` as the
/// `klog::ClockFn` after `set_cntfrq_khz` calibration.
/// # C: O(1)
fn now_ns_aarch64() -> u64 {
    use hal::TimerOps;
    hal_aarch64::ArmTimerOps::monotonic_ns().0
}

/// Boot-time CPU identification log. Reads MIDR_EL1 and the MMU
/// control registers the boot trampoline programmed before handoff.
/// # C: O(1)
#[cfg(feature = "debug-boot")]
fn log_cpu_info() {
    let m = hal_aarch64::midr_el1();
    klog::write_raw(b"[INFO]  midr_el1=");
    klog::write_hex_u64(m);
    klog::write_raw(b"\n[INFO]  mmu sctlr_el1=");
    klog::write_hex_u64(hal_aarch64::read_sctlr_el1());
    klog::write_raw(b" tcr_el1=");
    klog::write_hex_u64(hal_aarch64::read_tcr_el1());
    klog::write_raw(b" mair_el1=");
    klog::write_hex_u64(hal_aarch64::read_mair_el1());
    klog::write_raw(b"\n[INFO]  mmu ttbr0_el1=");
    klog::write_hex_u64(hal_aarch64::read_ttbr0_el1());
    klog::write_raw(b" ttbr1_el1=");
    klog::write_hex_u64(hal_aarch64::read_ttbr1_el1());
    klog::write_raw(b"\n");
}

use core::cell::UnsafeCell;
use boot_info::{BootInfo, BootMemRegion};

/// BSS-resident storage for the parsed DTB memmap. ~6 KiB cost
/// (256 entries × 24 B); QEMU virt rarely exceeds 16 entries.
const MAX_BOOT_REGIONS: usize = 256;
#[repr(C, align(8))]
struct MemmapStorage(UnsafeCell<[BootMemRegion; MAX_BOOT_REGIONS]>);
unsafe impl Sync for MemmapStorage {}
static MEMMAP_STORAGE: MemmapStorage = MemmapStorage(UnsafeCell::new([
    BootMemRegion {
        base_pa: 0,
        len:     0,
        kind:    boot_info::BootMemKind::Reserved,
    };
    MAX_BOOT_REGIONS
]));

/// Stub boot info. Real impl walks the DTB `/memory` node.
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
        smp_info_array: 0,
        smp_count: 0,
        bsp_lapic_id: 0,
        _pad: 0,
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

/// DTB physical address as handed to us in `x0` (U-Boot `booti` /
/// QEMU `-kernel`) or recovered from the EFI config table by the
/// trampoline's EFI stub (GRUB `linux` / UEFI). Stored by `_start`
/// before the stack swap so `_start_rust` can reach it from the new
/// stack. Validation happens inside `_start_rust`; if `parse_header`
/// rejects the blob we fall back to a conservative memmap.
static DTB_PHYS_ADDR: core::sync::atomic::AtomicU64
    = core::sync::atomic::AtomicU64::new(0);

/// Bootloader cmdline storage (mirrors x86_64). Holds the FDT
/// /chosen/bootargs bytes copied out of the bootloader region.
const CMDLINE_BUF_LEN: usize = 4096;
#[repr(C, align(8))]
struct CmdlineStorage(UnsafeCell<[u8; CMDLINE_BUF_LEN]>);
unsafe impl Sync for CmdlineStorage {}
static CMDLINE_STORAGE: CmdlineStorage =
    CmdlineStorage(UnsafeCell::new([0u8; CMDLINE_BUF_LEN]));

/// Parse the DTB blob's /chosen/bootargs property and publish it via
/// `cmdline::set`. No-op if the DTB is missing/invalid or `bootargs`
/// is empty; the kernel then falls back to `install_arch_default`.
/// # SAFETY: called once from boot path; reads bootloader-owned DTB
/// at DTB_PHYS_ADDR (HHDM-mapped at this stage); CMDLINE_STORAGE
/// is a single-writer 'static slot.
/// # C: O(dtb_struct_size)
#[cfg(target_os = "oxide-kernel")]
unsafe fn capture_cmdline_from_dtb() {
    // If something already populated the cmdline, leave it alone.
    if !cmdline::get().is_empty() { return; }
    let pa = DTB_PHYS_ADDR.load(core::sync::atomic::Ordering::Acquire);
    if pa == 0 { return; }
    // Self-boot cleared the low identity map (TTBR0), so the DTB blob is
    // only reachable via HHDM.
    let va = if selfboot::is_selfboot() { selfboot::ARM_SELFBOOT_HHDM + pa } else { pa };
    // SAFETY: DTB pointer from bootloader x0; the header's totalsize
    // bounds the safe read. We read 8 bytes first to learn totalsize.
    let head: &[u8] = unsafe {
        core::slice::from_raw_parts(va as *const u8, 8)
    };
    let totalsize = match dtb::parse_header(head) {
        Ok(h) => h.totalsize as usize,
        Err(_) => return,
    };
    if totalsize == 0 || totalsize > 4 * 1024 * 1024 { return; }
    // SAFETY: full blob bounded by the header's own totalsize.
    let blob: &[u8] = unsafe {
        core::slice::from_raw_parts(va as *const u8, totalsize)
    };
    let args = match dtb::chosen_bootargs(blob) { Some(s) => s, None => return };
    if args.is_empty() { return; }
    // SAFETY: dst is the 'static CMDLINE_STORAGE; sole writer here.
    let dst = unsafe { &mut *CMDLINE_STORAGE.0.get() };
    let n = args.len().min(CMDLINE_BUF_LEN - 1);
    dst[..n].copy_from_slice(&args[..n]);
    let mut total = n;
    if total < CMDLINE_BUF_LEN - 1 { dst[total] = b'\n'; total += 1; }
    // SAFETY: dst[..total] is initialised; 'static lifetime.
    let bytes: &'static [u8] = unsafe {
        core::slice::from_raw_parts(dst.as_ptr(), total)
    };
    // SAFETY: cmdline::set is boot-only single-writer.
    unsafe { cmdline::set(bytes); }
}

/// Build the self-bootstrap memmap: HHDM from the trampoline, RAM extent
/// from the DTB `/memory` node, with the kernel image + DTB blob carved
/// out as non-usable so the PMM never hands those pages to allocators.
/// # SAFETY: boot path, single-CPU; sole writer of MEMMAP_STORAGE.
/// # C: O(dtb)
#[cfg(target_os = "oxide-kernel")]
unsafe fn build_selfboot_memmap(info: &mut BootInfo) {
    const KB: u64 = 0xFFFF_FFFF_8000_0000;
    extern "C" { static __kernel_start: u8; static __kernel_end: u8; }
    info.hhdm_offset = selfboot::ARM_SELFBOOT_HHDM;
    // Actual phys load base the trampoline recorded (QEMU loads us 2 MiB
    // above RAM base). KB maps to this; phys = (VMA - KB) + load_base.
    let kp = selfboot::SB_LOAD_BASE.load(core::sync::atomic::Ordering::Acquire);

    let pa = DTB_PHYS_ADDR.load(core::sync::atomic::Ordering::Acquire);
    // RAM extent from the DTB /memory reg; fall back to a conservative
    // 1 GiB at the QEMU virt base if the DTB is unreadable.
    // SAFETY: pa is the bootloader DTB pointer; helper bounds reads by header.
    let (base, size) = unsafe { read_dtb_memory(pa) }.unwrap_or((0x4000_0000, 0x4000_0000));
    let ram_end = base.saturating_add(size);

    // Kernel image physical extent (page-rounded): VMA - KB + load_base.
    let kstart = (core::ptr::addr_of!(__kernel_start) as u64 - KB + kp) & !0xFFF;
    let kend = ((core::ptr::addr_of!(__kernel_end) as u64 - KB + kp) + 0xFFF) & !0xFFF;
    // DTB blob extent (page-rounded), if present.
    let (dstart, dend) = if pa != 0 {
        // SAFETY: pa is the bootloader DTB pointer; reads the 8-byte header.
        let ts = unsafe { dtb_totalsize(pa) };
        ((pa & !0xFFF), ((pa + ts + 0xFFF) & !0xFFF))
    } else { (0, 0) };

    // Two reserved blocks (kernel, DTB), sorted by start. Walk RAM and
    // emit Usable for the gaps, the reserved kind for each block.
    let mut blocks: [(u64, u64, boot_info::BootMemKind); 2] = [
        (kstart, kend, boot_info::BootMemKind::KernelImage),
        (dstart, dend, boot_info::BootMemKind::Reserved),
    ];
    if blocks[0].0 > blocks[1].0 { blocks.swap(0, 1); }

    // SAFETY: boot-only single-writer of the 'static MEMMAP_STORAGE.
    let storage = unsafe { &mut *MEMMAP_STORAGE.0.get() };
    let mut n = 0usize;
    let mut push = |s: u64, e: u64, k: boot_info::BootMemKind, n: &mut usize| {
        if e > s && *n < MAX_BOOT_REGIONS {
            storage[*n] = BootMemRegion { base_pa: s, len: e - s, kind: k };
            *n += 1;
        }
    };
    let mut cur = base;
    for &(bs, be, bk) in blocks.iter() {
        if be == 0 || be <= base || bs >= ram_end { continue; }
        let bs = bs.max(base);
        let be = be.min(ram_end);
        if bs > cur { push(cur, bs, boot_info::BootMemKind::Usable, &mut n); }
        push(bs, be, bk, &mut n);
        cur = cur.max(be);
    }
    if cur < ram_end { push(cur, ram_end, boot_info::BootMemKind::Usable, &mut n); }

    info.memmap_count = n as u32;
    info.memmap_ptr = storage.as_ptr();
}

/// DTB `/memory` reg → `(base, size)`. Reads the blob at phys `pa`
/// (HHDM-mapped). `None` on invalid/missing DTB.
/// # SAFETY: `pa` is the bootloader DTB pointer; header totalsize bounds the read.
/// # C: O(dtb)
#[cfg(target_os = "oxide-kernel")]
unsafe fn read_dtb_memory(pa: u64) -> Option<(u64, u64)> {
    if pa == 0 { return None; }
    let va = selfboot::ARM_SELFBOOT_HHDM + pa;
    // SAFETY: dtb_totalsize reads magic+totalsize from the HHDM-mapped header.
    let ts = unsafe { dtb_totalsize(pa) } as usize;
    if ts < 40 || ts > 4 * 1024 * 1024 { return None; }
    // SAFETY: blob bounded by its own header totalsize; HHDM-mapped. The full
    // blob (not an 8-byte prefix) is what dtb::parse_header needs to pass its
    // length checks inside first_memory_region.
    let blob = unsafe { core::slice::from_raw_parts(va as *const u8, ts) };
    dtb::first_memory_region(blob)
}

/// DTB `totalsize` at phys `pa` (HHDM-mapped); 0 if the magic is wrong.
/// Reads magic (offset 0) + totalsize (offset 4) directly — `dtb::parse_header`
/// can't be used here because it requires the FULL blob (its `totalsize <=
/// len` check rejects a header-only slice), and we need the size to know how
/// much to map. 8 bytes is enough for magic+totalsize.
/// # SAFETY: `pa` is the bootloader DTB pointer; the 8-byte read is HHDM-mapped.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
unsafe fn dtb_totalsize(pa: u64) -> u64 {
    let va = selfboot::ARM_SELFBOOT_HHDM + pa;
    // SAFETY: HHDM-mapped; read the 8-byte magic+totalsize prefix.
    let head = unsafe { core::slice::from_raw_parts(va as *const u8, 8) };
    let magic = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    if magic != dtb::FDT_MAGIC { return 0; }
    u32::from_be_bytes([head[4], head[5], head[6], head[7]]) as u64
}

/// Build a `BootInfo` from the self-bootstrap trampoline + DTB. HHDM
/// comes from the trampoline; the memmap is carved from the DTB
/// `/memory` node. Both live arm boot paths (GRUB EFI-stub `linux` and
/// QEMU `-kernel` flat Image) enter via the Image trampoline. The
/// kernel runs UP: no bootloader starts APs and the legacy smp_* fields
/// stay 0 (PSCI AP bring-up is a follow-on).
///
/// # SAFETY: caller is the boot path; DTB_PHYS_ADDR was written by
/// `_start` from the bootloader-provided x0 register.
/// # C: O(dtb)
#[cfg(target_os = "oxide-kernel")]
unsafe fn build_boot_info() -> BootInfo {
    // SAFETY: stub returns an owned BootInfo with a static empty
    // memmap; build_selfboot_memmap overlays HHDM + memmap.
    let mut info = unsafe { stub_boot_info() };
    // SAFETY: boot path; reads DTB + linker symbols, fills MEMMAP_STORAGE.
    unsafe { build_selfboot_memmap(&mut info); }
    use hal::TimerOps;
    info.boot_ns = hal_aarch64::ArmTimerOps::monotonic_ns().0;
    // ACPI RSDP from the EFI config table (efi_stub) → the kernel decodes
    // MCFG (PCI ECAM → virtio-blk/net/gpu) + MADT. 0 on the booti/-kernel
    // path (which has no ACPI). The kernel reads `rsdp_pa` AS A VA (only the
    // XSDT walk re-adds HHDM), so surface the HHDM-mapped VA, not the raw
    // physical — else it faults reading the bare PA.
    let efi_rsdp = selfboot::EFI_RSDP_PA.load(core::sync::atomic::Ordering::Acquire);
    info.rsdp_pa = if efi_rsdp != 0 { selfboot::ARM_SELFBOOT_HHDM + efi_rsdp } else { 0 };
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
    // selfboot breadcrumb 'G': proves _start -> _start_rust transition.
    // Raw HHDM PL011 write — gated under debug-boot per `04§4.0`.
    debug_boot! {
        if selfboot::is_selfboot() {
            // SAFETY: selfboot trampoline mapped HHDM (0xFFFF_8000…) device
            // block over phys 0; UART DR is at HHDM + 0x0900_0000.
            unsafe { core::ptr::write_volatile((selfboot::ARM_SELFBOOT_HHDM + 0x0900_0000) as *mut u32, 0x47); }
        }
    }
    // Install the EL1 vector table so any synchronous fault halts
    // at our default handler instead of looping on lost exceptions.
    // SAFETY: single-CPU boot, IRQs masked; install_default_vbar
    // writes VBAR_EL1 to a kernel-owned 0x800-aligned vector table.
    unsafe { hal_aarch64::install_default_vbar(); }

    // Enable FP/SIMD at EL0/EL1 globally. v1 doesn't do lazy
    // FP context switch (the per-task FpuStateAArch64 + trap-on-
    // first-use machinery in hal_aarch64::fpu exists but is unused);
    // enable unconditionally so user binaries built with NEON
    // intrinsics (busybox memcpy, glibc strxx, etc.) don't trap.
    hal_aarch64::fpu_enable();

    // The self-bootstrap Image trampoline installs the HHDM; hand its
    // offset to the PL011 driver so the UART is reachable after the MMU
    // is on. (A non-selfboot fallback keeps offset 0.)
    let hhdm = if selfboot::is_selfboot() {
        selfboot::ARM_SELFBOOT_HHDM
    } else {
        0
    };
    pl011::set_hhdm_offset(hhdm);

    // Sink registration is gated behind `debug-boot` per
    // `04§4.0` (R06): default builds emit zero klog bytes. Self-boot
    // routes klog through the real PL011 over HHDM; the fallback uses
    // the paging-agnostic semihosting sink.
    debug_boot! {
        if selfboot::is_selfboot() {
            klog::set_byte_sink(boot_emit_pl011);
        } else {
            klog::set_byte_sink(boot_emit);
        }
    }

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
    debug_boot! {
        if selfboot::is_selfboot() {
            // SAFETY: HHDM device block over UART; selfboot breadcrumb 'H'.
            unsafe { core::ptr::write_volatile((selfboot::ARM_SELFBOOT_HHDM + 0x0900_0000) as *mut u32, 0x48); }
        }
        log_cpu_info();
    }

    // SAFETY: boot-only single-writer; capture_cmdline_from_dtb reads
    // the DTB /chosen/bootargs and publishes it via cmdline::set, or
    // no-ops if the DTB lacks bootargs (the kernel then falls back to
    // install_arch_default).
    unsafe { capture_cmdline_from_dtb(); }
    // SAFETY: boot path; build_boot_info reads bootloader-owned
    // static state and produces an owned BootInfo.
    let info = unsafe { build_boot_info() };
    // SAFETY: kernel_main's contract is satisfied by the boot env
    // we just established (kernel stack installed, IRQs masked).
    unsafe { kmain::kernel_main(&info) }
}

/// Entry. The shared bootloader-agnostic entry the trampoline tail-calls
/// (`b _start`) with `x0` = DTB phys. We save x0 to `DTB_PHYS_ADDR`,
/// swap to `KERNEL_STACK`, and tail-call `_start_rust`.
///
/// # SAFETY: trampoline contract — MMU on with HHDM + kernel high map,
/// IRQs off, single-CPU.
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
    // SAFETY: stack_top is one past KERNEL_STACK; we force SPSel=1 so SP_EL1 (auto-selected on EL1 exception entry) points at our kernel stack — the boot handoff may arrive with SPSel=0; `_start_rust` is extern "C" + noreturn; `brk` hard-guards accidental return.
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
