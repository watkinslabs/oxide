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

/// Limine v9+ requests-region markers. Without these v12+ may
/// silently skip request scanning. Mirror the x86_64 boot crate.
#[used]
#[link_section = ".limine_requests.start"]
static LIMINE_REQUESTS_START: [u64; 4] = limine::REQUESTS_START_MARKER;

#[used]
#[link_section = ".limine_requests.end"]
static LIMINE_REQUESTS_END: [u64; 2] = limine::REQUESTS_END_MARKER;

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

/// EXECUTABLE_FILE / KERNEL_FILE — Limine 12 fills one of the two;
/// `capture_cmdline_from_limine` consults both. Provides the bootloader-
/// supplied cmdline (Limine config `cmdline: …` line) before falling
/// back to DTB /chosen/bootargs.
#[used]
#[link_section = ".limine_requests"]
pub static LIMINE_EXECUTABLE_FILE:
    limine::RequestHeader<limine::ExecutableFileResponse>
    = limine::RequestHeader {
        id:       limine::EXECUTABLE_FILE_ID,
        revision: limine::REVISION_0,
        response: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
    };

#[used]
#[link_section = ".limine_requests"]
pub static LIMINE_KERNEL_FILE:
    limine::RequestHeader<limine::ExecutableFileResponse>
    = limine::RequestHeader {
        id:       limine::KERNEL_FILE_ID,
        revision: limine::REVISION_0,
        response: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
    };

/// SMP request (aarch64). Limine starts each AP at our `goto_address`
/// MMU-on at EL1 with the kernel page tables — so APs can enter a
/// higher-half VA directly (`13§11`), unlike a bare PSCI CPU_ON.
#[used]
#[link_section = ".limine_requests"]
pub static LIMINE_SMP: limine::SmpRequestAArch64 = limine::SmpRequestAArch64 {
    id:       limine::SMP_ID,
    revision: limine::REVISION_0,
    response: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
    flags:    0,
};

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

/// Alternative klog sink via PL011 MMIO. Inactive until VMM lands a
/// real device-page mapping for `0x0900_0000` — see module-level
/// comment. Uses `lock_irqsave` per `06§3.1` for symmetry with the
/// x86 path: any IRQ-context klog (timer, fault, panic) needs the
/// IRQ-off window to avoid deadlock against a kernel-mode holder.
#[cfg(feature = "debug-boot")]
#[allow(dead_code)]
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
/// control registers Limine programmed before handoff.
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

/// DTB physical address as handed to us in `x0` by U-Boot / EDK2.
/// Stored by `_start` before the stack swap so `_start_rust` can
/// reach it from the new stack. Validation happens inside
/// `_start_rust`; if `parse_header` rejects the blob we fall back
/// to an empty BootInfo.
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

/// Read Limine's EXECUTABLE_FILE (or legacy KERNEL_FILE) response and
/// publish the cmdline via `kernel::boot_cmdline::set`. No-op if
/// Limine didn't fill either slot — the DTB fallback runs next.
/// # SAFETY: boot-only, single-CPU; CMDLINE_STORAGE is the sole writer.
/// # C: O(cmdline_len)
#[cfg(target_os = "oxide-kernel")]
unsafe fn capture_cmdline_from_limine() {
    let mut resp_ptr = LIMINE_EXECUTABLE_FILE
        .response.load(core::sync::atomic::Ordering::Acquire);
    if resp_ptr.is_null() {
        resp_ptr = LIMINE_KERNEL_FILE
            .response.load(core::sync::atomic::Ordering::Acquire);
    }
    if resp_ptr.is_null() { return; }
    // SAFETY: bootloader wrote valid ExecutableFileResponse before
    // handoff; pointer lives in HHDM-mapped region.
    let resp = unsafe { &*resp_ptr };
    if resp.executable_file.is_null() { return; }
    // SAFETY: LimineFile valid until BootloaderReclaimable recycle;
    // we copy out immediately.
    let file = unsafe { &*resp.executable_file };
    if file.cmdline.is_null() { return; }
    // SAFETY: dst is the 'static CMDLINE_STORAGE; sole writer here.
    let dst = unsafe { &mut *CMDLINE_STORAGE.0.get() };
    let mut n = 0usize;
    while n < CMDLINE_BUF_LEN - 1 {
        // SAFETY: bootloader-owned NUL-terminated C string.
        let b = unsafe { core::ptr::read_volatile(file.cmdline.add(n)) };
        if b == 0 { break; }
        dst[n] = b;
        n += 1;
    }
    if n == 0 { return; }
    if n < CMDLINE_BUF_LEN - 1 { dst[n] = b'\n'; n += 1; }
    // SAFETY: dst[..n] initialised; 'static lifetime.
    let bytes: &'static [u8] = unsafe {
        core::slice::from_raw_parts(dst.as_ptr(), n)
    };
    // SAFETY: boot_cmdline::set is boot-only single-writer.
    unsafe { kernel::boot_cmdline::set(bytes); }
}

/// Parse the DTB blob's /chosen/bootargs property and publish it via
/// `kernel::boot_cmdline::set`. No-op if the DTB is missing/invalid
/// or `bootargs` is empty; the kernel then falls back to
/// `install_arch_default`.
/// # SAFETY: called once from boot path; reads bootloader-owned DTB
/// at DTB_PHYS_ADDR (identity-mapped at this stage); CMDLINE_STORAGE
/// is a single-writer 'static slot.
/// # C: O(dtb_struct_size)
#[cfg(target_os = "oxide-kernel")]
unsafe fn capture_cmdline_from_dtb() {
    // If Limine already populated the cmdline, leave it alone.
    if !kernel::boot_cmdline::get().is_empty() { return; }
    let pa = DTB_PHYS_ADDR.load(core::sync::atomic::Ordering::Acquire);
    if pa == 0 { return; }
    // Self-boot cleared the low identity map (TTBR0), so the DTB blob is
    // only reachable via HHDM; Limine identity-maps low phys, so pa works
    // directly there.
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
    // SAFETY: boot-only single-writer per boot_cmdline contract.
    unsafe { kernel::boot_cmdline::set(bytes); }
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
    let mut blocks: [(u64, u64, kernel::BootMemKind); 2] = [
        (kstart, kend, kernel::BootMemKind::KernelImage),
        (dstart, dend, kernel::BootMemKind::Reserved),
    ];
    if blocks[0].0 > blocks[1].0 { blocks.swap(0, 1); }

    // SAFETY: boot-only single-writer of the 'static MEMMAP_STORAGE.
    let storage = unsafe { &mut *MEMMAP_STORAGE.0.get() };
    let mut n = 0usize;
    let mut push = |s: u64, e: u64, k: kernel::BootMemKind, n: &mut usize| {
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
        if bs > cur { push(cur, bs, kernel::BootMemKind::Usable, &mut n); }
        push(bs, be, bk, &mut n);
        cur = cur.max(be);
    }
    if cur < ram_end { push(cur, ram_end, kernel::BootMemKind::Usable, &mut n); }

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
    // SAFETY: HHDM maps phys 0.. ; read 8 bytes to learn totalsize.
    let head = unsafe { core::slice::from_raw_parts(va as *const u8, 8) };
    let ts = dtb::parse_header(head).ok()?.totalsize as usize;
    if ts == 0 || ts > 4 * 1024 * 1024 { return None; }
    // SAFETY: blob bounded by its own header totalsize; HHDM-mapped.
    let blob = unsafe { core::slice::from_raw_parts(va as *const u8, ts) };
    dtb::first_memory_region(blob)
}

/// DTB header totalsize at phys `pa` (HHDM-mapped); 0 on failure.
/// # SAFETY: `pa` bootloader DTB pointer.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
unsafe fn dtb_totalsize(pa: u64) -> u64 {
    let va = selfboot::ARM_SELFBOOT_HHDM + pa;
    // SAFETY: HHDM-mapped; 8-byte header read.
    let head = unsafe { core::slice::from_raw_parts(va as *const u8, 8) };
    dtb::parse_header(head).map(|h| h.totalsize as u64).unwrap_or(0)
}

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
    // Self-bootstrap (no Limine): HHDM + memmap come from the trampoline
    // + DTB instead of the (absent) Limine responses.
    if selfboot::is_selfboot() {
        // SAFETY: boot path; reads DTB + linker symbols, fills MEMMAP_STORAGE.
        unsafe { build_selfboot_memmap(&mut info); }
        use hal::TimerOps;
        info.boot_ns = hal_aarch64::ArmTimerOps::monotonic_ns().0;
        return info;
    }
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

    // SMP (aarch64): hand the kernel the Limine cpus[] array + count +
    // bsp mpidr so `13§11` AP startup parks each AP's goto_address.
    // smp_info_array reinterprets as `*const *mut SmpInfoAArch64` kernel-side.
    let s = LIMINE_SMP.response.load(core::sync::atomic::Ordering::Acquire);
    if !s.is_null() {
        // SAFETY: bootloader-owned SMP response per `36§3`; lives for the
        // rest of boot; cpus points at a `[*mut SmpInfoAArch64; cpu_count]`.
        let resp = unsafe { &*s };
        info.smp_info_array = resp.cpus as u64;
        info.smp_count      = resp.cpu_count;
        info.bsp_lapic_id   = (resp.bsp_mpidr & 0xff) as u32; // arm: bsp affinity-0
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
    // selfboot breadcrumb 'G': proves _start -> _start_rust transition.
    // Raw HHDM PL011 write; only on the self-boot path (Limine HHDM differs).
    if selfboot::is_selfboot() {
        // SAFETY: selfboot trampoline mapped HHDM (0xFFFF_8000…) device block
        // over phys 0; UART DR is at HHDM + 0x0900_0000.
        unsafe { core::ptr::write_volatile((selfboot::ARM_SELFBOOT_HHDM + 0x0900_0000) as *mut u32, 0x47); }
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

    // Capture the HHDM offset Limine wrote so the PL011 driver has
    // it ready for when a future VMM PR installs the device mapping.
    // With correct request magic Limine fills this; with a typo it
    // stays null. The pinning test against upstream `limine.h` is
    // the diagnostic — there's nowhere to log a runtime warning yet.
    // Self-bootstrap (Image trampoline) installs its own HHDM; Limine
    // fills LIMINE_HHDM.response instead. Pick the right source.
    let hhdm = if selfboot::is_selfboot() {
        selfboot::ARM_SELFBOOT_HHDM
    } else {
        let resp = LIMINE_HHDM.response.load(core::sync::atomic::Ordering::Acquire);
        if resp.is_null() {
            0
        } else {
            // SAFETY: bootloader wrote a non-null response pointer; the
            // backing struct lives for the rest of boot per `36§3`.
            unsafe { (*resp).offset }
        }
    };
    pl011::set_hhdm_offset(hhdm);

    // Sink registration is gated behind `debug-boot` per
    // `04§4.0` (R06): default builds emit zero klog bytes. Self-boot
    // (no Limine) has no semihosting host, so it routes klog through the
    // real PL011 over HHDM; the Limine path keeps the semihosting sink.
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
    if selfboot::is_selfboot() {
        // SAFETY: HHDM device block over UART; selfboot breadcrumb 'H'.
        unsafe { core::ptr::write_volatile((selfboot::ARM_SELFBOOT_HHDM + 0x0900_0000) as *mut u32, 0x48); }
    }
    debug_boot! { log_cpu_info(); }

    // SAFETY: bootloader-owned EXECUTABLE_FILE/KERNEL_FILE response
    // populated before kernel handoff; capture_cmdline_from_limine
    // copies the cmdline into CMDLINE_STORAGE and publishes via
    // kernel::boot_cmdline::set. DTB fallback runs second only when
    // the Limine response is absent (running outside Limine).
    // SAFETY: same boot-only single-writer contract for both capture paths; capture_cmdline_from_dtb is a no-op if Limine already populated the slot.
    unsafe { capture_cmdline_from_limine(); capture_cmdline_from_dtb(); }
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
