// DTB parsing is reached only from the `oxide-kernel` boot path below.
#[cfg(target_os = "oxide-kernel")]
use crate::dtb;
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
use crate::selfboot;
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
        framebuffer: boot_info::BootFramebuffer::EMPTY,
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

/// One-past-the-end pointer for the boot stack installed by `_start`.
/// # SAFETY: caller must run on the single-CPU boot path before scheduler init.
#[cfg(target_os = "oxide-kernel")]
pub(crate) unsafe fn kernel_stack_top() -> *mut u8 {
    // SAFETY: KERNEL_STACK is boot-owned and STACK_SIZE is exactly its byte length.
    unsafe { (KERNEL_STACK.0.get() as *mut u8).add(STACK_SIZE) }
}

/// DTB physical address as handed to us in `x0` (U-Boot `booti` /
/// QEMU `-kernel`) or recovered from the EFI config table by the
/// trampoline's EFI stub (GRUB `linux` / UEFI). Stored by `_start`
/// before the stack swap so `_start_rust` can reach it from the new
/// stack. Validation happens inside `_start_rust`; if `parse_header`
/// rejects the blob we fall back to a conservative memmap.
pub(super) static DTB_PHYS_ADDR: core::sync::atomic::AtomicU64
    = core::sync::atomic::AtomicU64::new(0);

/// Bootloader cmdline storage (mirrors x86_64). Holds the bytes copied out of
/// whichever bootloader transport carried them — EFI `LoadOptions` or the FDT
/// `/chosen/bootargs`.
const CMDLINE_BUF_LEN: usize = 4096;
#[repr(C, align(8))]
struct CmdlineStorage(UnsafeCell<[u8; CMDLINE_BUF_LEN]>);
unsafe impl Sync for CmdlineStorage {}
static CMDLINE_STORAGE: CmdlineStorage =
    CmdlineStorage(UnsafeCell::new([0u8; CMDLINE_BUF_LEN]));

/// Publish the command line the EFI stub decoded from the loaded-image
/// protocol's `LoadOptions`. No-op when we did not boot via EFI or the
/// firmware supplied none, leaving the DTB path (and then the arch default)
/// to run.
///
/// Ordering: EFI load options outrank `/chosen/bootargs`, matching how the
/// arm64 EFI boot protocol treats them — a bootloader that sets both means
/// the load options, and this firmware publishes no device tree at all, so
/// the load options are usually the only line in existence.
/// # SAFETY: called once from the boot path; CMDLINE_STORAGE is a
/// single-writer 'static slot and no procfs read can race it yet.
/// # C: O(cmdline_len)
#[cfg(target_os = "oxide-kernel")]
pub(crate) unsafe fn capture_cmdline_from_efi() {
    if !cmdline::get().is_empty() { return; }
    let n = selfboot::EFI_CMDLINE_LEN.load(core::sync::atomic::Ordering::Acquire) as usize;
    let n = n.min(selfboot::EFI_CMDLINE_MAX);
    if n == 0 { return; }
    // SAFETY: dst is the 'static CMDLINE_STORAGE; sole writer here.
    let dst = unsafe { &mut *CMDLINE_STORAGE.0.get() };
    let n = n.min(CMDLINE_BUF_LEN - 1);
    for i in 0..n { dst[i] = selfboot::EFI_CMDLINE[i].load(core::sync::atomic::Ordering::Acquire); }
    let mut total = n;
    // Linux convention: /proc/cmdline ends with '\n'.
    if total < CMDLINE_BUF_LEN - 1 { dst[total] = b'\n'; total += 1; }
    // SAFETY: dst[..total] is initialised and 'static.
    let bytes: &'static [u8] = unsafe { core::slice::from_raw_parts(dst.as_ptr(), total) };
    // SAFETY: cmdline::set is boot-only single-writer.
    unsafe { cmdline::set(bytes); }
}

/// Parse the DTB blob's /chosen/bootargs property and publish it via
/// `cmdline::set`. No-op if the DTB is missing/invalid or `bootargs`
/// is empty; the kernel then falls back to `install_arch_default`.
/// # SAFETY: called once from boot path; reads bootloader-owned DTB
/// at DTB_PHYS_ADDR (HHDM-mapped at this stage); CMDLINE_STORAGE
/// is a single-writer 'static slot.
/// # C: O(dtb_struct_size)
#[cfg(target_os = "oxide-kernel")]
pub(crate) unsafe fn capture_cmdline_from_dtb() {
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

    // Usable RAM regions, in priority order:
    //   1. DTB `/memory` extent (U-Boot `booti` / `-kernel`, or any EFI
    //      firmware that publishes an FDT) — one contiguous block.
    //   2. EFI `EfiConventionalMemory` regions captured by `efi_stub_setup`
    //      (QEMU EDK2 in ACPI mode exposes NO FDT, so the DTB read fails).
    //      Type-7 is genuinely-free DRAM — it excludes the kernel image, ACPI
    //      tables (this EDK2 keeps them in BootServicesData), runtime,
    //      reserved + MMIO — so no carve-out is needed and nothing the kernel
    //      still reads post-boot is ever marked usable.
    //   3. Last resort: a conservative 1 GiB at the QEMU virt base.
    let mut regions: [(u64, u64); selfboot::EFI_RAM_MAX] = [(0, 0); selfboot::EFI_RAM_MAX];
    let mut nregions = 0usize;
    // ACPI table extent to pin Reserved when reclaiming boot-services; (0,0)=none.
    let mut acpi_blk: (u64, u64) = (0, 0);
    // Publish the DTB-resolved PL011 UARTCLK before consuming the memmap, so the
    // runtime UART driver's baud reprogram uses the real reference clock.
    // SAFETY: pa is the bootloader DTB pointer; helper bounds reads by header.
    unsafe { publish_pl011_clock(pa); }
    // SAFETY: pa is the bootloader DTB pointer; helper bounds reads by header.
    match unsafe { read_dtb_memory(pa) } {
        Some((base, size)) => { regions[0] = (base, size); nregions = 1; }
        None => {
            let nr = selfboot::EFI_RAM_COUNT.load(core::sync::atomic::Ordering::Acquire) as usize;
            if nr > 0 {
                while nregions < nr && nregions < selfboot::EFI_RAM_MAX {
                    let b = selfboot::EFI_RAM_BASE[nregions].load(core::sync::atomic::Ordering::Acquire);
                    let pages = selfboot::EFI_RAM_PAGES[nregions].load(core::sync::atomic::Ordering::Acquire);
                    regions[nregions] = (b, pages.saturating_mul(0x1000));
                    nregions += 1;
                }
                // Reclaim BootServices Code/Data (3/4) too — but ONLY once we
                // can pin the ACPI tables the kernel reads in place (this EDK2
                // stashes the live ACPI in type4; reclaiming it raw → pci
                // devices=0). acpi_extent() bounds the RSDP+XSDT+listed tables.
                // SAFETY: reads the HHDM-mapped RSDP/XSDT; each table bounded by its header.
                if let Some(ext) = unsafe { acpi_extent() } {
                    acpi_blk = ext;
                    let nbs = selfboot::EFI_BS_COUNT.load(core::sync::atomic::Ordering::Acquire) as usize;
                    let mut j = 0usize;
                    while j < nbs && nregions < selfboot::EFI_RAM_MAX {
                        let b = selfboot::EFI_BS_BASE[j].load(core::sync::atomic::Ordering::Acquire);
                        let pages = selfboot::EFI_BS_PAGES[j].load(core::sync::atomic::Ordering::Acquire);
                        regions[nregions] = (b, pages.saturating_mul(0x1000));
                        nregions += 1;
                        j += 1;
                    }
                }
            } else {
                regions[0] = (0x4000_0000, 0x4000_0000);
                nregions = 1;
            }
        }
    }

    // Kernel image physical extent (page-rounded): VMA - KB + load_base.
    let kstart = (core::ptr::addr_of!(__kernel_start) as u64 - KB + kp) & !0xFFF;
    let kend = ((core::ptr::addr_of!(__kernel_end) as u64 - KB + kp) + 0xFFF) & !0xFFF;
    // DTB blob extent (page-rounded), if present.
    let (dstart, dend) = if pa != 0 {
        // SAFETY: pa is the bootloader DTB pointer; reads the 8-byte header.
        let ts = unsafe { dtb_totalsize(pa) };
        ((pa & !0xFFF), ((pa + ts + 0xFFF) & !0xFFF))
    } else { (0, 0) };

    // Reserved blocks (kernel image, DTB blob, ACPI tables), sorted by start
    // for the per-region gap walk. An absent block is (0,0) and skipped; a
    // block not inside a given region is skipped too.
    let mut blocks: [(u64, u64, boot_info::BootMemKind); 3] = [
        (kstart, kend, boot_info::BootMemKind::KernelImage),
        (dstart, dend, boot_info::BootMemKind::Reserved),
        (acpi_blk.0, acpi_blk.1, boot_info::BootMemKind::Reserved),
    ];
    let mut a = 1usize;
    while a < 3 {
        let mut b = a;
        while b > 0 && blocks[b - 1].0 > blocks[b].0 { blocks.swap(b - 1, b); b -= 1; }
        a += 1;
    }

    // SAFETY: boot-only single-writer of the 'static MEMMAP_STORAGE.
    let storage = unsafe { &mut *MEMMAP_STORAGE.0.get() };
    let mut n = 0usize;
    let mut push = |s: u64, e: u64, k: boot_info::BootMemKind, n: &mut usize| {
        if e > s && *n < MAX_BOOT_REGIONS {
            storage[*n] = BootMemRegion { base_pa: s, len: e - s, kind: k };
            *n += 1;
        }
    };
    // Walk each usable region, emitting Usable for the gaps and the carve
    // kind where a reserved block overlaps it.
    for ri in 0..nregions {
        let (base, size) = regions[ri];
        if size == 0 { continue; }
        let ram_end = base.saturating_add(size);
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
    }

    // Diagnostic: per-EFI-type RAM tally (MiB), so the free-vs-reserved
    // split is visible rather than inferred. Empty on the DTB path (the
    // tallies are only filled by efi_stub on the UEFI path).
    #[cfg(feature = "debug-boot")]
    {
        let mut t = 0usize;
        while t < 16 {
            let pages = selfboot::EFI_TYPE_PAGES[t].load(core::sync::atomic::Ordering::Acquire);
            if pages != 0 {
                klog::write_raw(b"[INFO]  efi-mem type");
                klog::write_dec_u64(t as u64);
                klog::write_raw(b" = ");
                klog::write_dec_u64(pages / 256); // pages * 4096 / (1024*1024)
                klog::write_raw(b" MiB\n");
            }
            t += 1;
        }
    }

    info.memmap_count = n as u32;
    info.memmap_ptr = storage.as_ptr();
}

/// Page-aligned `[lo, hi)` physical extent of the ACPI tables the kernel
/// reads in place: RSDP + XSDT + every XSDT-listed table. `firmware::acpi`
/// walks the XSDT and never chases FADT→DSDT, so this is exactly the set
/// that must stay valid; pinning it Reserved lets the rest of boot-services
/// be reclaimed. `None` when there is no RSDP (DTB / `-kernel` path).
/// # SAFETY: reads the HHDM-mapped RSDP/XSDT; each table is bounded by the
/// length in its own header and the entry count by the XSDT length.
/// # C: O(n_tables)
#[cfg(target_os = "oxide-kernel")]
unsafe fn acpi_extent() -> Option<(u64, u64)> {
    let h = selfboot::ARM_SELFBOOT_HHDM;
    let rsdp_pa = selfboot::EFI_RSDP_PA.load(core::sync::atomic::Ordering::Acquire);
    if rsdp_pa == 0 { return None; }
    // SAFETY: HHDM covers all RAM; ACPI fields are not guaranteed aligned.
    let rd32 = |pa: u64| -> u32 { unsafe { core::ptr::read_unaligned((h + pa) as *const u32) } };
    // SAFETY: HHDM covers all RAM; ACPI fields are not guaranteed aligned.
    let rd64 = |pa: u64| -> u64 { unsafe { core::ptr::read_unaligned((h + pa) as *const u64) } };
    let xsdt_pa = rd64(rsdp_pa + 24); // ACPI 2.0 XsdtAddress @ offset 24
    if xsdt_pa == 0 { return None; }
    let xsdt_len = rd32(xsdt_pa + 4) as u64; // SDT header Length @ offset 4
    if xsdt_len < 36 || xsdt_len > 4096 { return None; }
    let mut lo = rsdp_pa.min(xsdt_pa);
    let mut hi = (rsdp_pa + 36).max(xsdt_pa + xsdt_len);
    let n = ((xsdt_len - 36) / 8).min(64);
    let mut i = 0u64;
    while i < n {
        let tpa = rd64(xsdt_pa + 36 + i * 8);
        i += 1;
        if tpa == 0 { continue; }
        let mut tlen = rd32(tpa + 4) as u64;
        if tlen < 36 { tlen = 36; }
        if tlen > 0x10_0000 { tlen = 0x10_0000; }
        if tpa < lo { lo = tpa; }
        if tpa + tlen > hi { hi = tpa + tlen; }
    }
    Some((lo & !0xFFF, (hi + 0xFFF) & !0xFFF))
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

/// Resolve the PL011 `UARTCLK` from the DTB clock tree and publish it to
/// `hal_aarch64::pl011` (Linux `pl011_probe`→`clk_get_rate`). The runtime UART
/// driver's TCSETS baud reprogram then computes the divisor against the real
/// reference clock instead of an assumed constant. No-op if the DTB is
/// missing/invalid or describes no PL011 clock (the hal keeps its 24 MHz
/// fallback). # SAFETY: `pa` is the bootloader DTB pointer; the read is bounded
/// by the header totalsize and HHDM-mapped. # C: O(dtb)
#[cfg(target_os = "oxide-kernel")]
unsafe fn publish_pl011_clock(pa: u64) {
    if pa == 0 { return; }
    let va = selfboot::ARM_SELFBOOT_HHDM + pa;
    // SAFETY: reads the HHDM-mapped magic+totalsize prefix.
    let ts = unsafe { dtb_totalsize(pa) } as usize;
    if ts < 40 || ts > 4 * 1024 * 1024 { return; }
    // SAFETY: blob bounded by its own header totalsize; HHDM-mapped.
    let blob = unsafe { core::slice::from_raw_parts(va as *const u8, ts) };
    if let Some(hz) = dtb::pl011_clock_hz(blob) {
        hal_aarch64::pl011::set_uartclk_hz(hz);
    }
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
pub(crate) unsafe fn build_boot_info() -> BootInfo {
    // SAFETY: stub returns an owned BootInfo with a static empty
    // memmap; build_selfboot_memmap overlays HHDM + memmap.
    let mut info = unsafe { stub_boot_info() };
    // SAFETY: boot path; reads DTB + linker symbols, fills MEMMAP_STORAGE.
    unsafe { build_selfboot_memmap(&mut info); }
    use hal::TimerOps;
    info.boot_ns = hal_aarch64::ArmTimerOps::monotonic_ns().0;
    // The boot handoff has no CPU table. Keep the same u32 representation
    // consumed by ACPI CPU topology while deriving it from this boot CPU.
    info.bsp_lapic_id = hal_aarch64::mpidr_el1() as u32;
    // ACPI RSDP from the EFI config table (efi_stub) → the kernel decodes
    // MCFG (PCI ECAM → virtio-blk/net/gpu) + MADT. 0 on the booti/-kernel
    // path (which has no ACPI). The kernel reads `rsdp_pa` AS A VA (only the
    // XSDT walk re-adds HHDM), so surface the HHDM-mapped VA, not the raw
    // physical — else it faults reading the bare PA.
    let efi_rsdp = selfboot::EFI_RSDP_PA.load(core::sync::atomic::Ordering::Acquire);
    info.rsdp_pa = if efi_rsdp != 0 { selfboot::ARM_SELFBOOT_HHDM + efi_rsdp } else { 0 };
    info
}

/// Publish the PSCI AP-startup parameters to `hal_aarch64::smp` before
/// `kernel_main` brings APs up. Computes the physical addresses of the
/// self-boot page tables (`phys = VA - KERNEL_BASE + load_base`, since the
/// image maps KB→load_base linearly) and enumerates the DTB `/cpus` MPIDR
/// list. No-op (→ SMP=1) when the load base is unknown or the DTB has no
/// secondary CPUs.
/// # SAFETY: boot path, single-CPU, pre-SMP; reads `.global` self-boot page
/// table symbols + the HHDM-mapped DTB; `set_psci_ap_params` copies into a
/// boot-owned static.
/// # C: O(dtb)
#[cfg(target_os = "oxide-kernel")]
pub(crate) unsafe fn publish_psci_ap_params() {
    extern "C" {
        static _sb_ap_l0: u8;
        static _sb_ttbr0_l0: u8;
        static _sb_ttbr1_l0: u8;
    }
    const KERNEL_BASE: u64 = 0xFFFF_FFFF_8000_0000;
    let load_base = selfboot::SB_LOAD_BASE.load(core::sync::atomic::Ordering::Acquire);
    if load_base == 0 { return; }
    let to_pa = |va: u64| va - KERNEL_BASE + load_base;
    // `.global` self-boot BSS page tables, mapped at their linked high VA;
    // addr_of! only takes the address (no read), so it needs no unsafe.
    let ap_l0_pa = to_pa(core::ptr::addr_of!(_sb_ap_l0) as u64);
    let ttbr1_pa = to_pa(core::ptr::addr_of!(_sb_ttbr1_l0) as u64);
    let ttbr0_kernel_pa = to_pa(core::ptr::addr_of!(_sb_ttbr0_l0) as u64);
    let pa = DTB_PHYS_ADDR.load(core::sync::atomic::Ordering::Acquire);
    let mut mpidrs = [0u64; 16];
    // SAFETY: header read bounds the blob; HHDM-mapped DTB (0 if no DTB).
    let ts = if pa != 0 { (unsafe { dtb_totalsize(pa) }) as usize } else { 0 };
    let n = if pa != 0 && ts != 0 && ts <= 4 * 1024 * 1024 {
        let va = selfboot::ARM_SELFBOOT_HHDM + pa;
        // SAFETY: blob bounded by its own totalsize; HHDM-mapped.
        let blob = unsafe { core::slice::from_raw_parts(va as *const u8, ts) };
        dtb::enum_cpus(blob, &mut mpidrs)
    } else { 0 };
    let n = n.min(mpidrs.len());
    hal_aarch64::smp::set_psci_ap_params(ap_l0_pa, ttbr1_pa, ttbr0_kernel_pa, load_base, &mpidrs[..n]);
}
