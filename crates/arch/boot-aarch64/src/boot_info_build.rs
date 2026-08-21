// DTB parsing is reached only from the `oxide-kernel` boot path below.
#[cfg(target_os = "oxide-kernel")]
use crate::dtb;
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
use crate::selfboot;
use core::cell::UnsafeCell;
use boot_info::{BootFramebuffer, BootInfo, BootMemRegion};

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
mod dtb_helpers;
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
use dtb_helpers::{acpi_extent, dtb_totalsize, publish_pl011_clock, read_dtb_memory_all};
mod efi_topology;
mod memmap;

/// Prefer a DT simple-framebuffer when it exists, otherwise retain the GOP
/// surface captured by the EFI stub.  Some EFI firmware supplies a DTB for
/// memory discovery without describing its active display there.
fn select_framebuffer(dtb: Option<BootFramebuffer>, efi: BootFramebuffer) -> BootFramebuffer {
    dtb.unwrap_or(efi)
}

static EMPTY_BOOT_REGIONS: [BootMemRegion; 0] = [];

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
static MEMMAP_WORKSPACE: MemmapStorage = MemmapStorage(UnsafeCell::new([
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
    BootInfo {
        memmap_count: 0,
        memmap_ptr: EMPTY_BOOT_REGIONS.as_ptr(),
        seed: [0; 32],
        boot_ns: 0,
        hhdm_offset: 0,
        rsdp_pa: 0,
        framebuffer: boot_info::BootFramebuffer::EMPTY,
        dtb_pa: 0, dtb_len: 0, dtb_crc32: 0, bsp_lapic_id: 0,
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

/// Static handoff storage keeps BootInfo growth out of the fixed boot stack.
/// The boot CPU is the sole writer and publishes one shared reference only
/// after the DTB/EFI fields are complete.
#[cfg(target_os = "oxide-kernel")]
struct BootInfoStorage(UnsafeCell<BootInfo>);
#[cfg(target_os = "oxide-kernel")]
unsafe impl Sync for BootInfoStorage {}
#[cfg(target_os = "oxide-kernel")]
static BOOT_INFO_STORAGE: BootInfoStorage = BootInfoStorage(UnsafeCell::new(BootInfo {
    memmap_count: 0,
    memmap_ptr: EMPTY_BOOT_REGIONS.as_ptr(),
    seed: [0; 32],
    boot_ns: 0,
    hhdm_offset: 0,
    rsdp_pa: 0,
    framebuffer: boot_info::BootFramebuffer::EMPTY,
    dtb_pa: 0, dtb_len: 0, dtb_crc32: 0, bsp_lapic_id: 0,
    _pad: 0,
}));

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
    // SAFETY: DTB pointer from bootloader x0; the header's totalsize bounds
    // the safe read. Read 8 bytes first to learn totalsize — `parse_header`
    // cannot serve that, because its `totalsize <= len` check rejects every
    // prefix, so asking it here rejected EVERY blob and `/chosen/bootargs`
    // was never once read on the path that carries it.
    let head: &[u8] = unsafe {
        core::slice::from_raw_parts(va as *const u8, 8)
    };
    // SAFETY: the closure forms the full-blob slice only for the length the
    // header itself declared, at the HHDM-mapped address the bootloader gave.
    let args = match dtb::bootargs_via_prefix(head, |ts| unsafe {
        Some(core::slice::from_raw_parts(va as *const u8, ts))
    }) {
        Some(s) => s, None => return,
    };
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

    let empty = BootMemRegion { base_pa: 0, len: 0,
        kind: boot_info::BootMemKind::Reserved };
    // SAFETY: boot is single-CPU and this unpublished workspace is disjoint
    // from the retained MEMMAP_STORAGE consumed after this function returns.
    let regions = unsafe { &mut *MEMMAP_WORKSPACE.0.get() };
    regions.fill(empty);
    let nregions;
    let mut acpi_blk = (0, 0);
    // Publish the DTB-resolved PL011 UARTCLK before consuming the memmap, so the
    // runtime UART driver's baud reprogram uses the real reference clock.
    // SAFETY: pa is the bootloader DTB pointer; helper bounds reads by header.
    unsafe { publish_pl011_clock(pa); }
    if let Some((map_pa, map_size, desc_size, _)) = selfboot::retained_efi_memmap() {
        let map_va = selfboot::ARM_SELFBOOT_HHDM.checked_add(map_pa)
            .expect("ARM EFI map address overflow");
        // SAFETY: EFI stub retained exactly `map_size` bytes in the loaded
        // kernel image, whose physical extent is HHDM-mapped for this boot.
        let bytes = unsafe { core::slice::from_raw_parts(map_va as *const u8, map_size as usize) };
        nregions = efi_topology::decode(bytes, desc_size as usize, regions)
            .expect("ARM EFI memory map is malformed or too large");
        // SAFETY: reads HHDM-mapped ACPI tables, each bounded by its header.
        acpi_blk = unsafe { acpi_extent() }.unwrap_or((0, 0));
    } else {
        let mut dt_regions = [(0u64, 0u64); selfboot::EFI_RAM_MAX];
        // SAFETY: pa is the bootloader DTB pointer; helper bounds its walk.
        let mut nr = unsafe { read_dtb_memory_all(pa, &mut dt_regions) }
            .min(dt_regions.len());
        if nr == 0 {
            dt_regions[0] = (0x4000_0000, 0x4000_0000);
            nr = 1;
        }
        for (dst, &(base_pa, len)) in regions.iter_mut().zip(dt_regions[..nr].iter()) {
            *dst = BootMemRegion { base_pa, len, kind: boot_info::BootMemKind::Usable };
        }
        nregions = nr;
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
    let mut n = efi_topology::overlay(&regions[..nregions], &blocks, storage)
        .expect("ARM boot topology exceeds retained capacity");
    // A malformed firmware map must not make the loaded image disappear from
    // physical truth; EFI normally reaches it through the loader descriptor.
    memmap::retain_kernel_image(storage, &mut n, kstart, kend);

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
pub(crate) unsafe fn build_boot_info() -> &'static BootInfo {
    // SAFETY: single-CPU boot is the sole writer of this static handoff;
    // build_selfboot_memmap overlays its initialized empty map in place.
    let info = unsafe { &mut *BOOT_INFO_STORAGE.0.get() };
    // SAFETY: boot path; reads DTB + linker symbols, fills MEMMAP_STORAGE.
    unsafe { build_selfboot_memmap(info); }
    use hal::TimerOps;
    info.boot_ns = hal_aarch64::ArmTimerOps::monotonic_ns().0;
    let efi_framebuffer = selfboot::framebuffer();
    info.framebuffer = efi_framebuffer;
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
    // Retain the device tree: `build_selfboot_memmap` has already carved the
    // blob's pages out of usable RAM, so the firmware region is the kernel's
    // for the rest of the boot and the pair below is a durable handle to it.
    // Publishing it here is what lets the kernel serve the raw blob and the
    // unflattened tree to userspace; a size of 0 (bad magic, absurd length)
    // publishes nothing rather than a pointer nobody can bound.
    let dtb_pa = DTB_PHYS_ADDR.load(core::sync::atomic::Ordering::Acquire);
    // SAFETY: `dtb_pa` is the bootloader DTB pointer; the read is the
    // HHDM-mapped 8-byte header prefix and returns 0 for anything unusable.
    let dtb_len = if dtb_pa != 0 { unsafe { dtb_totalsize(dtb_pa) } } else { 0 };
    info.dtb_pa = if dtb_len != 0 { dtb_pa } else { 0 };
    info.dtb_len = dtb_len;
    let dtb_framebuffer = if dtb_len != 0 {
        let va = selfboot::ARM_SELFBOOT_HHDM + dtb_pa;
        // SAFETY: the validated DTB header bounds this HHDM-mapped blob.
        let blob = unsafe { core::slice::from_raw_parts(va as *const u8, dtb_len as usize) };
        dtb::simple_framebuffer(blob).map(|fb| boot_info::BootFramebuffer {
            base_pa: fb.base_pa, pitch: fb.stride, width: fb.width, height: fb.height,
            bpp: fb.bpp, kind: boot_info::BootFramebufferKind::Rgb,
            red: boot_info::BootFramebufferBitfield { offset: fb.red.0, length: fb.red.1 },
            green: boot_info::BootFramebufferBitfield { offset: fb.green.0, length: fb.green.1 },
            blue: boot_info::BootFramebufferBitfield { offset: fb.blue.0, length: fb.blue.1 }, _pad: [0; 2],
        })
    } else { None };
    info.framebuffer = select_framebuffer(dtb_framebuffer, efi_framebuffer);
    // Checksum taken HERE, at scan time, so the kernel can prove before it
    // publishes anything that the tree it is about to hand userspace is the
    // one the boot stub read (`36§4.1`).
    info.dtb_crc32 = if dtb_len != 0 {
        let va = selfboot::ARM_SELFBOOT_HHDM + dtb_pa;
        // SAFETY: `dtb_pa` names a blob whose own header bounds it at
        // `dtb_len`, HHDM-mapped and reserved in the memmap built above.
        let blob = unsafe { core::slice::from_raw_parts(va as *const u8, dtb_len as usize) };
        crc::crc32_be_update(!0u32, blob)
    } else { 0 };
    // Whether this firmware described itself with a device tree is otherwise
    // invisible until userspace looks for `/sys/firmware/fdt` and does not
    // find it — by which point the answer looks like a kernel bug rather than
    // a machine that is ACPI-only.
    debug_boot! {
        klog::write_raw(b"[INFO]  dtb pa=");
        klog::write_hex_u64(info.dtb_pa);
        klog::write_raw(b" len=");
        klog::write_dec_u64(info.dtb_len);
        klog::write_raw(b"\n");
    }
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

#[cfg(test)]
mod tests {
    use super::select_framebuffer;
    use boot_info::BootFramebuffer;

    #[test]
    fn absent_dtb_framebuffer_keeps_efi_gop() {
        let mut efi = BootFramebuffer::EMPTY;
        efi.base_pa = 0x8_0000_0000;
        assert_eq!(select_framebuffer(None, efi), efi);
    }

    #[test]
    fn dtb_framebuffer_is_preferred_when_available() {
        let mut dtb = BootFramebuffer::EMPTY;
        dtb.base_pa = 0x9_0000_0000;
        let mut efi = BootFramebuffer::EMPTY;
        efi.base_pa = 0x8_0000_0000;
        assert_eq!(select_framebuffer(Some(dtb), efi), dtb);
    }
}
