// Kernel library. The actual binary is the per-arch boot crate
// (`crates/boot-x86_64`, `crates/boot-aarch64`) which provides the
// arch `_start` symbol, sets up a minimal env, then tail-calls
// `kernel_main`.
//
// This library is `#![no_std]`; it compiles on host so hosted unit
// tests can exercise everything that doesn't require asm.
//
// Phase 0 exit goal per `00§3`: hello-world boots both arches via
// QEMU, prints "init started" on UART, exits cleanly. The string is
// emitted here; the UART backend is wired by the per-arch boot
// crate.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

pub mod acpi;
#[cfg(target_arch = "aarch64")]
pub mod arm_timer;
#[cfg(target_arch = "aarch64")]
pub mod gic;
#[cfg(target_arch = "x86_64")]
pub mod lapic;
#[cfg(target_arch = "aarch64")]
pub mod pl011;
pub mod pmm_setup;

/// Kernel-wide heap allocator per `12§2`. Fixed-size BSS heap for v1;
/// replaced by PMM-backed slab routing once a binary stage exists.
/// Hosts the `BTreeMap` / `Vec` machinery used by `vmm::VmaTree` and
/// later subsystems.
///
/// Gated `cfg(target_os = "oxide-kernel")` so the declaration is
/// active only when building for the kernel targets in `targets/`.
/// Host builds (used by hosted tests in this and downstream crates)
/// keep `std`'s default allocator.
#[cfg(target_os = "oxide-kernel")]
#[global_allocator]
static GLOBAL_ALLOC: kalloc::KAlloc = kalloc::KAlloc::new();

/// Boot info passed by the arch boot stub.
///
/// Layout is bootloader-defined per `36`; the stub parses the
/// bootloader-specific blob (Limine info on x86_64, DTB/EDK2 on
/// aarch64) and hands a uniform view to the kernel.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct BootInfo {
    /// Number of memory map entries.
    pub memmap_count: u32,
    /// Pointer to a `[BootMemRegion; memmap_count]`.
    pub memmap_ptr: *const BootMemRegion,
    /// Bootloader-provided initial entropy (RDRAND on x86; RNDR on
    /// arm; bootloader-collected jitter as fallback).
    pub seed: [u8; 32],
    /// Boot-time monotonic counter snapshot in nanoseconds.
    pub boot_ns: u64,
    /// Higher-half direct-map offset (Limine HHDM, `36§3`). For any
    /// physical address `pa` covered by HHDM, the kernel-VA mirror
    /// is `hhdm_offset + pa`. `0` means the bootloader did not
    /// populate the HHDM response (early-boot diagnostics, hosted
    /// tests, or stub paths).
    pub hhdm_offset: u64,
    /// Physical address of the ACPI RSDP table, or 0 if the
    /// bootloader did not surface one (no UEFI / no ACPI on this
    /// platform).
    pub rsdp_pa: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct BootMemRegion {
    pub base_pa: u64,
    pub len: u64,
    pub kind: BootMemKind,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BootMemKind {
    Usable = 0,
    Reserved = 1,
    AcpiReclaim = 2,
    AcpiNvs = 3,
    BadMem = 4,
    BootloaderUsed = 5,
    KernelImage = 6,
    Initramfs = 7,
}

/// Kernel entry. Called by per-arch boot stub after low-level setup.
///
/// # SAFETY: caller has set up a valid kernel stack, mapped the kernel
/// image at the upper-half virtual address per the linker script, set
/// per-CPU base register, and disabled interrupts. `info` points to a
/// valid `BootInfo` whose `memmap_ptr` references valid memory for at
/// least `memmap_count` entries.
///
/// # C: not measured (one-shot init)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn kernel_main(info: &BootInfo) -> ! {
    // Bring up the kernel heap before any subsystem that allocates.
    // SAFETY: kernel_main is called once per boot from a single CPU
    // with IRQs off; `STATIC_HEAP` is BSS-resident, exclusively owned
    // by `kalloc`, and not yet referenced by anything else.
    #[cfg(target_os = "oxide-kernel")]
    unsafe { GLOBAL_ALLOC.init_static() };

    klog::kinfo!("init started");
    if info.hhdm_offset != 0 {
        klog::kinfo!("hhdm: present");
    } else {
        klog::kinfo!("hhdm: absent");
    }
    if info.rsdp_pa != 0 {
        klog::write_raw(b"[INFO]  rsdp: ");
        klog::write_hex_u64(info.rsdp_pa);
        klog::write_raw(b"\n");
        // SAFETY: `info.rsdp_pa` is the Limine-supplied kernel VA
        // for the RSDP (HHDM-mapped); the bootloader keeps the
        // backing memory alive past kernel handoff per `36§3`.
        unsafe { acpi::try_log_acpi(info.rsdp_pa, info.hhdm_offset); }
    } else {
        klog::kinfo!("rsdp: absent");
    }
    if info.memmap_count != 0 {
        klog::kinfo!("memmap: present");
        // SAFETY: kernel_main fn-contract guarantees memmap_ptr is a
        // valid slice of length memmap_count for this call.
        let regions: &[BootMemRegion] = unsafe {
            core::slice::from_raw_parts(info.memmap_ptr, info.memmap_count as usize)
        };
        log_memmap(regions);
    } else {
        klog::kinfo!("memmap: absent");
    }

    // Bring up the physical memory manager.
    // SAFETY: kernel_main fn-contract; single-CPU, IRQs off, info
    // outlives the call.
    let pmm = unsafe { pmm_setup::init_from_boot_info(info) };
    match &pmm {
        Ok(_)                                       => klog::kinfo!("pmm: ready"),
        Err(pmm_setup::SetupError::NoMemmap)        => klog::kinfo!("pmm: skip (no memmap)"),
        Err(pmm_setup::SetupError::NoHhdm)          => klog::kinfo!("pmm: skip (no hhdm)"),
        Err(pmm_setup::SetupError::NoUsableRegion)  => klog::kerror!("pmm: no usable region"),
        Err(pmm_setup::SetupError::NoSpaceForBitmaps) => klog::kerror!("pmm: pool too big"),
        Err(pmm_setup::SetupError::TooManyRegions)  => klog::kerror!("pmm: too many regions"),
        Err(pmm_setup::SetupError::PmmInit(_))      => klog::kerror!("pmm: Pmm::init refused"),
        Err(pmm_setup::SetupError::AlreadyInit)     => klog::kerror!("pmm: already init"),
    }
    // Runtime smoke: alloc/free at order 0 to prove the buddy
    // machinery works after init. Removed once a real consumer
    // (slab) wires in.
    if let Ok(p) = pmm {
        match p.alloc(pmm::Order(0)) {
            Ok(pfn) => {
                klog::kinfo!("pmm-smoke: alloc(0) ok");
                // SAFETY: pfn was just returned by alloc(0); free is
                // the matching counterpart and is single-threaded
                // here per pre-init contract.
                unsafe { p.free(pfn, pmm::Order(0)); }
                klog::kinfo!("pmm-smoke: free(0) ok");
            }
            Err(_) => klog::kerror!("pmm-smoke: alloc(0) failed"),
        }
        // Memory summary: `pmm: <free_mib> MiB free, <alloc> page(s) reserved`.
        let free_pages = p.free_pages();
        let alloc_pages = p.allocated_pages();
        // 4 KiB pages -> MiB: pages * 4096 / (1024*1024) = pages / 256.
        let free_mib = free_pages / 256;
        klog::write_raw(b"[INFO]  pmm: ");
        klog::write_dec_u64(free_mib);
        klog::write_raw(b" MiB free, ");
        klog::write_dec_u64(alloc_pages);
        klog::write_raw(b" page(s) reserved\n");

        // PMM stress: alloc 64 order-0 pages, free in reverse, verify
        // free_pages count matches the baseline. Catches simple
        // bookkeeping bugs the single-page smoke can't.
        const STRESS_N: usize = 64;
        let baseline = p.free_pages();
        let mut buf: [hal::Pfn; STRESS_N] = [hal::Pfn(0); STRESS_N];
        let mut got = 0usize;
        while got < STRESS_N {
            match p.alloc(pmm::Order(0)) {
                Ok(pfn) => { buf[got] = pfn; got += 1; }
                Err(_)  => break,
            }
        }
        // SAFETY: every pfn in `buf[..got]` was returned by alloc(0)
        // above and not yet freed; reverse-order frees match the
        // alloc count exactly.
        unsafe {
            while got > 0 {
                got -= 1;
                p.free(buf[got], pmm::Order(0));
            }
        }
        let after = p.free_pages();
        if after == baseline {
            klog::kinfo!("pmm-stress: 64x alloc/free balanced");
        } else {
            klog::kerror!("pmm-stress: free_pages drift");
        }

        // Multi-order stress: one alloc/free per order 0..=10. Exercises
        // the split-and-merge paths the single-order stress can't.
        let baseline_mo = p.free_pages();
        let mut order_buf: [(hal::Pfn, u8); 11] = [(hal::Pfn(0), 0); 11];
        let mut got_mo = 0usize;
        for o in 0u8..=10 {
            match p.alloc(pmm::Order(o)) {
                Ok(pfn) => { order_buf[got_mo] = (pfn, o); got_mo += 1; }
                Err(_)  => break,
            }
        }
        // SAFETY: each pair in `order_buf[..got_mo]` came from a matching
        // `alloc(o)` above; we free with the same order, single-threaded.
        unsafe {
            while got_mo > 0 {
                got_mo -= 1;
                let (pfn, o) = order_buf[got_mo];
                p.free(pfn, pmm::Order(o));
            }
        }
        if p.free_pages() == baseline_mo {
            klog::kinfo!("pmm-stress: orders 0..=10 balanced");
        } else {
            klog::kerror!("pmm-stress: multi-order drift");
        }
        // Re-emit the summary to make the round-trip visible in the trace.
        klog::write_raw(b"[INFO]  pmm: ");
        klog::write_dec_u64(p.free_pages() / 256);
        klog::write_raw(b" MiB free post-stress, ");
        klog::write_dec_u64(p.allocated_pages());
        klog::write_raw(b" page(s) reserved\n");

        // Device-mapping smoke: install a Device-attr 4 KiB MMIO
        // page using a PMM-backed frame allocator, then read one
        // 32-bit register from the new VA.
        #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
        smoke_device_map_x86(p, info.hhdm_offset);
        #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
        smoke_device_map_arm(p, info.hhdm_offset);
    }


    // kalloc smoke: insert a VMA into a `vmm::VmaTree`, exercising
    // the global allocator's `BTreeMap` path.
    #[cfg(target_os = "oxide-kernel")]
    {
        let mut tree = vmm::VmaTree::new();
        // SAFETY: addresses are within the user-VA range (0x1000 < USER_VA_END).
        let start = hal::UserVirtAddr::new(0x1000).expect("test addr in user range");
        let end   = hal::UserVirtAddr::new(0x2000).expect("test addr in user range");
        if tree.insert(vmm::Vma::new(
            start, end,
            vmm::VmaProt::READ,
            vmm::VmaFlags::PRIVATE | vmm::VmaFlags::ANONYMOUS,
            vmm::VmaBacking::Anonymous,
        )).is_ok() {
            klog::kinfo!("kalloc-smoke: VmaTree insert ok");
        } else {
            klog::kerror!("kalloc-smoke: VmaTree insert failed");
        }
    }

    klog::kinfo!("boot: kernel ready, halting");
    halt_forever()
}

/// Map `BootMemKind` to a short ASCII tag for memmap dumps.
fn kind_tag(k: BootMemKind) -> &'static [u8] {
    match k {
        BootMemKind::Usable         => b"USABLE",
        BootMemKind::Reserved       => b"RESV  ",
        BootMemKind::AcpiReclaim    => b"ACPI-R",
        BootMemKind::AcpiNvs        => b"ACPI-N",
        BootMemKind::BadMem         => b"BAD   ",
        BootMemKind::BootloaderUsed => b"BL-USE",
        BootMemKind::KernelImage    => b"KERNEL",
        BootMemKind::Initramfs      => b"INITRD",
    }
}

/// Emit one line per memmap region. Cheap O(N) at boot.
fn log_memmap(regions: &[BootMemRegion]) {
    let mut usable_bytes: u64 = 0;
    let mut reserved_bytes: u64 = 0;
    let mut bootloader_bytes: u64 = 0;
    for r in regions {
        klog::write_raw(b"[INFO]    ");
        klog::write_raw(kind_tag(r.kind));
        klog::write_raw(b" base=");
        klog::write_hex_u64(r.base_pa);
        klog::write_raw(b" len=");
        klog::write_hex_u64(r.len);
        klog::write_raw(b"\n");
        match r.kind {
            BootMemKind::Usable         => usable_bytes     = usable_bytes.saturating_add(r.len),
            BootMemKind::BootloaderUsed => bootloader_bytes = bootloader_bytes.saturating_add(r.len),
            BootMemKind::Reserved
            | BootMemKind::AcpiNvs
            | BootMemKind::AcpiReclaim
            | BootMemKind::BadMem
            | BootMemKind::KernelImage
            | BootMemKind::Initramfs    => reserved_bytes   = reserved_bytes.saturating_add(r.len),
        }
    }
    klog::write_raw(b"[INFO]    memmap totals: ");
    klog::write_dec_u64(usable_bytes / (1024 * 1024));
    klog::write_raw(b" MiB usable, ");
    klog::write_dec_u64(bootloader_bytes / (1024 * 1024));
    klog::write_raw(b" MiB bootloader-reclaim, ");
    klog::write_dec_u64(reserved_bytes / (1024 * 1024));
    klog::write_raw(b" MiB reserved\n");
}

/// Kernel device-mapping base VA. Per `21§5` we carve a 4 GiB
/// sub-region of L4 slot 0x1FE: `VA = KERNEL_DEVICE_BASE | (pa & 0xFFFFFFFF)`.
/// Disjoint from HHDM (L4[0..0x100]) and kernel image (L4[0x1FF]).
#[cfg(target_os = "oxide-kernel")]
const KERNEL_DEVICE_BASE: u64 = 0xffff_ff00_0000_0000;

/// HPET phys base on QEMU q35 (matches MADT log).
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
const HPET_PHYS: u64 = 0xfed0_0000;
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
const HPET_VA: u64 = KERNEL_DEVICE_BASE | (HPET_PHYS & 0xFFFF_FFFF);

/// LAPIC phys base (matches MADT `madt lapic_pa=…`).
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
const LAPIC_PHYS: u64 = 0xfee0_0000;
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
const LAPIC_VA: u64 = KERNEL_DEVICE_BASE | (LAPIC_PHYS & 0xFFFF_FFFF);

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn smoke_device_map_x86(
    p: &'static pmm::Pmm<pmm_setup::HhdmBacking>,
    hhdm: u64,
) {
    let alloc = || p.alloc(pmm::Order(0)).ok().map(|pfn| pfn.0 * 4096);
    // SAFETY: single-CPU, IRQs off, PMM owns its frames; we splice
    // a 4 KiB Device-attr leaf into the kernel-half of the live PML4.
    let r = unsafe {
        hal_x86_64::vmm::map_device_4k(HPET_VA, HPET_PHYS, hhdm, alloc)
    };
    match r {
        Ok(()) => {
            // SAFETY: HPET_VA was just mapped Device-attr; the read is
            // a volatile MMIO load of HPET_GCAP_ID at offset 0.
            let cap = unsafe { core::ptr::read_volatile(HPET_VA as *const u32) };
            klog::write_raw(b"[INFO]  device-map: hpet cap=");
            klog::write_hex_u64(cap as u64);
            klog::write_raw(b"\n");
        }
        Err(_) => klog::kerror!("device-map: x86 map_device_4k failed"),
    }

    // LAPIC enable. Map → set IA32_APIC_BASE.E + SVR.SW_ENABLE → log
    // APIC ID + version.
    let alloc2 = || p.alloc(pmm::Order(0)).ok().map(|pfn| pfn.0 * 4096);
    // SAFETY: chosen kernel VA disjoint from existing mappings; phys
    // 0xFEE00000 is the standard LAPIC base from MADT.
    let lr = unsafe {
        hal_x86_64::vmm::map_device_4k(LAPIC_VA, LAPIC_PHYS, hhdm, alloc2)
    };
    match lr {
        Ok(()) => {
            // SAFETY: LAPIC_VA is freshly Device-attr mapped; single-CPU.
            let s = unsafe { lapic::enable(LAPIC_VA) };
            match s {
                lapic::LapicStatus::AlreadyOn => klog::kinfo!("lapic: already on"),
                lapic::LapicStatus::Enabled { apic_id, version } => {
                    klog::write_raw(b"[INFO]  lapic: enabled apic_id=");
                    klog::write_dec_u64(apic_id as u64);
                    klog::write_raw(b" version=");
                    klog::write_hex_u64(version as u64);
                    klog::write_raw(b"\n");
                    // Polled-timer smoke: verify count register decrements.
                    // SAFETY: lapic::enable just succeeded so LAPIC is live.
                    if let Some((a, b)) = unsafe { lapic::timer_smoke(0xFFFF_FFFF) } {
                        klog::write_raw(b"[INFO]  lapic: timer ");
                        klog::write_hex_u64(a as u64);
                        klog::write_raw(b" -> ");
                        klog::write_hex_u64(b as u64);
                        klog::write_raw(if b < a { b" (counting)\n" } else { b" (stuck)\n" });
                    }
                }
            }
        }
        Err(_) => klog::kerror!("device-map: lapic map_device_4k failed"),
    }
}

/// GICv2 distributor base on QEMU virt (matches MADT log).
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
const GICD_PHYS: u64 = 0x0800_0000;
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
const GICD_VA: u64 = KERNEL_DEVICE_BASE | (GICD_PHYS & 0xFFFF_FFFF);

/// GICv2 CPU-interface base on QEMU virt (GICD + 0x10000 by convention).
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
const GICC_PHYS: u64 = 0x0801_0000;
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
const GICC_VA: u64 = KERNEL_DEVICE_BASE | (GICC_PHYS & 0xFFFF_FFFF);

/// PL011 phys base on QEMU virt (matches SPCR log).
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
const PL011_PHYS: u64 = 0x0900_0000;
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
const PL011_VA: u64 = KERNEL_DEVICE_BASE | (PL011_PHYS & 0xFFFF_FFFF);

#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
fn smoke_device_map_arm(
    p: &'static pmm::Pmm<pmm_setup::HhdmBacking>,
    hhdm: u64,
) {
    let alloc = || p.alloc(pmm::Order(0)).ok().map(|pfn| pfn.0 * 4096);
    // SAFETY: same contract as the x86 smoke — TTBR1_EL1 active, single-CPU, IRQs off.
    let r = unsafe {
        hal_aarch64::vmm::map_device_4k(GICD_VA, GICD_PHYS, hhdm, alloc)
    };
    match r {
        Ok(()) => {
            // SAFETY: GICD_VA was just mapped Device-nGnRnE; read GICD_TYPER at offset 4.
            let typer = unsafe { core::ptr::read_volatile((GICD_VA + 0x4) as *const u32) };
            klog::write_raw(b"[INFO]  device-map: gicd typer=");
            klog::write_hex_u64(typer as u64);
            klog::write_raw(b"\n");
        }
        Err(_) => klog::kerror!("device-map: arm map_device_4k failed"),
    }

    // GICv2 enable: map GICC and program both halves.
    let alloc_c = || p.alloc(pmm::Order(0)).ok().map(|pfn| pfn.0 * 4096);
    // SAFETY: same contract; GICC at GICD+0x10000 on QEMU virt.
    let cr = unsafe {
        hal_aarch64::vmm::map_device_4k(GICC_VA, GICC_PHYS, hhdm, alloc_c)
    };
    if cr.is_ok() {
        // SAFETY: both VAs are freshly Device-attr mapped; single-CPU pre-init.
        let s = unsafe { gic::enable(GICD_VA, GICC_VA) };
        match s {
            gic::GicStatus::AlreadyOn => klog::kinfo!("gic: already on"),
            gic::GicStatus::Enabled { typer, gicd_iidr, gicc_iidr } => {
                klog::write_raw(b"[INFO]  gic: enabled typer=");
                klog::write_hex_u64(typer as u64);
                klog::write_raw(b" gicd_iidr=");
                klog::write_hex_u64(gicd_iidr as u64);
                klog::write_raw(b" gicc_iidr=");
                klog::write_hex_u64(gicc_iidr as u64);
                klog::write_raw(b"\n");
                // Polled-timer smoke: virtual generic-timer
                // counts down from 0xFFFF_FFFF over a brief spin.
                // SAFETY: timer is unprivileged sysreg-only; no IRQ delivery (IMASK set).
                if let Some((a, b)) = unsafe { arm_timer::timer_smoke(0xFFFF_FFFF) } {
                    klog::write_raw(b"[INFO]  arm-timer: tval ");
                    klog::write_hex_u64(a as u64);
                    klog::write_raw(b" -> ");
                    klog::write_hex_u64(b as u64);
                    klog::write_raw(if b < a { b" (counting)\n" } else { b" (stuck)\n" });
                }
            }
        }
    } else {
        klog::kerror!("device-map: gicc map_device_4k failed");
    }

    // Map PL011 + swap klog sink from semihosting to the real UART.
    let alloc2 = || p.alloc(pmm::Order(0)).ok().map(|pfn| pfn.0 * 4096);
    // SAFETY: same contract; chosen kernel VA disjoint from existing
    // mappings; phys 0x09000000 is the QEMU virt PL011 base from SPCR.
    let pr = unsafe {
        hal_aarch64::vmm::map_device_4k(PL011_VA, PL011_PHYS, hhdm, alloc2)
    };
    match pr {
        Ok(()) => {
            // SAFETY: PL011_VA is freshly mapped Device-nGnRnE,
            // covering 4 KiB; we own the device pre-init.
            unsafe { pl011::enable(PL011_VA); }
            klog::set_byte_sink(pl011::pl011_emit);
            klog::kinfo!("pl011: switched klog sink to real UART");
        }
        Err(_) => klog::kerror!("device-map: pl011 map_device_4k failed"),
    }
}

/// Park the CPU forever. On the kernel target, uses the per-arch
/// halt instruction (`hlt` / `wfi`) so the host doesn't burn 100%
/// CPU cycling on a spin loop. Host fallback keeps `spin_loop` for
/// hosted unit-test compatibility.
///
/// # C: O(∞)
pub fn halt_forever() -> ! {
    loop {
        #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
        // SAFETY: `hlt` parks the core until next IRQ; legal at CPL=0.
        unsafe { core::arch::asm!("hlt", options(nomem, nostack, preserves_flags)); }
        #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
        // SAFETY: `wfi` parks the core until any wake event; unprivileged at EL1.
        unsafe { core::arch::asm!("wfi", options(nomem, nostack, preserves_flags)); }
        #[cfg(not(target_os = "oxide-kernel"))]
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_info_layout_is_repr_c() {
        // Sanity check: BootInfo size is determinist on a 64-bit host.
        // u32 + ptr + [u8;32] + u64 + u64 with natural alignment.
        assert!(core::mem::size_of::<BootInfo>() >= 60);
    }

    #[test]
    fn boot_mem_kind_distinct() {
        assert_ne!(BootMemKind::Usable as u8, BootMemKind::BadMem as u8);
    }
}
