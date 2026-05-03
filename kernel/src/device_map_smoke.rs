// Per-arch device-MMIO mapping bring-up smokes.
//
// Splices the 4 KiB Device-attr leaves we need (HPET + LAPIC on
// x86; GICD + GICC + PL011 on arm) into the live page tables via
// `hal_<arch>::vmm::map_device_4k`, then enables each device and
// optionally runs a polled-timer + IRQ smoke under the right
// `debug-<sub>` gate.
//
// All call sites are diagnostic / gated; the device-mapping calls
// themselves are always-on production bring-up. The actual
// per-arch IRQ infrastructure (LAPIC enable, GIC enable, IRQ
// periodic-timer arm/disarm) lives in `lapic.rs` / `gic.rs`.

use crate::{pmm_setup};

/// Kernel device-mapping base VA. Per `21§5` we carve a 4 GiB
/// sub-region of L4 slot 0x1FE: `VA = KERNEL_DEVICE_BASE | (pa & 0xFFFFFFFF)`.
/// Disjoint from HHDM (L4[0..0x100]) and kernel image (L4[0x1FF]).
#[cfg(target_os = "oxide-kernel")]
pub const KERNEL_DEVICE_BASE: u64 = 0xffff_ff00_0000_0000;

// ---------------------------------------------------------------------------
// x86_64
// ---------------------------------------------------------------------------

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

/// x86 device-MMIO bring-up smoke. Maps HPET + LAPIC at fixed
/// kernel-VA, enables LAPIC, runs the polled + IRQ-driven timer
/// smokes (gated `debug-vmm` / `debug-irq`).
/// # SAFETY: caller is the boot path; allocator up; PMM ready;
/// single-CPU; IRQs masked at entry.
/// # C: O(walk depth × 2) for the maps; spin loops dominate runtime.
/// # Ctx: pre-init, IRQ-off (entry), single-CPU
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub fn smoke_device_map_x86(
    p: &'static pmm::Pmm<pmm_setup::HhdmBacking>,
    hhdm: u64,
) {
    use crate::lapic;
    let alloc = || p.alloc(pmm::Order(0)).ok().map(|pfn| pfn.0 * 4096);
    // SAFETY: single-CPU, IRQs off, PMM owns its frames; we splice
    // a 4 KiB Device-attr leaf into the kernel-half of the live PML4.
    let r = unsafe {
        hal_x86_64::vmm::map_device_4k(HPET_VA, HPET_PHYS, hhdm, alloc)
    };
    match r {
        Ok(()) => {
            debug_vmm! {
                // SAFETY: HPET_VA was just mapped Device-attr; the read is
                // a volatile MMIO load of HPET_GCAP_ID at offset 0.
                let cap = unsafe { core::ptr::read_volatile(HPET_VA as *const u32) };
                klog::write_raw(b"[INFO]  device-map: hpet cap=");
                klog::write_hex_u64(cap as u64);
                klog::write_raw(b"\n");
            }
        }
        Err(_) => { debug_vmm! { klog::kerror!("device-map: x86 map_device_4k failed"); } }
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
                lapic::LapicStatus::AlreadyOn => { debug_irq! { klog::kinfo!("lapic: already on"); } }
                lapic::LapicStatus::Enabled { apic_id: _apic_id, version: _version } => {
                    debug_irq! {
                        klog::write_raw(b"[INFO]  lapic: enabled apic_id=");
                        klog::write_dec_u64(_apic_id as u64);
                        klog::write_raw(b" version=");
                        klog::write_hex_u64(_version as u64);
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
                        // Periodic timer + STI: take real timer IRQs at
                        // vec 0x40 for a brief observation window.
                        let pre = lapic::TICK_COUNT.load(core::sync::atomic::Ordering::Relaxed);
                        // SAFETY: LAPIC enabled, IDT[0x40] -> IRQ stub
                        // (per #124), oxide_irq_dispatch handles EOI.
                        if unsafe { lapic::timer_periodic(1_000_000) } {
                            // SAFETY: STI legal at CPL=0; pairs with the
                            // CLI below; ticks fire during the spin.
                            unsafe { core::arch::asm!("sti", options(nomem, nostack)); }
                            for _ in 0..10_000_000 { core::hint::spin_loop(); }
                            // SAFETY: CLI restores the pre-STI state
                            // (IF clear) before further bring-up steps.
                            unsafe { core::arch::asm!("cli", options(nomem, nostack)); }
                        }
                        let post = lapic::TICK_COUNT.load(core::sync::atomic::Ordering::Relaxed);
                        klog::write_raw(b"[INFO]  lapic: timer ticks=");
                        klog::write_dec_u64(post.wrapping_sub(pre));
                        klog::write_raw(b"\n");
                    }
                }
            }
        }
        Err(_) => { debug_vmm! { klog::kerror!("device-map: lapic map_device_4k failed"); } }
    }
}

// ---------------------------------------------------------------------------
// aarch64
// ---------------------------------------------------------------------------

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

/// arm device-MMIO bring-up smoke. Maps GICD + GICC + PL011,
/// enables GICv2, swaps the klog sink from semihosting to PL011,
/// runs the polled + IRQ-driven timer smokes (gated `debug-vmm`/
/// `debug-irq`/`debug-boot`).
/// # SAFETY: caller is the boot path; allocator up; PMM ready;
/// single-CPU; IRQs masked at entry.
/// # C: O(walk depth × 3) for the maps; spin loops dominate runtime.
/// # Ctx: pre-init, IRQ-off (entry), single-CPU
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
pub fn smoke_device_map_arm(
    p: &'static pmm::Pmm<pmm_setup::HhdmBacking>,
    hhdm: u64,
) {
    use crate::{arm_timer, gic, pl011};
    let alloc = || p.alloc(pmm::Order(0)).ok().map(|pfn| pfn.0 * 4096);
    // SAFETY: same contract as the x86 smoke — TTBR1_EL1 active, single-CPU, IRQs off.
    let r = unsafe {
        hal_aarch64::vmm::map_device_4k(GICD_VA, GICD_PHYS, hhdm, alloc)
    };
    match r {
        Ok(()) => {
            debug_vmm! {
                // SAFETY: GICD_VA was just mapped Device-nGnRnE; read GICD_TYPER at offset 4.
                let typer = unsafe { core::ptr::read_volatile((GICD_VA + 0x4) as *const u32) };
                klog::write_raw(b"[INFO]  device-map: gicd typer=");
                klog::write_hex_u64(typer as u64);
                klog::write_raw(b"\n");
            }
        }
        Err(_) => { debug_vmm! { klog::kerror!("device-map: arm map_device_4k failed"); } }
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
            gic::GicStatus::AlreadyOn => { debug_irq! { klog::kinfo!("gic: already on"); } }
            gic::GicStatus::Enabled { typer: _typer, gicd_iidr: _gicd_iidr, gicc_iidr: _gicc_iidr } => {
                debug_irq! {
                    klog::write_raw(b"[INFO]  gic: enabled typer=");
                    klog::write_hex_u64(_typer as u64);
                    klog::write_raw(b" gicd_iidr=");
                    klog::write_hex_u64(_gicd_iidr as u64);
                    klog::write_raw(b" gicc_iidr=");
                    klog::write_hex_u64(_gicc_iidr as u64);
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
        }
    } else {
        debug_vmm! { klog::kerror!("device-map: gicc map_device_4k failed"); }
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
            debug_boot! {
                klog::set_byte_sink(pl011::pl011_emit);
                klog::kinfo!("pl011: switched klog sink to real UART");
            }
        }
        Err(_) => { debug_vmm! { klog::kerror!("device-map: pl011 map_device_4k failed"); } }
    }

    // ARM virtual generic-timer IRQ smoke. Pure diagnostic — gated.
    // Production timer arming will live alongside scheduler bring-up.
    debug_irq! {
        let pre = gic::TICK_COUNT.load(core::sync::atomic::Ordering::Relaxed);
        // SAFETY: GIC is mapped + enabled; INTID 27 is the QEMU-virt CNTV PPI.
        unsafe { gic::enable_intid(27); }
        // SAFETY: timer sysregs are unprivileged at EL1; INTID 27 was just enabled at the distributor.
        unsafe { arm_timer::timer_periodic(10_000); }
        // SAFETY: opening DAIF.I lets the GIC deliver the CNTV line via VBAR_EL1[0x280] → oxide_arm_irq_dispatch.
        unsafe { core::arch::asm!("msr daifclr, #2", options(nomem, nostack, preserves_flags)); }
        for _ in 0..2_000_000 { core::hint::spin_loop(); }
        // Mid-spin diag: ISTATUS in CNTV_CTL, GICD_ISPENDR0 PPI bits, DAIF.
        let (mid_ctl, mid_daif): (u64, u64);
        // SAFETY: pure mrs reads of unprivileged sysregs.
        unsafe {
            core::arch::asm!("mrs {v}, cntv_ctl_el0", v = out(reg) mid_ctl, options(nomem, nostack, preserves_flags));
            core::arch::asm!("mrs {v}, daif", v = out(reg) mid_daif, options(nomem, nostack, preserves_flags));
        }
        // SAFETY: GICD was mapped Device-attr; ISPENDR0 + ISACTIVER0 are within the 4 KiB.
        let (ispend, isactive) = unsafe {
            (
                core::ptr::read_volatile((GICD_VA + 0x200) as *const u32),
                core::ptr::read_volatile((GICD_VA + 0x300) as *const u32),
            )
        };
        klog::write_raw(b"[INFO]  arm-timer: mid ctl=");
        klog::write_hex_u64(mid_ctl);
        klog::write_raw(b" daif=");
        klog::write_hex_u64(mid_daif);
        klog::write_raw(b" ispend0=");
        klog::write_hex_u64(ispend as u64);
        klog::write_raw(b" isactive0=");
        klog::write_hex_u64(isactive as u64);
        klog::write_raw(b"\n");
        for _ in 0..8_000_000 { core::hint::spin_loop(); }
        // SAFETY: re-mask before disarming the timer to avoid a spurious tick during teardown.
        unsafe { core::arch::asm!("msr daifset, #2", options(nomem, nostack, preserves_flags)); }
        // SAFETY: disable CNTV (CTL=0) so no further line assertion.
        unsafe {
            let off: u64 = 0;
            core::arch::asm!("msr cntv_ctl_el0, {c}", c = in(reg) off, options(nomem, nostack, preserves_flags));
        }
        let post = gic::TICK_COUNT.load(core::sync::atomic::Ordering::Relaxed);
        let (daif, ctl, vbar): (u64, u64, u64);
        // SAFETY: mrs of unprivileged DAIF / CNTV_CTL / VBAR_EL1; pure reads, no memory effect.
        unsafe {
            core::arch::asm!("mrs {v}, daif", v = out(reg) daif, options(nomem, nostack, preserves_flags));
            core::arch::asm!("mrs {v}, cntv_ctl_el0", v = out(reg) ctl, options(nomem, nostack, preserves_flags));
            core::arch::asm!("mrs {v}, vbar_el1", v = out(reg) vbar, options(nomem, nostack, preserves_flags));
        }
        klog::write_raw(b"[INFO]  arm-timer: irq ticks=");
        klog::write_dec_u64(post.wrapping_sub(pre));
        klog::write_raw(b" last_intid=");
        klog::write_hex_u64(gic::LAST_INTID.load(core::sync::atomic::Ordering::Relaxed) as u64);
        klog::write_raw(b" daif=");
        klog::write_hex_u64(daif);
        klog::write_raw(b" cntv_ctl=");
        klog::write_hex_u64(ctl);
        klog::write_raw(b" vbar=");
        klog::write_hex_u64(vbar);
        klog::write_raw(b"\n");
    }
}
