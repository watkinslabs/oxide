use super::{device_flags, map_ecam_window, ECAM_BASE_VA, KERNEL_DEVICE_BASE};
use hal::{MmuOps, Pa, PageSize, Va};

#[path = "its.rs"]
mod its;

/// GIC distributor base on QEMU virt (matches MADT log; same address
/// for v2 and v3).
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
const GICD_PHYS: u64 = 0x0800_0000;
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
const GICD_VA: u64 = KERNEL_DEVICE_BASE | (GICD_PHYS & 0xFFFF_FFFF);

/// GICv3 redistributor base on QEMU virt. 128 KiB per CPU (RD frame
/// at +0, SGI frame at +0x10000); single-CPU UP only maps the first.
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
const GICR_PHYS: u64 = 0x080A_0000;
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
const GICR_VA: u64 = KERNEL_DEVICE_BASE | (GICR_PHYS & 0xFFFF_FFFF);

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
pub fn smoke_device_map_arm(_hhdm: u64) {
    use arch_irq::gic;
    use hal_aarch64::pl011;
    #[cfg(feature = "debug-irq")]
    use hal_aarch64::timer as arm_timer;
    use hal_aarch64::mmu_ops::ArmMmu;
    // SAFETY: same contract as the x86 smoke — TTBR1_EL1 active,
    // single-CPU, IRQs off; mmu_ops state initialised.
    // Map all 16 pages (64 KiB) of the GICD region so GICv3
    // IROUTER (offset 0x6000+) is reachable.
    unsafe {
        for i in 0..16u64 {
            <ArmMmu as MmuOps>::map(
                Va(GICD_VA + i * 0x1000),
                Pa(GICD_PHYS + i * 0x1000),
                device_flags(),
                PageSize::P4K,
            );
        }
    }
    debug_vmm! {
        // SAFETY: GICD_VA was just mapped Device-nGnRnE; read GICD_TYPER at offset 4.
        let typer = unsafe { core::ptr::read_volatile((GICD_VA + 0x4) as *const u32) };
        klog::write_raw(b"[INFO]  device-map: gicd typer=");
        klog::write_hex_u64(typer as u64);
        klog::write_raw(b"\n");
    }

    // GICv3 enable: map both 64 KiB redistributor frames (RD + SGI)
    // for CPU 0 and program the distributor + per-CPU sysregs.
    // SAFETY: GICR_PHYS is the QEMU virt redistributor base; we own the device pre-init.
    unsafe {
        <ArmMmu as MmuOps>::map(Va(GICR_VA),               Pa(GICR_PHYS),               device_flags(), PageSize::P4K);
        <ArmMmu as MmuOps>::map(Va(GICR_VA + 0x10000),     Pa(GICR_PHYS + 0x10000),     device_flags(), PageSize::P4K);
    }
    {
        // SAFETY: both VAs are freshly Device-attr mapped; single-CPU pre-init.
        let s = unsafe { gic::enable(GICD_VA, GICR_VA) };
        match s {
            gic::GicStatus::AlreadyOn => { debug_irq! { klog::kinfo!("gic: already on"); } }
            gic::GicStatus::Enabled { typer: _typer, gicd_iidr: _gicd_iidr, gicr_typer_lo: _gicr_typer } => {
                debug_irq! {
                    klog::write_raw(b"[INFO]  gicv3: enabled typer=");
                    klog::write_hex_u64(_typer as u64);
                    klog::write_raw(b" gicd_iidr=");
                    klog::write_hex_u64(_gicd_iidr as u64);
                    klog::write_raw(b" gicr_typer_lo=");
                    klog::write_hex_u64(_gicr_typer as u64);
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
    }

    // F56-04: LPI bring-up on the boot CPU's redistributor. Allocates
    // the global LPI configuration table (16 KiB) + per-RD pending
    // table (64 KiB) and sets GICR_CTLR.EnableLPI. Must precede ITS
    // setup — once the ITS posts MAPD/MAPC/MAPTI, LPIs delivered via
    // GITS_TRANSLATER need a configured pending region or the RD
    // drops them silently.
    {
        let hhdm_lpi = hal_aarch64::mmu_ops::hhdm_offset();
        // SAFETY: gic::enable just ran (publishes GICR_VA); PMM is up; GICR RD frame Device-attr mapped above; single-CPU pre-init.
        let _l = unsafe { gic::lpis_enable(hhdm_lpi) };
        debug_irq! {
            match _l {
                gic::LpisStatus::AlreadyOn =>
                    klog::write_raw(b"[INFO]  lpis: already on\n"),
                gic::LpisStatus::AllocFailed =>
                    klog::write_raw(b"[ERROR] lpis: pmm alloc failed\n"),
                gic::LpisStatus::Ready { prop_pa, pend_pa, propbaser_rd, pendbaser_rd, ctlr_post } => {
                    klog::write_raw(b"[INFO]  lpis: prop_pa=");
                    klog::write_hex_u64(prop_pa);
                    klog::write_raw(b" pend_pa=");
                    klog::write_hex_u64(pend_pa);
                    klog::write_raw(b" propbaser_rd=");
                    klog::write_hex_u64(propbaser_rd);
                    klog::write_raw(b" pendbaser_rd=");
                    klog::write_hex_u64(pendbaser_rd);
                    klog::write_raw(b" gicr_ctlr=");
                    klog::write_hex_u64(ctlr_post as u64);
                    klog::write_raw(b"\n");
                }
            }
        }
    }

    its::bring_up();

    // Map PL011 + swap klog sink from semihosting to the real UART.
    // SAFETY: same contract; chosen kernel VA disjoint from existing
    // mappings; phys 0x09000000 is the QEMU virt PL011 base from SPCR.
    unsafe { <ArmMmu as MmuOps>::map(Va(PL011_VA), Pa(PL011_PHYS), device_flags(), PageSize::P4K); }
    // SAFETY: PL011_VA is freshly mapped Device-nGnRnE, covering
    // 4 KiB; we own the device pre-init.
    unsafe { pl011::enable(PL011_VA); }
    debug_boot! {
        klog::set_byte_sink(pl011::pl011_emit);
        klog::kinfo!("pl011: switched klog sink to real UART");
    }
    // F47: turn on PL011 RX + RX-timeout IRQs and enable the matching
    // SPI at the distributor. SPCR exposes irq=33 as the PL011 line on
    // QEMU virt; with F45's ITARGETSR+ICFGR programming, SPI 33 will
    // now deliver to oxide_arm_irq_dispatch; stdin wakeup is IRQ-owned.
    // SAFETY: pl011::enable just ran; gic::enable_intid is idempotent and the GIC was enabled earlier in this fn; single-CPU pre-init.
    unsafe {
        hal_aarch64::pl011::enable_rx_irq();
        // PL011 is level-sensitive on QEMU virt — the line stays
        // asserted while RBR holds data. Edge-trigger (the
        // `enable_intid` default for SPIs) would fire once on the
        // first byte and silently miss every subsequent assertion
        // because the line never drops to re-arm the edge detector.
        arch_irq::gic::enable_intid_level(33);
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

    // PCIe ECAM device-mapping. After acpi::decode_mcfg published
    // the segment-0 base PA and bus range, map the advertised first
    // segment window at a dedicated kernel VA so all reachable bridge
    // buses can be probed through `hal_aarch64::pci::EcamPci`.
    let ecam_pa = firmware::acpi::ECAM_BASE_PA
        .load(core::sync::atomic::Ordering::Acquire);
    let ecam_bus_cap = firmware::acpi::ecam_bus_cap();
    if ecam_pa != 0 && ecam_bus_cap != 0 {
        // SAFETY: same contract as the GICD/PL011 maps above — single-CPU
        // pre-init, MmuOps state initialised, and ECAM_PA came from ACPI MCFG.
        unsafe { map_ecam_window::<ArmMmu>(ecam_pa, ecam_bus_cap); }
        hal_aarch64::pci::ECAM_BASE_VA
            .store(ECAM_BASE_VA, core::sync::atomic::Ordering::Release);
    }

    // F36: GICv2m MSI frame device-map (1 page) + read MSI_TYPER at +0x008.
    // Bits[25:16] = first SPI; bits[9:0] = SPI count. Together with the
    // frame base PA published by F35, this lets F37+ MSI wiring allocate
    // SPIs and encode MSI message addr/data correctly.
    let v2m_pa = firmware::acpi::GIC_MSI_FRAME_PA
        .load(core::sync::atomic::Ordering::Acquire);
    if v2m_pa != 0 {
        const V2M_VA: u64 = 0xffff_fc00_0000_0000;
        // SAFETY: GICv2m frame map: single-CPU pre-init, MmuOps state initialised, v2m_pa came from MADT type-13 entry, V2M_VA disjoint from KERNEL_DEVICE_BASE and ECAM_BASE_VA.
        unsafe { <ArmMmu as MmuOps>::map(Va(V2M_VA), Pa(v2m_pa), device_flags(), PageSize::P4K); }
        // F45: publish VA so pci_boot self-fire diagnostic can write SETSPI_NS directly.
        arch_irq::GICV2M_VA.store(V2M_VA, core::sync::atomic::Ordering::Release);
        // SAFETY: V2M_VA is freshly Device-attr mapped above; aligned u32 read of the MSI_TYPER register at offset 0x008.
        let typer = unsafe {
            core::ptr::read_volatile((V2M_VA + 0x008) as *const u32)
        };
        let spi_first = (typer >> 16) & 0x3FF;
        let spi_count = typer & 0x3FF;
        // F37: publish the SPI range so `arch_irq::alloc_arm_spi`
        // can hand out vectors. Side effect runs unconditionally;
        // klog stays gated under R06.
        arch_irq::GICV2M_SPI_FIRST
            .store(spi_first, core::sync::atomic::Ordering::Release);
        arch_irq::GICV2M_SPI_COUNT
            .store(spi_count, core::sync::atomic::Ordering::Release);
        debug_boot! {
            klog::write_raw(b"[INFO]  gicv2m typer=");
            klog::write_hex_u64(typer as u64);
            klog::write_raw(b" spi_first=");
            klog::write_dec_u64(spi_first as u64);
            klog::write_raw(b" spi_count=");
            klog::write_dec_u64(spi_count as u64);
            klog::write_raw(b"\n");
            // F37 demo: allocate one SPI + enable it at the GIC
            // distributor. No MSI-X table write yet (F38), so nothing
            // will fire — this just proves the alloc + GIC enable path.
            if let Some(spi) = arch_irq::alloc_arm_spi() {
                // SAFETY: gic::enable was called earlier in this same fn (smoke_device_map_arm); SPI is freshly allocated and owned by F37; single-CPU pre-init.
                unsafe { arch_irq::gic::enable_intid(spi); }
                klog::write_raw(b"[INFO]  msi-spi alloc=");
                klog::write_dec_u64(spi as u64);
                klog::write_raw(b" enabled\n");
            }
        }
    }
}
