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

use hal::{MmuOps, Pa, PageFlags, PageSize, Va};

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

/// Device-MMIO leaf flags: writable kernel mapping, no-cache,
/// write-through (so x86 packs PCD|PWT = Strong UC; arm packs
/// AttrIdx=Device-nGnRnE), no exec. Equivalent to the device-leaf
/// bits the previous-generation `vmm::map_device_4k` packed
/// directly.
fn device_flags() -> PageFlags {
    PageFlags::READ | PageFlags::WRITE | PageFlags::NO_CACHE | PageFlags::WRITE_THROUGH
}

/// x86 device-MMIO bring-up smoke. Maps HPET + LAPIC at fixed
/// kernel-VA via `MmuOps::map` (per-arch impl in
/// `hal_x86_64::mmu_ops::X86Mmu`), enables LAPIC, runs the polled
/// + IRQ-driven timer smokes (gated `debug-vmm` / `debug-irq`).
/// # SAFETY: caller is the boot path; allocator up; PMM ready;
/// `mmu_ops::set_hhdm_offset` + `set_frame_alloc` already invoked
/// for x86; single-CPU; IRQs masked at entry.
/// # C: O(walk depth × 2) for the maps; spin loops dominate runtime.
/// # Ctx: pre-init, IRQ-off (entry), single-CPU
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub fn smoke_device_map_x86(_hhdm: u64) {
    use crate::lapic;
    use hal_x86_64::mmu_ops::X86Mmu;
    // SAFETY: single-CPU, IRQs off, PMM owns its frames; we splice
    // a 4 KiB Device-attr leaf into the kernel-half of the live
    // PML4 via the live MmuOps state.
    unsafe { <X86Mmu as MmuOps>::map(Va(HPET_VA), Pa(HPET_PHYS), device_flags(), PageSize::P4K); }
    debug_vmm! {
        // SAFETY: HPET_VA was just mapped Device-attr; the read is
        // a volatile MMIO load of HPET_GCAP_ID at offset 0.
        let cap = unsafe { core::ptr::read_volatile(HPET_VA as *const u32) };
        klog::write_raw(b"[INFO]  device-map: hpet cap=");
        klog::write_hex_u64(cap as u64);
        klog::write_raw(b"\n");
    }

    // LAPIC enable. Map → set IA32_APIC_BASE.E + SVR.SW_ENABLE → log
    // APIC ID + version.
    // SAFETY: chosen kernel VA disjoint from existing mappings; phys
    // 0xFEE00000 is the standard LAPIC base from MADT.
    unsafe { <X86Mmu as MmuOps>::map(Va(LAPIC_VA), Pa(LAPIC_PHYS), device_flags(), PageSize::P4K); }
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

// ---------------------------------------------------------------------------
// aarch64
// ---------------------------------------------------------------------------

/// Print an `its::CmdStatus` in a one-line format. Used by the
/// MAPC/MAPD/MAPTI bring-up sites in `smoke_device_map_arm`.
/// Gated to `debug-irq` so the klog call sites stay zero-cost in
/// stripped builds.
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64", feature = "debug-irq"))]
fn log_cmd_status(s: crate::its::CmdStatus) {
    match s {
        crate::its::CmdStatus::NotReady => {
            klog::write_raw(b"NotReady\n");
        }
        crate::its::CmdStatus::Posted { cwriter, creadr, polls } => {
            klog::write_raw(b"Posted cwriter=");
            klog::write_hex_u64(cwriter);
            klog::write_raw(b" creadr=");
            klog::write_hex_u64(creadr);
            klog::write_raw(b" polls=");
            klog::write_dec_u64(polls as u64);
            klog::write_raw(b"\n");
        }
        crate::its::CmdStatus::Timeout { cwriter, creadr } => {
            klog::write_raw(b"Timeout cwriter=");
            klog::write_hex_u64(cwriter);
            klog::write_raw(b" creadr=");
            klog::write_hex_u64(creadr);
            klog::write_raw(b"\n");
        }
    }
}
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64", not(feature = "debug-irq")))]
fn log_cmd_status(_s: crate::its::CmdStatus) {}

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
    use crate::gic;
use hal_aarch64::{timer as arm_timer, pl011};
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

    // F56-01: ITS bring-up. Map the 64 KiB control frame published
    // via MADT type-15 (`acpi::GIC_ITS_PA`), probe GITS_TYPER/CTLR.
    // No enable yet — subsequent F56 PRs add command queue, tables,
    // LPI prop/pend, GITS_CTLR.Enabled.
    {
        let its_pa = crate::acpi::GIC_ITS_PA
            .load(core::sync::atomic::Ordering::Acquire);
        if its_pa != 0 {
            let its_va = KERNEL_DEVICE_BASE | (its_pa & 0xFFFF_FFFF);
            // SAFETY: chosen kernel VA disjoint; phys came from MADT type-15; we own the device pre-init.
            unsafe {
                for i in 0..16u64 {
                    <ArmMmu as MmuOps>::map(
                        Va(its_va + i * 0x1000),
                        Pa(its_pa + i * 0x1000),
                        device_flags(),
                        PageSize::P4K,
                    );
                }
            }
            // SAFETY: ITS control frame freshly Device-attr mapped; single-CPU pre-init.
            let _s = unsafe { crate::its::enable(its_va) };
            debug_irq! {
                match _s {
                    crate::its::ItsStatus::Absent => {
                        klog::write_raw(b"[INFO]  its: absent\n");
                    }
                    crate::its::ItsStatus::AlreadyOn => {
                        klog::write_raw(b"[INFO]  its: already on\n");
                    }
                    crate::its::ItsStatus::Discovered { typer, ctlr, iidr, baser0 } => {
                        klog::write_raw(b"[INFO]  its: discovered typer=");
                        klog::write_hex_u64(typer);
                        klog::write_raw(b" ctlr=");
                        klog::write_hex_u64(ctlr as u64);
                        klog::write_raw(b" iidr=");
                        klog::write_hex_u64(iidr as u64);
                        klog::write_raw(b" baser0=");
                        klog::write_hex_u64(baser0);
                        klog::write_raw(b"\n");
                        klog::write_raw(b"[INFO]  its: dev_id_bits=");
                        klog::write_dec_u64(crate::its::typer_devbits(typer) as u64);
                        klog::write_raw(b" event_id_bits=");
                        klog::write_dec_u64(crate::its::typer_id_bits(typer) as u64);
                        klog::write_raw(b" itt_entry_size=");
                        klog::write_dec_u64(crate::its::typer_itt_entry_size(typer) as u64);
                        klog::write_raw(b" phys_lpi=");
                        klog::write_dec_u64(crate::its::typer_phys_lpi(typer) as u64);
                        klog::write_raw(b" translater_pa=");
                        klog::write_hex_u64(crate::its::translater_pa());
                        klog::write_raw(b"\n");
                    }
                }
            }
            // F56-02: program the ITS command queue. Allocates one
            // 4 KiB frame, zeroes it via HHDM, writes GITS_CBASER +
            // CWRITER. Does NOT enable the ITS yet (no GITS_CTLR
            // flip); subsequent F56 PRs add device/collection tables
            // + LPI prop/pend + GITS_CTLR.Enabled + MAPD/MAPC/MAPTI.
            let hhdm = hal_aarch64::mmu_ops::hhdm_offset();
            // SAFETY: ITS control frame Device-attr mapped above; PMM up; HHDM covers PMM frames; single-CPU pre-init.
            let _q = unsafe { crate::its::cmdq_setup(hhdm) };
            debug_irq! {
                match _q {
                    crate::its::CmdqStatus::NoIts =>
                        klog::write_raw(b"[INFO]  its-cmdq: no its\n"),
                    crate::its::CmdqStatus::AllocFailed =>
                        klog::write_raw(b"[ERROR] its-cmdq: pmm alloc failed\n"),
                    crate::its::CmdqStatus::AlreadyOn =>
                        klog::write_raw(b"[INFO]  its-cmdq: already on\n"),
                    crate::its::CmdqStatus::Ready { cmdq_pa, cbaser_wr, cbaser_rd, creadr } => {
                        klog::write_raw(b"[INFO]  its-cmdq: pa=");
                        klog::write_hex_u64(cmdq_pa);
                        klog::write_raw(b" cbaser_wr=");
                        klog::write_hex_u64(cbaser_wr);
                        klog::write_raw(b" cbaser_rd=");
                        klog::write_hex_u64(cbaser_rd);
                        klog::write_raw(b" creadr=");
                        klog::write_hex_u64(creadr);
                        klog::write_raw(b"\n");
                    }
                }
            }
            // F56-03: program GITS_BASER<n> for every implemented
            // table slot. Each slot gets one 4 KiB page (flat table)
            // — enough for low-DeviceID PCI devices and small
            // collection counts; Indirect tables come later when SMP
            // CPU counts or wide DeviceIDs need them.
            let mut slots = [crate::its::BaserSlot {
                idx: 0,
                ty: crate::its::BaserType::Unimplemented,
                raw_pre: 0,
                raw_post: 0,
                table_pa: 0,
            }; crate::its::GITS_BASER_COUNT];
            // SAFETY: cmdq_setup completed; PMM up; ITS control frame mapped; single-CPU pre-init.
            let _n = unsafe { crate::its::baser_setup(hhdm, &mut slots) };
            debug_irq! {
                klog::write_raw(b"[INFO]  its-baser: programmed=");
                klog::write_dec_u64(_n as u64);
                klog::write_raw(b"\n");
                for s in slots.iter() {
                    if s.raw_pre == 0 && s.raw_post == 0 { continue; }
                    klog::write_raw(b"[INFO]  its-baser[");
                    klog::write_dec_u64(s.idx as u64);
                    klog::write_raw(b"] type=");
                    klog::write_dec_u64(s.ty as u64);
                    klog::write_raw(b" pre=");
                    klog::write_hex_u64(s.raw_pre);
                    klog::write_raw(b" post=");
                    klog::write_hex_u64(s.raw_post);
                    klog::write_raw(b" table_pa=");
                    klog::write_hex_u64(s.table_pa);
                    klog::write_raw(b"\n");
                }
            }
            // F56-05: flip GITS_CTLR.Enabled.
            // SAFETY: cmdq + BASERs programmed above; LPIs enabled at the RD; single-CPU pre-init.
            let _ctlr = unsafe { crate::its::ctlr_enable() };
            debug_irq! {
                klog::write_raw(b"[INFO]  its-ctlr: post=");
                klog::write_hex_u64(_ctlr as u64);
                klog::write_raw(b"\n");
            }

            // F56-06: post MAPC (ICID 0 → boot CPU) + MAPD for the
            // two virtio devices (BDF 0x08 = virtio-net, 0x10 =
            // virtio-blk; QEMU virt's IORT does identity BDF→DeviceID
            // mapping). Verifies the cmd-post protocol: CREADR
            // catches up to CWRITER without ITS errors.
            for (label, cmd) in [
                (b"mapc-icid0" as &[u8],
                 crate::its::cmd_mapc(0, 0)),
            ] {
                // SAFETY: ITS enabled; HHDM live; single-CPU pre-init; pre-issue barrier inside cmd_post.
                let s = unsafe { crate::its::cmd_post(hhdm, cmd) };
                debug_irq! {
                    klog::write_raw(b"[INFO]  its-cmd ");
                    klog::write_raw(label);
                    klog::write_raw(b" ");
                    log_cmd_status(s);
                }
            }
            // Allocate one ITT per virtio device. 4 KiB / 12B-entry
            // = 341 events; plenty for ≤4-vector virtio MSI-X.
            for (label, did) in [
                (b"mapd-net" as &[u8], 0x08u32),
                (b"mapd-blk" as &[u8], 0x10u32),
            ] {
                if let Some(itt_pa) = pmm::setup::alloc_one_frame() {
                    if hhdm != 0 {
                        // SAFETY: HHDM-mapped freshly-allocated PMM frame; aligned u64 stores.
                        unsafe {
                            let p = hhdm.wrapping_add(itt_pa) as *mut u64;
                            for i in 0..(0x1000 / 8) {
                                core::ptr::write_volatile(p.add(i), 0);
                            }
                        }
                    }
                    // Size=4 → 32 EventIDs supported by this device.
                    let cmd = crate::its::cmd_mapd(did, itt_pa, 4);
                    // SAFETY: ITS enabled; ITT freshly zeroed and 4 KiB-aligned.
                    let s = unsafe { crate::its::cmd_post(hhdm, cmd) };
                    debug_irq! {
                        klog::write_raw(b"[INFO]  its-cmd ");
                        klog::write_raw(label);
                        klog::write_raw(b" did=");
                        klog::write_hex_u64(did as u64);
                        klog::write_raw(b" itt_pa=");
                        klog::write_hex_u64(itt_pa);
                        klog::write_raw(b" ");
                        log_cmd_status(s);
                    }
                }
            }
            // F56-07/08: MAPTI + LPI prop byte + INV + SYNC for
            // virtio-blk's first MSI vector. Maps DeviceID 0x10,
            // EventID 0 → LPI 8192 on ICID 0; writes the per-LPI
            // configuration byte (priority 0xA0, Group1, Enable=1)
            // BETWEEN MAPTI and INV so the ITS re-reads it on INV.
            // SAFETY: ITS enabled; MAPC + MAPD posted above.
            let s_mapti = unsafe {
                crate::its::cmd_post(hhdm, crate::its::cmd_mapti(0x10, 0, 8192, 0))
            };
            // SAFETY: lpis_enable published LPI_PROP_PA; HHDM live; LPI 8192 within table bounds.
            let lpi_set = unsafe {
                crate::gic::lpi_set_config(hhdm, 8192, crate::gic::LPI_PROP_DEFAULT)
            };
            // SAFETY: MAPTI just posted; cmd queue protocol per F56-06.
            let s_inv = unsafe {
                crate::its::cmd_post(hhdm, crate::its::cmd_inv(0x10, 0))
            };
            // SAFETY: ITS enabled and queue protocol per F56-06; SYNC barriers against the boot RD's processor number.
            let s_sync = unsafe {
                crate::its::cmd_post(hhdm, crate::its::cmd_sync(0))
            };
            debug_irq! {
                klog::write_raw(b"[INFO]  its-cmd mapti-blk "); log_cmd_status(s_mapti);
                klog::write_raw(b"[INFO]  lpi-prop[8192]=");
                klog::write_hex_u64(crate::gic::LPI_PROP_DEFAULT as u64);
                klog::write_raw(b" set=");
                klog::write_dec_u64(lpi_set as u64);
                klog::write_raw(b"\n");
                klog::write_raw(b"[INFO]  its-cmd inv-blk ");  log_cmd_status(s_inv);
                klog::write_raw(b"[INFO]  its-cmd sync ");      log_cmd_status(s_sync);
            }
            // F56-09: kernel-side self-test of the ITS → LPI →
            // dispatcher path. Post INT(DeviceID=0x10, EventID=0)
            // which makes the ITS synthesise LPI 8192 as if
            // virtio-blk had written GITS_TRANSLATER. Briefly
            // unmask DAIF.I so the dispatcher can take the IRQ
            // and bump MSI_FIRES. If this counter increments, the
            // ITS-side plumbing is correct and any later silent-
            // MSI is the device's fault, not ours.
            let pre = msi::MSI_FIRES.load(core::sync::atomic::Ordering::Relaxed);
            // SAFETY: ITS enabled, MAPD+MAPC+MAPTI posted above, LPI 8192 enabled in PROPBASER; cmd_post follows the F56-06 protocol.
            let s_int = unsafe {
                crate::its::cmd_post(hhdm, crate::its::cmd_int(0x10, 0))
            };
            // SAFETY: clear DAIF.I momentarily so a pending LPI
            // can deliver; we re-mask before returning. Single
            // CPU pre-init context.
            unsafe {
                core::arch::asm!("msr daifclr, #2", options(nomem, nostack, preserves_flags));
                for _ in 0..2_000_000 { core::hint::spin_loop(); }
                core::arch::asm!("msr daifset, #2", options(nomem, nostack, preserves_flags));
            }
            let post = msi::MSI_FIRES.load(core::sync::atomic::Ordering::Relaxed);
            debug_irq! {
                klog::write_raw(b"[INFO]  its-cmd int-self ");  log_cmd_status(s_int);
                klog::write_raw(b"[INFO]  its-self-fire pre=");
                klog::write_dec_u64(pre as u64);
                klog::write_raw(b" post=");
                klog::write_dec_u64(post as u64);
                klog::write_raw(b" delta=");
                klog::write_dec_u64(post.saturating_sub(pre) as u64);
                klog::write_raw(b" last_intid=");
                klog::write_hex_u64(crate::gic::LAST_INTID
                    .load(core::sync::atomic::Ordering::Relaxed) as u64);
                klog::write_raw(b"\n");
            }
        } else {
            debug_irq! {
                klog::write_raw(b"[INFO]  its: no MADT type-15 reported\n");
            }
        }
    }

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
    // now actually deliver to oxide_arm_irq_dispatch. Replaces the
    // timer-poll fallback for stdin wakeup.
    // SAFETY: pl011::enable just ran; gic::enable_intid is idempotent and the GIC was enabled earlier in this fn; single-CPU pre-init.
    unsafe {
        hal_aarch64::pl011::enable_rx_irq();
        crate::gic::enable_intid(33);
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
    // the segment-0 base PA, map bus 0 (256 × 4 KiB = 1 MiB) at a
    // dedicated kernel VA so `hal_aarch64::pci::EcamPci` can MMIO
    // the per-BDF config space. v1 only enumerates bus 0 (one
    // segment, one bus is enough for QEMU virt's host + virtio
    // devices); higher buses fault if probed and need a follow-up.
    let ecam_pa = crate::acpi::ECAM_BASE_PA
        .load(core::sync::atomic::Ordering::Acquire);
    if ecam_pa != 0 {
        // Disjoint VA from KERNEL_DEVICE_BASE so the (pa & 0xffff_ffff)
        // convention there isn't aliased.
        const ECAM_BUS0_VA: u64 = 0xffff_fe00_0000_0000;
        for page in 0..256u64 {
            let pa = ecam_pa + page * 0x1000;
            let va = ECAM_BUS0_VA + page * 0x1000;
            // SAFETY: same contract as the GICD/PL011 maps above —
            // single-CPU pre-init, MmuOps state initialised; ECAM_PA
            // came from ACPI MCFG so QEMU has the matching device.
            unsafe { <ArmMmu as MmuOps>::map(Va(va), Pa(pa), device_flags(), PageSize::P4K); }
        }
        hal_aarch64::pci::ECAM_BASE_VA
            .store(ECAM_BUS0_VA, core::sync::atomic::Ordering::Release);
    }

    // F36: GICv2m MSI frame device-map (1 page) + read MSI_TYPER at +0x008.
    // Bits[25:16] = first SPI; bits[9:0] = SPI count. Together with the
    // frame base PA published by F35, this lets F37+ MSI wiring allocate
    // SPIs and encode MSI message addr/data correctly.
    let v2m_pa = crate::acpi::GIC_MSI_FRAME_PA
        .load(core::sync::atomic::Ordering::Acquire);
    if v2m_pa != 0 {
        const V2M_VA: u64 = 0xffff_fc00_0000_0000;
        // SAFETY: GICv2m frame map: single-CPU pre-init, MmuOps state initialised, v2m_pa came from MADT type-13 entry, V2M_VA disjoint from KERNEL_DEVICE_BASE and ECAM_BUS0_VA.
        unsafe { <ArmMmu as MmuOps>::map(Va(V2M_VA), Pa(v2m_pa), device_flags(), PageSize::P4K); }
        // F45: publish VA so pci_boot self-fire diagnostic can write SETSPI_NS directly.
        msi::GICV2M_VA.store(V2M_VA, core::sync::atomic::Ordering::Release);
        // SAFETY: V2M_VA is freshly Device-attr mapped above; aligned u32 read of the MSI_TYPER register at offset 0x008.
        let typer = unsafe {
            core::ptr::read_volatile((V2M_VA + 0x008) as *const u32)
        };
        let spi_first = (typer >> 16) & 0x3FF;
        let spi_count = typer & 0x3FF;
        // F37: publish the SPI range so `msi::alloc_arm_spi`
        // can hand out vectors. Side effect runs unconditionally;
        // klog stays gated under R06.
        msi::GICV2M_SPI_FIRST
            .store(spi_first, core::sync::atomic::Ordering::Release);
        msi::GICV2M_SPI_COUNT
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
            if let Some(spi) = msi::alloc_arm_spi() {
                // SAFETY: gic::enable was called earlier in this same fn (smoke_device_map_arm); SPI is freshly allocated and owned by F37; single-CPU pre-init.
                unsafe { crate::gic::enable_intid(spi); }
                klog::write_raw(b"[INFO]  msi-spi alloc=");
                klog::write_dec_u64(spi as u64);
                klog::write_raw(b" enabled\n");
            }
        }
    }
}
