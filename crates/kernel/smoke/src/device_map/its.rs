/// Print an `its::CmdStatus` in a one-line format. Used by the
/// MAPC/MAPD/MAPTI bring-up sites in `smoke_device_map_arm`.
/// Gated to `debug-irq` so the klog call sites stay zero-cost in
/// stripped builds.
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64", feature = "debug-irq"))]
fn log_cmd_status(s: arch_irq::its::CmdStatus) {
    match s {
        arch_irq::its::CmdStatus::NotReady => {
            klog::write_raw(b"NotReady\n");
        }
        arch_irq::its::CmdStatus::Posted { cwriter, creadr, polls } => {
            klog::write_raw(b"Posted cwriter=");
            klog::write_hex_u64(cwriter);
            klog::write_raw(b" creadr=");
            klog::write_hex_u64(creadr);
            klog::write_raw(b" polls=");
            klog::write_dec_u64(polls as u64);
            klog::write_raw(b"\n");
        }
        arch_irq::its::CmdStatus::Timeout { cwriter, creadr } => {
            klog::write_raw(b"Timeout cwriter=");
            klog::write_hex_u64(cwriter);
            klog::write_raw(b" creadr=");
            klog::write_hex_u64(creadr);
            klog::write_raw(b"\n");
        }
    }
}

use super::{device_flags, KERNEL_DEVICE_BASE};
use hal::{MmuOps, Pa, PageSize, Va};
use hal_aarch64::mmu_ops::ArmMmu;

pub(super) fn bring_up() {
    // F56-01: ITS bring-up. Map the 64 KiB control frame published
    // via MADT type-15 (`acpi::GIC_ITS_PA`), probe GITS_TYPER/CTLR.
    // No enable yet — subsequent F56 PRs add command queue, tables,
    // LPI prop/pend, GITS_CTLR.Enabled.
    {
        let its_pa = firmware::acpi::GIC_ITS_PA
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
            let _s = unsafe { arch_irq::its::enable(its_va) };
            debug_irq! {
                match _s {
                    arch_irq::its::ItsStatus::Absent => {
                        klog::write_raw(b"[INFO]  its: absent\n");
                    }
                    arch_irq::its::ItsStatus::AlreadyOn => {
                        klog::write_raw(b"[INFO]  its: already on\n");
                    }
                    arch_irq::its::ItsStatus::Discovered { typer, ctlr, iidr, baser0 } => {
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
                        klog::write_dec_u64(arch_irq::its::typer_devbits(typer) as u64);
                        klog::write_raw(b" event_id_bits=");
                        klog::write_dec_u64(arch_irq::its::typer_id_bits(typer) as u64);
                        klog::write_raw(b" itt_entry_size=");
                        klog::write_dec_u64(arch_irq::its::typer_itt_entry_size(typer) as u64);
                        klog::write_raw(b" phys_lpi=");
                        klog::write_dec_u64(arch_irq::its::typer_phys_lpi(typer) as u64);
                        klog::write_raw(b" translater_pa=");
                        klog::write_hex_u64(arch_irq::its::translater_pa());
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
            let _q = unsafe { arch_irq::its::cmdq_setup(hhdm) };
            debug_irq! {
                match _q {
                    arch_irq::its::CmdqStatus::NoIts =>
                        klog::write_raw(b"[INFO]  its-cmdq: no its\n"),
                    arch_irq::its::CmdqStatus::AllocFailed =>
                        klog::write_raw(b"[ERROR] its-cmdq: pmm alloc failed\n"),
                    arch_irq::its::CmdqStatus::AlreadyOn =>
                        klog::write_raw(b"[INFO]  its-cmdq: already on\n"),
                    arch_irq::its::CmdqStatus::Ready { cmdq_pa, cbaser_wr, cbaser_rd, creadr } => {
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
            let mut slots = [arch_irq::its::BaserSlot {
                idx: 0,
                ty: arch_irq::its::BaserType::Unimplemented,
                raw_pre: 0,
                raw_post: 0,
                table_pa: 0,
            }; arch_irq::its::GITS_BASER_COUNT];
            // SAFETY: cmdq_setup completed; PMM up; ITS control frame mapped; single-CPU pre-init.
            let _n = unsafe { arch_irq::its::baser_setup(hhdm, &mut slots) };
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
            let _ctlr = unsafe { arch_irq::its::ctlr_enable() };
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
            for (_label, cmd) in [
                (b"mapc-icid0" as &[u8],
                 arch_irq::its::cmd_mapc(0, 0)),
            ] {
                // SAFETY: ITS enabled; HHDM live; single-CPU pre-init; pre-issue barrier inside cmd_post.
                let _s = unsafe { arch_irq::its::cmd_post(hhdm, cmd) };
                debug_irq! {
                    klog::write_raw(b"[INFO]  its-cmd ");
                    klog::write_raw(_label);
                    klog::write_raw(b" ");
                    log_cmd_status(_s);
                }
            }
            // Allocate one ITT per virtio device. 4 KiB / 12B-entry
            // = 341 events; plenty for ≤4-vector virtio MSI-X.
            for (_label, did) in [
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
                    let cmd = arch_irq::its::cmd_mapd(did, itt_pa, 4);
                    // SAFETY: ITS enabled; ITT freshly zeroed and 4 KiB-aligned.
                    let _s = unsafe { arch_irq::its::cmd_post(hhdm, cmd) };
                    debug_irq! {
                        klog::write_raw(b"[INFO]  its-cmd ");
                        klog::write_raw(_label);
                        klog::write_raw(b" did=");
                        klog::write_hex_u64(did as u64);
                        klog::write_raw(b" itt_pa=");
                        klog::write_hex_u64(itt_pa);
                        klog::write_raw(b" ");
                        log_cmd_status(_s);
                    }
                }
            }
            // F56-07/08: MAPTI + LPI prop byte + INV + SYNC for
            // virtio-blk's first MSI vector. Maps DeviceID 0x10,
            // EventID 0 → LPI 8192 on ICID 0; writes the per-LPI
            // configuration byte (priority 0xA0, Group1, Enable=1)
            // BETWEEN MAPTI and INV so the ITS re-reads it on INV.
            // SAFETY: ITS enabled; MAPC + MAPD posted above.
            let _s_mapti = unsafe {
                arch_irq::its::cmd_post(hhdm, arch_irq::its::cmd_mapti(0x10, 0, 8192, 0))
            };
            // SAFETY: lpis_enable published LPI_PROP_PA; HHDM live; LPI 8192 within table bounds.
            let _lpi_set = unsafe {
                arch_irq::gic::lpi_set_config(hhdm, 8192, arch_irq::gic::LPI_PROP_DEFAULT)
            };
            // SAFETY: MAPTI just posted; cmd queue protocol per F56-06.
            let _s_inv = unsafe {
                arch_irq::its::cmd_post(hhdm, arch_irq::its::cmd_inv(0x10, 0))
            };
            // SAFETY: ITS enabled and queue protocol per F56-06; SYNC barriers against the boot RD's processor number.
            let _s_sync = unsafe {
                arch_irq::its::cmd_post(hhdm, arch_irq::its::cmd_sync(0))
            };
            debug_irq! {
                klog::write_raw(b"[INFO]  its-cmd mapti-blk "); log_cmd_status(_s_mapti);
                klog::write_raw(b"[INFO]  lpi-prop[8192]=");
                klog::write_hex_u64(arch_irq::gic::LPI_PROP_DEFAULT as u64);
                klog::write_raw(b" set=");
                klog::write_dec_u64(_lpi_set as u64);
                klog::write_raw(b"\n");
                klog::write_raw(b"[INFO]  its-cmd inv-blk ");  log_cmd_status(_s_inv);
                klog::write_raw(b"[INFO]  its-cmd sync ");      log_cmd_status(_s_sync);
            }
            // F56-09: kernel-side self-test of the ITS → LPI →
            // dispatcher path. Post INT(DeviceID=0x10, EventID=0)
            // which makes the ITS synthesise LPI 8192 as if
            // virtio-blk had written GITS_TRANSLATER. Briefly
            // unmask DAIF.I so the dispatcher can take the IRQ
            // and bump MSI_FIRES. If this counter increments, the
            // ITS-side plumbing is correct and any later silent-
            // MSI is the device's fault, not ours.
            let _pre = arch_irq::MSI_FIRES.load(core::sync::atomic::Ordering::Relaxed);
            // SAFETY: ITS enabled, MAPD+MAPC+MAPTI posted above, LPI 8192 enabled in PROPBASER; cmd_post follows the F56-06 protocol.
            let _s_int = unsafe {
                arch_irq::its::cmd_post(hhdm, arch_irq::its::cmd_int(0x10, 0))
            };
            // SAFETY: clear DAIF.I momentarily so a pending LPI
            // can deliver; we re-mask before returning. Single
            // CPU pre-init context.
            unsafe {
                core::arch::asm!("msr daifclr, #2", options(nomem, nostack, preserves_flags));
                for _ in 0..2_000_000 { core::hint::spin_loop(); }
                core::arch::asm!("msr daifset, #2", options(nomem, nostack, preserves_flags));
            }
            let _post = arch_irq::MSI_FIRES.load(core::sync::atomic::Ordering::Relaxed);
            debug_irq! {
                klog::write_raw(b"[INFO]  its-cmd int-self ");  log_cmd_status(_s_int);
                klog::write_raw(b"[INFO]  its-self-fire pre=");
                klog::write_dec_u64(_pre as u64);
                klog::write_raw(b" post=");
                klog::write_dec_u64(_post as u64);
                klog::write_raw(b" delta=");
                klog::write_dec_u64(_post.saturating_sub(_pre) as u64);
                klog::write_raw(b" last_intid=");
                klog::write_hex_u64(arch_irq::gic::LAST_INTID
                    .load(core::sync::atomic::Ordering::Relaxed) as u64);
                klog::write_raw(b"\n");
            }
        } else {
            debug_irq! {
                klog::write_raw(b"[INFO]  its: no MADT type-15 reported\n");
            }
        }
    }

}
