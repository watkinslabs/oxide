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

            // The boot CPU collection is mapped once during ITS bring-up.
            // Device maps are created later by the PCI MSI owner for the
            // discovered function that asks for a vector; boot reserves no
            // identities for an imagined topology.
            // SAFETY: ITS enabled; HHDM live; single-CPU pre-init command context.
            let _mapc = unsafe { arch_irq::its::cmd_post(hhdm, arch_irq::its::cmd_mapc(0, 0)) };
            // SAFETY: MAPC targets the boot RD; the paired SYNC completes it before PCI probes begin.
            let _sync = unsafe { arch_irq::its::cmd_post(hhdm, arch_irq::its::cmd_sync(0)) };
            debug_irq! {
                klog::write_raw(b"[INFO]  its-cmd mapc-boot "); log_cmd_status(_mapc);
                klog::write_raw(b"[INFO]  its-cmd sync-boot "); log_cmd_status(_sync);
            }
        } else {
            debug_irq! {
                klog::write_raw(b"[INFO]  its: no MADT type-15 reported\n");
            }
        }
    }

}
