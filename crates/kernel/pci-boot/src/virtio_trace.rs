// virtio-pci probe trace, split out of `virtio_drv` to keep that file
// under the 1000-line cap (docs/08§7). All output is gated under
// `debug-boot` (R06) — zero bytes in a default build.

use super::virtio_drv::VirtioProbe;

/// Emit the per-device `[INFO] virtio-*` probe trace lines. Gated under
/// `debug-boot`; the side-effect bring-up itself runs in `virtio_drv`.
/// # C: O(num_queues) klog writes
pub(super) fn trace_probe(bdf: pci::Bdf, p: &VirtioProbe) {
    #[cfg(not(feature = "debug-boot"))]
    let _ = (bdf, p);
    debug_boot! {
        klog::write_raw(b"[INFO]  pci-cmd ");
        klog::write_dec_u64(bdf.bus as u64);
        klog::write_raw(b":");
        klog::write_dec_u64(bdf.device as u64);
        klog::write_raw(b".");
        klog::write_dec_u64(bdf.function as u64);
        klog::write_raw(b" was=");
        klog::write_hex_u64(p.cmd_orig as u64);
        klog::write_raw(b" now=");
        klog::write_hex_u64(p.cmd_new as u64);
        klog::write_raw(b"\n");

        klog::write_raw(b"[INFO]  virtio-cfg ");
        klog::write_dec_u64(bdf.bus as u64);
        klog::write_raw(b":");
        klog::write_dec_u64(bdf.device as u64);
        klog::write_raw(b".");
        klog::write_dec_u64(bdf.function as u64);
        klog::write_raw(b" common-va=");
        klog::write_hex_u64(p.cfg_va);
        klog::write_raw(b" feat=");
        klog::write_hex_u64(p.dev_features);
        klog::write_raw(b" drv_feat=");
        klog::write_hex_u64(p.drv_features);
        klog::write_raw(b" status=");
        klog::write_hex_u64(p.post_status as u64);
        klog::write_raw(b" features_ok=");
        klog::write_dec_u64(p.features_ok as u64);
        klog::write_raw(b" num_queues=");
        klog::write_dec_u64(p.num_queues as u64);
        klog::write_raw(b" msix_cfg=");
        klog::write_hex_u64(p.msix_cfg as u64);
        klog::write_raw(b"\n");

        for i in 0..p.queues_len {
            let (qi, qsz) = p.queues[i];
            klog::write_raw(b"[INFO]  virtio-q ");
            klog::write_dec_u64(bdf.bus as u64);
            klog::write_raw(b":");
            klog::write_dec_u64(bdf.device as u64);
            klog::write_raw(b".");
            klog::write_dec_u64(bdf.function as u64);
            klog::write_raw(b" idx=");
            klog::write_dec_u64(qi as u64);
            klog::write_raw(b" size=");
            klog::write_dec_u64(qsz as u64);
            klog::write_raw(b"\n");
        }
        if p.avail_idx_posted > 0 {
            klog::write_raw(b"[INFO]  virtio-rx-post ");
            klog::write_dec_u64(bdf.bus as u64);
            klog::write_raw(b":");
            klog::write_dec_u64(bdf.device as u64);
            klog::write_raw(b".");
            klog::write_dec_u64(bdf.function as u64);
            klog::write_raw(b" avail_idx=");
            klog::write_dec_u64(p.avail_idx_posted as u64);
            klog::write_raw(b" used_idx=");
            klog::write_dec_u64(p.used_idx_observed as u64);
            klog::write_raw(b" isr=");
            klog::write_hex_u64(p.isr_status as u64);
            klog::write_raw(b"\n");
        }
        if p.q1_notify_va != 0 {
            klog::write_raw(b"[INFO]  virtio-tx ");
            klog::write_dec_u64(bdf.bus as u64);
            klog::write_raw(b":");
            klog::write_dec_u64(bdf.device as u64);
            klog::write_raw(b".");
            klog::write_dec_u64(bdf.function as u64);
            klog::write_raw(b" q1_notify_off=");
            klog::write_dec_u64(p.q1_notify_off as u64);
            klog::write_raw(b" q1_notify_va=");
            klog::write_hex_u64(p.q1_notify_va);
            klog::write_raw(b"\n");
        }
        if p.q0_notify_va != 0 {
            klog::write_raw(b"[INFO]  virtio-notify ");
            klog::write_dec_u64(bdf.bus as u64);
            klog::write_raw(b":");
            klog::write_dec_u64(bdf.device as u64);
            klog::write_raw(b".");
            klog::write_dec_u64(bdf.function as u64);
            klog::write_raw(b" q=0 off=");
            klog::write_hex_u64(p.q0_notify_off as u64);
            klog::write_raw(b" va=");
            klog::write_hex_u64(p.q0_notify_va);
            klog::write_raw(b" post_status=");
            klog::write_hex_u64(p.post_notify_status as u64);
            klog::write_raw(b"\n");
        }
        //: read back queue_msix_vector (high u16 of dword at 0x18)
        // and report MSI delivery count seen by the IRQ dispatcher.
        // SAFETY: cfg_va Device-attr mapped during init; aligned u32 read.
        let qmv_word = unsafe {
            core::ptr::read_volatile((p.cfg_va + 0x18) as *const u32)
        };
        let qmv = (qmv_word >> 16) as u16;
        let fires = arch_irq::MSI_FIRES.load(core::sync::atomic::Ordering::Acquire);
        klog::write_raw(b"[INFO]  virtio-msix ");
        klog::write_dec_u64(bdf.bus as u64);
        klog::write_raw(b":");
        klog::write_dec_u64(bdf.device as u64);
        klog::write_raw(b".");
        klog::write_dec_u64(bdf.function as u64);
        klog::write_raw(b" q0_msix_vec=");
        klog::write_hex_u64(qmv as u64);
        klog::write_raw(b" msi_fires=");
        klog::write_dec_u64(fires as u64);
        klog::write_raw(b"\n");
        if p.q0_desc_pa != 0 {
            klog::write_raw(b"[INFO]  virtio-q0-prog ");
            klog::write_dec_u64(bdf.bus as u64);
            klog::write_raw(b":");
            klog::write_dec_u64(bdf.device as u64);
            klog::write_raw(b".");
            klog::write_dec_u64(bdf.function as u64);
            klog::write_raw(b" desc_pa=");
            klog::write_hex_u64(p.q0_desc_pa);
            klog::write_raw(b" driver_pa=");
            klog::write_hex_u64(p.q0_driver_pa);
            klog::write_raw(b" device_pa=");
            klog::write_hex_u64(p.q0_device_pa);
            klog::write_raw(b" final_status=");
            klog::write_hex_u64(p.final_status as u64);
            klog::write_raw(b"\n");
        }
    }
}
