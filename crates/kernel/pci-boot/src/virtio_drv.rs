// Modern virtio-pci transport bring-up. Split from pci_boot/mod.rs.
// klog calls gated under debug_boot! per R06.

use super::map_mmio_pages;

// drivers-plan D1a model drivers. Each live virtio driver gets a
// static `drv::Driver` whose `matches` keys on its PCI device-id.
// `probe` is a no-op: the inline bring-up below already brought the
// device up — D1b moves bring-up into `probe`. We `register_driver`
// + `bind` at the existing success sites; bring-up itself is unchanged.
macro_rules! model_driver {
    ($ty:ident, $static:ident, $name:literal, $($id:literal)|+) => {
        struct $ty;
        impl drv::Driver for $ty {
            fn name(&self) -> &'static str { $name }
            fn matches(&self, dev: &drv::Device) -> bool {
                dev.bus == "pci" && dev.vendor_id == 0x1AF4 && matches!(dev.device_id, $($id)|+)
            }
        }
        static $static: $ty = $ty;
    };
}
model_driver!(VirtioBlkDrv,   VIRTIO_BLK_DRV,   "virtio-blk",   0x1001 | 0x1042);
model_driver!(VirtioNetDrv,   VIRTIO_NET_DRV,   "virtio-net",   0x1000 | 0x1041);
model_driver!(VirtioGpuDrv,   VIRTIO_GPU_DRV,   "virtio-gpu",   0x1050);
model_driver!(VirtioInputDrv, VIRTIO_INPUT_DRV, "virtio-input", 0x1052);
model_driver!(VirtioRngDrv,   VIRTIO_RNG_DRV,   "virtio-rng",   0x1044);
model_driver!(VirtioVsockDrv, VIRTIO_VSOCK_DRV, "virtio-vsock", 0x1053);

/// Canonical `0000:bb:dd.f` addr for a BDF (matches enumeration loop).
/// # C: O(1)
fn pci_addr(bdf: pci::Bdf) -> alloc::string::String {
    alloc::format!("{:04x}:{:02x}:{:02x}.{}", 0u16, bdf.bus, bdf.device, bdf.function)
}

/// Register the model driver `d` once and bind the PCI device at `bdf`
/// to it (publishes `/sys/bus/pci/drivers/<name>` + the device's
/// `driver` symlink). Called from a bring-up success site.
/// # C: O(N_drivers + N_devices)
fn model_bind(d: &'static dyn drv::Driver, bdf: pci::Bdf) {
    drv::register_driver(d);
    drv::bind_addr("pci", &pci_addr(bdf), d.name());
}

// pub(super) so the trace (virtio_trace.rs) can read the fields without
// re-deriving them; the inline bring-up here is the sole producer.
pub(super) struct VirtioProbe {
    pub(super) cmd_orig: u16,
    pub(super) cmd_new:  u16,
    pub(super) cfg_va:   u64,
    pub(super) dev_features: u64,
    pub(super) drv_features: u64,
    pub(super) post_status: u32,
    pub(super) features_ok: bool,
    pub(super) msix_cfg:    u16,
    pub(super) num_queues:  u16,
    pub(super) queues: [(u16, u16); 8],
    pub(super) queues_len: usize,
    pub(super) q0_desc_pa:   u64,
    pub(super) q0_driver_pa: u64,
    pub(super) q0_device_pa: u64,
    pub(super) final_status: u8,
    pub(super) q0_notify_off: u16,
    pub(super) q0_notify_va:  u64,
    pub(super) post_notify_status: u8,
    pub(super) avail_idx_posted: u16,
    pub(super) used_idx_observed: u16,
    pub(super) isr_status: u8,
    pub(super) tx_used_idx: u16,
    pub(super) q1_notify_va: u64,
    pub(super) q1_notify_off: u16,
    pub(super) q0_size: u16,
    pub(super) q1_size: u16,
    pub(super) q1_desc_pa:   u64,
    pub(super) q1_driver_pa: u64,
    pub(super) q1_device_pa: u64,
    pub(super) rx0_buf_pa:  u64,
    pub(super) rx0_buf_len: u16,
    pub(super) mac:       [u8; 6],
    pub(super) mac_valid: bool,
    pub(super) tx0_buf_pa: u64,
    // virtio-blk device-cfg harvest: capacity (512B sectors) + block
    // size. Valid iff blk_cfg_valid. Serial read by the engine via GET_ID.
    pub(super) blk_capacity: u64,
    pub(super) blk_blk_size: u32,
    pub(super) blk_cfg_valid: bool,
    // D3.3: virtio-vsock guest CID (device-cfg offset 0, le64).
    pub(super) vsock_cid: u64,
    pub(super) vsock_cid_valid: bool,
}

/// Drive one modern virtio-pci device through FEATURES_OK and
/// scan its queue layout. Returns Some(probe) on success.
/// # SAFETY: caller is the boot path; PMM ready; single-CPU; IRQs masked.
/// # C: O(BAR pages mapped + ~num_queues u32 reads)
fn virtio_init_arch(d: &pci::PciDevice) -> Option<VirtioProbe> {
    if !virtio::is_modern(d.vendor_id, d.device_id) { return None; }
    let bdf = d.bdf;
    // Hoist device-class detection so queue 1 (TX) setup can hook in
    // alongside queue 0 inside the per-queue setup block below.
    let is_virtio_net_early = d.vendor_id == 0x1AF4
        && (d.device_id == 0x1000 || d.device_id == 0x1041);
    // D3.3: virtio-vsock (0x1053) also needs q1 (TX) programmed, like
    // virtio-net's q0(RX)+q1(TX) split (only net's dummy-TX-frame is gated).
    let is_virtio_vsock_early = d.vendor_id == 0x1AF4 && d.device_id == 0x1053;
    let needs_q1 = is_virtio_net_early || is_virtio_vsock_early;

    // Re-walk caps + decode virtio cfgs + decode BARs.
    let (vcaps, bars) = {
        #[cfg(target_arch = "x86_64")]
        {
            let r = hal_x86_64::pci::LegacyPci;
            let c = pci::capabilities(&r, bdf);
            let v = virtio::decode_all(&r, bdf, &c);
            let b = pci::decode_bars(&r, bdf);
            (v, b)
        }
        #[cfg(target_arch = "aarch64")]
        {
            match hal_aarch64::pci::EcamPci::from_published() {
                Some(r) => {
                    let c = pci::capabilities(&r, bdf);
                    let v = virtio::decode_all(&r, bdf, &c);
                    let b = pci::decode_bars(&r, bdf);
                    (v, b)
                }
                None => return None,
            }
        }
    };

    // Enable Memory + BusMaster in PCI cmd reg.
    let cmd_orig = {
        #[cfg(target_arch = "x86_64")]
        { let r = hal_x86_64::pci::LegacyPci;
          <hal_x86_64::pci::LegacyPci as pci::ConfigSpaceReader>::read32(&r, bdf, 0x04) }
        #[cfg(target_arch = "aarch64")]
        { match hal_aarch64::pci::EcamPci::from_published() {
            Some(r) => <hal_aarch64::pci::EcamPci as pci::ConfigSpaceReader>::read32(&r, bdf, 0x04),
            None => return None,
        } }
    };
    let cmd_new = (cmd_orig & 0xFFFF_0000) | ((cmd_orig & 0xFFFF) | 0x0006);
    if cmd_new != cmd_orig {
        #[cfg(target_arch = "x86_64")]
        { let r = hal_x86_64::pci::LegacyPci;
          <hal_x86_64::pci::LegacyPci as pci::ConfigSpaceReader>::write32(&r, bdf, 0x04, cmd_new); }
        #[cfg(target_arch = "aarch64")]
        { if let Some(r) = hal_aarch64::pci::EcamPci::from_published() {
            <hal_aarch64::pci::EcamPci as pci::ConfigSpaceReader>::write32(&r, bdf, 0x04, cmd_new);
        } }
    }

    // Locate COMMON cfg + map the BAR page.
    let common = vcaps.find(virtio::VIRTIO_PCI_CAP_COMMON_CFG)?;
    let bar_pa = match bars[common.bar as usize] {
        pci::Bar::Mem32 { base, .. } => base as u64,
        pci::Bar::Mem64 { base, .. } => base,
        _ => return None,
    };
    let common_pa = bar_pa + common.offset as u64;
    let page_pa = common_pa & !0xFFF;
    let page_off = (common_pa - page_pa) as u64;
    // SAFETY: BAR PA decoded from device BAR reg; bump VA is exclusive.
    let base_va = unsafe { map_mmio_pages(page_pa, 1) };
    let cfg_va = base_va + page_off;

    // u32 volatile R/W over the Device-attr MMIO window.
    let r32 = |off: u64| -> u32 {
        // SAFETY: cfg_va Device-attr mapped; off < 0x1000.
        unsafe { core::ptr::read_volatile((cfg_va + off) as *const u32) }
    };
    let w32 = |off: u64, v: u32| {
        // SAFETY: same window; writes drive device per spec.
        unsafe { core::ptr::write_volatile((cfg_va + off) as *mut u32, v); }
    };
    // F59-09: u16-precise writes for the byte/word fields in
    // virtio_pci_common_cfg. QEMU's `virtio_pci_common_write`
    // dispatches by `switch(addr)` — a 4-byte store at 0x14
    // only triggers the DEVSTATUS handler (byte 0); bytes 1-3
    // (config_generation @ 0x15 + queue_select @ 0x16) are
    // silently dropped. queue_select MUST be written as a u16
    // at 0x16 or it never takes effect.
    let w16 = |off: u64, v: u16| {
        // SAFETY: same window; per Virtio 1.2 §4.1.4.3 the field at `off` is u16-aligned.
        unsafe { core::ptr::write_volatile((cfg_va + off) as *mut u16, v); }
    };
    let w8 = |off: u64, v: u8| {
        // SAFETY: same window; per Virtio 1.2 §4.1.4.3 device_status is a u8 at +0x14.
        unsafe { core::ptr::write_volatile((cfg_va + off) as *mut u8, v); }
    };

    // Spec §3.1.1 driver init sequence.
    let st = |s: u8| -> u32 { s as u32 };
    w32(0x14, st(0));                                              // reset
    let _ = r32(0x14);
    w32(0x14, st(virtio::VIRTIO_STATUS_ACKNOWLEDGE));
    w32(0x14, st(virtio::VIRTIO_STATUS_ACKNOWLEDGE
               | virtio::VIRTIO_STATUS_DRIVER));

    // Feature negotiation. Insist on VIRTIO_F_VERSION_1 (bit 32) for
    // modern transport. F59-08: also accept VIRTIO_NET_F_MAC (bit 5)
    // + VIRTIO_NET_F_STATUS (bit 16) for virtio-net so QEMU's modern
    // virtio-net-pci queues actually start processing kicks. The
    // boot probe's q1 TX never advanced used.idx with only V1
    // negotiated; QEMU's virtio_net_set_status() gates queue
    // activation on a complete enough feature set for nets.
    w32(0x00, 0); let dev_feat_lo = r32(0x04);
    w32(0x00, 1); let dev_feat_hi = r32(0x04);
    let dev_features: u64 = ((dev_feat_hi as u64) << 32) | (dev_feat_lo as u64);
    let mut want = virtio::VIRTIO_F_VERSION_1;
    if d.vendor_id == 0x1AF4 && (d.device_id == 0x1000 || d.device_id == 0x1041) {
        want |= virtio::VIRTIO_NET_F_MAC | virtio::VIRTIO_NET_F_STATUS;
    }
    let drv_features: u64 = dev_features & want;
    w32(0x08, 1); w32(0x0C, (drv_features >> 32) as u32);
    w32(0x08, 0); w32(0x0C, (drv_features & 0xFFFF_FFFF) as u32);
    w32(0x14, st(virtio::VIRTIO_STATUS_ACKNOWLEDGE
               | virtio::VIRTIO_STATUS_DRIVER
               | virtio::VIRTIO_STATUS_FEATURES_OK));

    let post_status = r32(0x14) & 0xFF;
    let features_ok = post_status & virtio::VIRTIO_STATUS_FEATURES_OK as u32 != 0;

    let w_msix_nq = r32(0x10);
    let msix_cfg   = (w_msix_nq & 0xFFFF) as u16;
    let num_queues = (w_msix_nq >> 16) as u16;

    // Queue scan: iterate queue_select 0..min(num_queues, 8) reading
    // queue_size at +0x18. queue_size==0 means the queue is disabled
    // (per spec). queue_select sits in the high u16 of the same dword
    // as device_status; preserve status when writing.
    let mut queues = [(0u16, 0u16); 8];
    let mut queues_len = 0usize;
    let cap = if num_queues == 0 || num_queues > 8 { 8 } else { num_queues } as u16;
    for qi in 0..cap {
        // F59-09: queue_select is a u16 at +0x16 — must be a u16
        // store, not a u32 store at 0x14 (QEMU's switch-based
        // dispatcher would only update DEVSTATUS @ 0x14).
        w16(0x16, qi);
        let qs_data = r32(0x18);
        let queue_size = (qs_data & 0xFFFF) as u16;
        queues[queues_len] = (qi, queue_size);
        queues_len += 1;
        if queue_size == 0 { break; }
    }

    // Per-arch HHDM offset, hoisted once for all queue programming. The
    // virtio core (virtio_qsetup) programs EVERY virtqueue uniformly —
    // q0 (all devices) + q1 (net/vsock TX) here, q2/q3 for multi-queue
    // devices (virtio-snd) via the same `program_queue`.
    let hhdm = {
        #[cfg(target_arch = "x86_64")]
        { hal_x86_64::mmu_ops::hhdm_offset() }
        #[cfg(target_arch = "aarch64")]
        { hal_aarch64::mmu_ops::hhdm_offset() }
    };
    // queue 1 (TX) state captured when net/vsock program it below.
    let mut q1_desc_pa: u64 = 0;
    let mut q1_driver_pa: u64 = 0;
    let mut q1_device_pa: u64 = 0;
    let mut q1_notify_off_local: u16 = 0;
    let q0_size = if queues_len > 0 { queues[0].1 } else { 0 };
    let (q0_desc_pa, q0_driver_pa, q0_device_pa, q0_notify_off, final_status) = if features_ok {
        // q0: msix_vec=0 (vector 0). program_queue returns None if the
        // device reports queue_size==0 (no such queue) or alloc fails.
        match super::virtio_qsetup::program_queue(cfg_va, 0, 0, hhdm) {
            Some(r0) => {
                //: for virtio-net / virtio-vsock, also stand up queue 1
                // (TX) so we can post outgoing frames. queue 0 = RX,
                // queue 1 = TX by spec §5.1.6 Device Operation. q1 polls
                // used.idx, so bind VIRTIO_MSI_NO_VECTOR (0xFFFF).
                if needs_q1 {
                    if let Some(r1) = super::virtio_qsetup::program_queue(cfg_va, 1, 0xFFFF, hhdm) {
                        q1_desc_pa = r1.desc_pa;
                        q1_driver_pa = r1.driver_pa;
                        q1_device_pa = r1.device_pa;
                        q1_notify_off_local = r1.notify_off;
                    }
                }

                // DRIVER_OK
                w32(0x14, st(virtio::VIRTIO_STATUS_ACKNOWLEDGE
                           | virtio::VIRTIO_STATUS_DRIVER
                           | virtio::VIRTIO_STATUS_FEATURES_OK
                           | virtio::VIRTIO_STATUS_DRIVER_OK));
                let final_status = (r32(0x14) & 0xFF) as u8;
                (r0.desc_pa, r0.driver_pa, r0.device_pa, r0.notify_off, final_status)
            }
            None => (0, 0, 0, 0, post_status as u8),
        }
    } else {
        (0, 0, 0, 0, post_status as u8)
    };
    // virtio-blk (transitional 0x1001 or modern 0x1042) — device-cfg
    // is harvested below; the persistent engine (drv-virtio-blk) owns
    // all reads/writes once registered.
    let is_virtio_blk = d.vendor_id == 0x1AF4
        && (d.device_id == 0x1001 || d.device_id == 0x1042);

    //: for virtio-net (transitional 0x1000 or modern 0x1041),
    // post one RX buffer descriptor on queue 0 and bump avail.idx
    // before kicking. For other devices the queue stays empty so the
    // kick is a no-op nudge.
    let mut avail_idx_posted = 0u16;
    // F59-02: persisted RX-buffer info for runtime rx_poll. Set when
    // the virtio-net branch below allocates the boot-time RX page;
    // 0/0 if no virtio-net device or DRIVER_OK didn't land.
    let mut rx0_buf_pa_local: u64 = 0;
    let mut rx0_buf_len_local: u16 = 0;
    let is_virtio_net = d.vendor_id == 0x1AF4
        && (d.device_id == 0x1000 || d.device_id == 0x1041);
    let is_virtio_gpu = d.vendor_id == 0x1AF4 && d.device_id == 0x1050;
    let is_virtio_input = d.vendor_id == 0x1AF4 && d.device_id == 0x1052;
    let bdf_word = (d.bdf.bus as u32) << 16
                 | (d.bdf.device as u32) << 8
                 | (d.bdf.function as u32);
    if is_virtio_gpu && (final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0 {
        // The real DRM card (with the live DisplayInfo from CMD_GET_DISPLAY_INFO)
        // + the scanout are registered by post_init::get_display_info below; do
        // NOT register a second card here with an empty DisplayInfo::default()
        // (that became card0 with 0 crtcs and broke GETRESOURCES). Just bind the
        // D1a model entry.
        debug_boot! { klog::write_raw(b"[INFO]  virtio-gpu installed feat=");
            klog::write_hex_u64(drv_features); klog::write_raw(b"\n"); }
        model_bind(&VIRTIO_GPU_DRV, d.bdf); // D1a: publish + bind
    }
    if is_virtio_input && (final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0 {
        let evdev_id = drv_virtio_input::install_default(bdf_word);
        debug_boot! { klog::write_raw(b"[INFO]  virtio-input installed evdev_id=");
            klog::write_dec_u64(evdev_id as u64); klog::write_raw(b"\n"); }
        model_bind(&VIRTIO_INPUT_DRV, d.bdf); // D1a: publish + bind
    }
    // Stage 1: the persistent virtio-blk engine (drv-virtio-blk) owns
    // all blk reads now — the boot probe no longer issues a throwaway
    // sector-1 diagnostic. The device registers via `register_blk`
    // below and ext4 mounts through `BlockDevice::submit_sync`.
    if is_virtio_net && q0_desc_pa != 0 && (final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0 {
        let hhdm = {
            #[cfg(target_arch = "x86_64")]
            { hal_x86_64::mmu_ops::hhdm_offset() }
            #[cfg(target_arch = "aarch64")]
            { hal_aarch64::mmu_ops::hhdm_offset() }
        };
        if let Some(rx_pa) = pmm::setup::alloc_one_frame() {
            if hhdm != 0 {
                // F59-02: capture rx_pa for runtime rx_poll re-publish.
                rx0_buf_pa_local = rx_pa;
                rx0_buf_len_local = 2048;
                // Descriptor[0]: { addr=rx_pa; len=2048; flags=WRITE(2); next=0 }
                let desc0 = (hhdm.wrapping_add(q0_desc_pa)) as *mut u64;
                // SAFETY: HHDM-mapped, freshly-allocated frame, single-CPU.
                unsafe {
                    core::ptr::write_volatile(desc0, rx_pa);
                    // len=2048 (low 32) | flags=WRITE(2) << 32 | next=0 << 48
                    let lo32 = 2048u32 as u64;
                    let flags_next = (virtio::VRING_DESC_F_WRITE as u64) << 32;
                    core::ptr::write_volatile(desc0.add(1), lo32 | flags_next);
                }
                // avail.ring[0] = 0 at driver_pa+0x04
                let avail = (hhdm.wrapping_add(q0_driver_pa)) as *mut u16;
                // SAFETY: same frame, ring[0] at byte +4 = u16 offset 2.
                unsafe {
                    core::ptr::write_volatile(avail.add(2), 0u16);
                }
                // Memory barrier so the descriptor + ring writes are
                // observable before avail.idx bump.
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                // avail.idx = 1 at driver_pa+0x02 (u16 offset 1).
                // SAFETY: HHDM-mapped avail ring as above; this u16 store at idx publishes the descriptor we just wrote.
                unsafe { core::ptr::write_volatile(avail.add(1), 1u16); }
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                avail_idx_posted = 1;
            }
        }
    }

    //: kick the notify register for queue 0. Notify address per
    // Virtio 1.2 §4.1.4.4:
    //   notify_pa = NOTIFY_BAR_pa + notify_cap.offset + qoff * notify_mult
    // where qoff = the queue_notify_off captured above.
    let (q0_notify_va, post_notify_status) = if final_status & virtio::VIRTIO_STATUS_FAILED == 0
        && (final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0
    {
        if let Some(notify_cap) = vcaps.find(virtio::VIRTIO_PCI_CAP_NOTIFY_CFG) {
            let nbar_pa = match bars[notify_cap.bar as usize] {
                pci::Bar::Mem32 { base, .. } => base as u64,
                pci::Bar::Mem64 { base, .. } => base,
                _ => 0,
            };
            if nbar_pa != 0 {
                let nfy_pa = nbar_pa + notify_cap.offset as u64
                           + (q0_notify_off as u64) * (notify_cap.notify_off_multiplier as u64);
                let n_page_pa = nfy_pa & !0xFFF;
                let n_page_off = nfy_pa - n_page_pa;
                // SAFETY: NOTIFY BAR PA decoded from device cap; bump VA private.
                let n_va = unsafe { map_mmio_pages(n_page_pa, 1) };
                let kick_va = n_va + n_page_off;
                // Write queue index 0 as a u16 to the notify address.
                // SAFETY: kick_va Device-attr; aligned u16 write.
                unsafe { core::ptr::write_volatile(kick_va as *mut u16, 0u16); }
                // Brief observation window for any device-driven RX
                // completion (QEMU user-net delivers nothing without
                // packets, so used.idx will normally stay 0).
                for _ in 0..1_000_000 { core::hint::spin_loop(); }
                let st = (r32(0x14) & 0xFF) as u8;
                (kick_va, st)
            } else {
                (0u64, final_status)
            }
        } else {
            (0u64, final_status)
        }
    } else {
        (0u64, final_status)
    };

    //: virtio-net TX path. After DRIVER_OK + (existing F26) q0
    // kick, post one ethernet frame to queue 1, kick q1, observe
    // q1.used.idx. Frame = 12-byte virtio_net_hdr (zeros) + 60-byte
    // dummy ethernet broadcast frame. Single descriptor, flags=0
    // (driver-side only).
    let mut q1_notify_va_local: u64 = 0;
    let mut tx_used_idx_local: u16 = 0;
    // F59-05: persist TX scratch buffer PA so drv_virtio_net::modern::
    // tx_frame can rewrite + repost it after boot. 0 if no virtio-net
    // or DRIVER_OK didn't land or the q1 setup bailed before alloc.
    let mut tx0_buf_pa_local: u64 = 0;
    if is_virtio_net_early
        && q1_desc_pa != 0
        && (final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0
    {
        let hhdm = {
            #[cfg(target_arch = "x86_64")]
            { hal_x86_64::mmu_ops::hhdm_offset() }
            #[cfg(target_arch = "aarch64")]
            { hal_aarch64::mmu_ops::hhdm_offset() }
        };
        if let Some(tx_pa) = pmm::setup::alloc_one_frame() {
            tx0_buf_pa_local = tx_pa;
            if hhdm != 0 {
                let tx_va = hhdm.wrapping_add(tx_pa) as *mut u8;
                // SAFETY: HHDM-mapped freshly-allocated frame; bytes 0..72 stay within the 4 KiB page; we own this frame exclusively.
                unsafe {
                    // virtio_net_hdr: 12 bytes of zeros (no checksum, no GSO, num_buffers=0).
                    for i in 0..12usize { core::ptr::write_volatile(tx_va.add(i), 0); }
                    // 60-byte dummy ethernet frame at +12.
                    // dst MAC (broadcast) ff*6
                    for i in 0..6 { core::ptr::write_volatile(tx_va.add(12 + i), 0xFF); }
                    // src MAC 02:00:00:00:00:01
                    core::ptr::write_volatile(tx_va.add(18), 0x02);
                    for i in 19..24 { core::ptr::write_volatile(tx_va.add(i), 0); }
                    core::ptr::write_volatile(tx_va.add(23), 0x01);
                    // ethertype 0x0800 (IPv4)
                    core::ptr::write_volatile(tx_va.add(24), 0x08);
                    core::ptr::write_volatile(tx_va.add(25), 0x00);
                    // 46 bytes of pad (already zeroed via PMM in some
                    // setups; explicit for safety).
                    for i in 26..72 { core::ptr::write_volatile(tx_va.add(i), 0); }
                }
                // descriptor[0] for q1 = { addr=tx_pa, len=72, flags=0, next=0 }
                let q1_desc = (hhdm.wrapping_add(q1_desc_pa)) as *mut u64;
                // SAFETY: HHDM-mapped queue-1 descriptor table; aligned u64 stores within frame bounds; driver owns it.
                unsafe {
                    core::ptr::write_volatile(q1_desc, tx_pa);
                    core::ptr::write_volatile(q1_desc.add(1), 72u64);
                }
                // avail.ring[0] = 0; avail.idx = 1
                let q1_avail = (hhdm.wrapping_add(q1_driver_pa)) as *mut u16;
                // SAFETY: HHDM-mapped q1 avail ring frame; u16 offset 2 = ring[0], offset 1 = idx.
                unsafe {
                    core::ptr::write_volatile(q1_avail.add(2), 0u16);
                }
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                // SAFETY: same frame; published idx=1 after the desc and ring writes are observable.
                unsafe { core::ptr::write_volatile(q1_avail.add(1), 1u16); }
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                // Compute q1 notify VA from notify_cap + q1_off * mult.
                if let Some(notify_cap) = vcaps.find(virtio::VIRTIO_PCI_CAP_NOTIFY_CFG) {
                    let nbar_pa = match bars[notify_cap.bar as usize] {
                        pci::Bar::Mem32 { base, .. } => base as u64,
                        pci::Bar::Mem64 { base, .. } => base,
                        _ => 0,
                    };
                    if nbar_pa != 0 {
                        let nfy_pa = nbar_pa + notify_cap.offset as u64
                            + (q1_notify_off_local as u64)
                              * (notify_cap.notify_off_multiplier as u64);
                        let n_page_pa = nfy_pa & !0xFFF;
                        let n_page_off = nfy_pa - n_page_pa;
                        // SAFETY: NOTIFY BAR PA decoded from device cap; bump VA private to virtio.
                        let n_va = unsafe { super::map_mmio_pages(n_page_pa, 1) };
                        let kick_va = n_va + n_page_off;
                        q1_notify_va_local = kick_va;
                        // Write queue index 1 to the q1 notify VA.
                        // SAFETY: kick_va Device-attr mapped above; aligned u16 write.
                        unsafe { core::ptr::write_volatile(kick_va as *mut u16, 1u16); }
                        // Brief observation window for any TX completion.
                        for _ in 0..1_000_000 { core::hint::spin_loop(); }
                        let q1_used = (hhdm.wrapping_add(q1_device_pa)) as *const u16;
                        // SAFETY: HHDM-mapped q1 used ring; u16 idx at offset 1.
                        tx_used_idx_local = unsafe { core::ptr::read_volatile(q1_used.add(1)) };
                    }
                }
            }
        }
    }

    // D3.3: virtio-vsock q1 notify VA. No dummy TX frame (vsock has no
    // broadcast warm-up); the persistent driver posts real OP_* packets
    // post-boot. Just map the q1 notify window so `tx_packet` can kick.
    if is_virtio_vsock_early
        && q1_desc_pa != 0
        && (final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0
    {
        if let Some(notify_cap) = vcaps.find(virtio::VIRTIO_PCI_CAP_NOTIFY_CFG) {
            q1_notify_va_local = super::virtio_vsock_cfg::map_q1_notify(
                &notify_cap, &bars, q1_notify_off_local);
        }
    }

    //: locate ISR cap, map its BAR page, and read the ISR byte
    // post-kick. Per Virtio 1.2 §4.1.4.5: ISR is a 1-byte read-to-clear
    // register; bit 0 = queue interrupt, bit 1 = config-change
    // interrupt. With MSI-X unbound the device would normally route via
    // INTx; we're not catching those yet but the ISR poll lets us see
    // whether the device attempted notification.
    let isr_status = if avail_idx_posted > 0 {
        if let Some(isr_cap) = vcaps.find(virtio::VIRTIO_PCI_CAP_ISR_CFG) {
            let ibar_pa = match bars[isr_cap.bar as usize] {
                pci::Bar::Mem32 { base, .. } => base as u64,
                pci::Bar::Mem64 { base, .. } => base,
                _ => 0,
            };
            if ibar_pa != 0 {
                let isr_pa = ibar_pa + isr_cap.offset as u64;
                let i_page_pa = isr_pa & !0xFFF;
                let i_page_off = isr_pa - i_page_pa;
                // SAFETY: ISR BAR PA decoded from device cap; bump VA private.
                let i_va = unsafe { map_mmio_pages(i_page_pa, 1) };
                let isr_va = i_va + i_page_off;
                // SAFETY: isr_va Device-attr; aligned u8 read clears it.
                unsafe { core::ptr::read_volatile(isr_va as *const u8) }
            } else { 0 }
        } else { 0 }
    } else { 0 };

    // F59-04: harvest virtio-net MAC from the device-cfg region. Per
    // Virtio 1.2 §5.1.4 `virtio_net_config`, the first 6 bytes of the
    // device-cfg space are the MAC address (when F_MAC negotiated;
    // QEMU's virtio-net always supports it). Layout: bar=N off=M from
    // the `VIRTIO_PCI_CAP_DEVICE_CFG` capability decoded above.
    let mut mac_local: [u8; 6] = [0; 6];
    let mut mac_valid_local: bool = false;
    if is_virtio_net {
        if let Some(devcfg_cap) = vcaps.find(virtio::VIRTIO_PCI_CAP_DEVICE_CFG) {
            let dbar_pa = match bars[devcfg_cap.bar as usize] {
                pci::Bar::Mem32 { base, .. } => base as u64,
                pci::Bar::Mem64 { base, .. } => base,
                _ => 0,
            };
            if dbar_pa != 0 {
                let d_pa = dbar_pa + devcfg_cap.offset as u64;
                let d_page_pa = d_pa & !0xFFF;
                let d_page_off = d_pa - d_page_pa;
                // SAFETY: device-cfg BAR PA decoded from device cap; bump VA private; one-page window covers the 6-byte MAC at offset 0.
                let d_va = unsafe { map_mmio_pages(d_page_pa, 1) };
                let mac_va = d_va + d_page_off;
                for i in 0..6 {
                    // SAFETY: mac_va Device-attr-mapped above via map_mmio_pages; aligned u8 read within the one-page MAC window.
                    mac_local[i] = unsafe {
                        core::ptr::read_volatile((mac_va + i as u64) as *const u8)
                    };
                }
                mac_valid_local = true;
            }
        }
    }

    // Stage 1: harvest virtio_blk_config (spec §5.2.4) from the
    // device-cfg cap. capacity = le64 sectors (512B units) at offset 0;
    // blk_size = le32 at offset 20 iff VIRTIO_BLK_F_BLK_SIZE negotiated,
    // else the wire default 512. The serial is read later by the engine
    // via GET_ID, not from device-cfg. Same window pattern as the MAC
    // harvest above.
    // D3.3: harvest virtio_vsock_config (spec §5.10.4): guest_cid is a
    // le64 at device-cfg offset 0. Same window pattern as the MAC harvest.
    let mut vsock_cid_local: u64 = 0;
    let mut vsock_cid_valid_local: bool = false;
    if is_virtio_vsock_early {
        if let Some(devcfg_cap) = vcaps.find(virtio::VIRTIO_PCI_CAP_DEVICE_CFG) {
            let (cid, valid) = super::virtio_vsock_cfg::harvest_cid(&devcfg_cap, &bars);
            vsock_cid_local = cid;
            vsock_cid_valid_local = valid;
        }
    }

    let mut blk_capacity_local: u64 = 0;
    let mut blk_blk_size_local: u32 = virtio::VIRTIO_BLK_SECTOR_BYTES;
    let mut blk_cfg_valid_local: bool = false;
    if is_virtio_blk {
        if let Some(devcfg_cap) = vcaps.find(virtio::VIRTIO_PCI_CAP_DEVICE_CFG) {
            let (cap, bs, valid) =
                super::virtio_blk_cfg::harvest(&devcfg_cap, &bars, drv_features);
            blk_capacity_local = cap;
            blk_blk_size_local = bs;
            blk_cfg_valid_local = valid;
        }
    }


    //: read used.idx after the kick.
    let used_idx_observed = if avail_idx_posted > 0 && q0_device_pa != 0 {
        let hhdm = {
            #[cfg(target_arch = "x86_64")]
            { hal_x86_64::mmu_ops::hhdm_offset() }
            #[cfg(target_arch = "aarch64")]
            { hal_aarch64::mmu_ops::hhdm_offset() }
        };
        if hhdm != 0 {
            let used = (hhdm.wrapping_add(q0_device_pa)) as *const u16;
            // used.idx at +0x02 (u16 offset 1).
            // SAFETY: HHDM-mapped frame; aligned u16 load.
            unsafe { core::ptr::read_volatile(used.add(1)) }
        } else { 0 }
    } else { 0 };

    Some(VirtioProbe {
        cmd_orig: (cmd_orig & 0xFFFF) as u16,
        cmd_new:  (cmd_new  & 0xFFFF) as u16,
        cfg_va,
        dev_features,
        drv_features,
        post_status,
        features_ok,
        msix_cfg,
        num_queues,
        queues,
        queues_len,
        q0_desc_pa,
        q0_driver_pa,
        q0_device_pa,
        final_status,
        q0_notify_off,
        q0_notify_va,
        post_notify_status,
        avail_idx_posted,
        used_idx_observed,
        isr_status,
        tx_used_idx: tx_used_idx_local,
        q1_notify_va: q1_notify_va_local,
        q1_notify_off: q1_notify_off_local,
        q0_size,
        q1_size: if queues_len > 1 { queues[1].1 } else { 0 },
        q1_desc_pa,
        q1_driver_pa,
        q1_device_pa,
        rx0_buf_pa:  rx0_buf_pa_local,
        rx0_buf_len: rx0_buf_len_local,
        mac:       mac_local,
        mac_valid: mac_valid_local,
        tx0_buf_pa: tx0_buf_pa_local,
        blk_capacity:  blk_capacity_local,
        blk_blk_size:  blk_blk_size_local,
        blk_cfg_valid: blk_cfg_valid_local,
        vsock_cid:       vsock_cid_local,
        vsock_cid_valid: vsock_cid_valid_local,
    })
}

/// Drive one modern virtio-pci device + emit `[INFO] virtio-cfg ...`
/// + per-queue `[INFO] virtio-q ...` lines under `debug-boot`.
/// Side-effect work runs unconditionally; only the trace is gated.
/// # C: O(BAR pages mapped + ~num_queues u32 reads)
pub(super) fn virtio_probe_arch(d: &pci::PciDevice) {
    let p = match virtio_init_arch(d) { Some(p) => p, None => return };
    let bdf = d.bdf;
    super::virtio_trace::trace_probe(bdf, &p);
    // F59-01: hand persistent runtime state for the modern virtio-net
    // device to dev_virtio_net so later phases (RX poll, TX, ARP) can
    // drive the queues post-boot. Only register if the device reached
    // virtio-gpu post-init: submit CMD_GET_DISPLAY_INFO over CTRLQ.
    let is_virtio_gpu_post = d.vendor_id == 0x1AF4 && d.device_id == 0x1050;
    if is_virtio_gpu_post
        && (p.final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0
        && p.q0_desc_pa != 0
        && p.q0_notify_va != 0
    {
        // SAFETY: caller is boot path; PMM up; q0 + notify VAs valid; single-CPU.
        let _ = unsafe {
            drv_virtio_gpu::post_init::get_display_info(
                bdf.bus, bdf.device, bdf.function,
                p.drv_features,
                p.q0_desc_pa, p.q0_driver_pa, p.q0_device_pa,
                p.q0_notify_va,
            )
        };
    }

    // DRIVER_OK with both queues programmed; ring PAs and notify VAs
    // are required for the runtime path.
    let is_virtio_net = d.vendor_id == 0x1AF4
        && (d.device_id == 0x1000 || d.device_id == 0x1041);
    if is_virtio_net
        && (p.final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0
        && p.q0_desc_pa != 0
        && p.q1_desc_pa != 0
        && p.q0_notify_va != 0
        && p.q1_notify_va != 0
    {
        drv_virtio_net::modern::init_modern(
            drv_virtio_net::modern::ModernNetState {
                bus:      bdf.bus,
                device:   bdf.device,
                function: bdf.function,
                cfg_va:        p.cfg_va,
                q0_notify_va:  p.q0_notify_va,
                q1_notify_va:  p.q1_notify_va,
                q0_desc_pa:    p.q0_desc_pa,
                q0_driver_pa:  p.q0_driver_pa,
                q0_device_pa:  p.q0_device_pa,
                q1_desc_pa:    p.q1_desc_pa,
                q1_driver_pa:  p.q1_driver_pa,
                q1_device_pa:  p.q1_device_pa,
                q0_size:       p.q0_size,
                q1_size:       p.q1_size,
                rx0_buf_pa:    p.rx0_buf_pa,
                rx0_buf_len:   p.rx0_buf_len,
                mac:           p.mac,
                mac_valid:     p.mac_valid,
                tx0_buf_pa:    p.tx0_buf_pa,
            },
        );
        model_bind(&VIRTIO_NET_DRV, bdf); // D1a: publish + bind
    }

    // Stage 1: register the virtio-blk device as a `BlockDevice` so
    // ext4 can mount a real disk. The persistent engine (drv-virtio-blk)
    // reads the serial via GET_ID and owns all I/O. Gated on
    // blk_cfg_valid — a device whose device-cfg BAR never decoded
    // reports capacity=0; registering it would hand ext4 a phantom
    // zero-capacity disk to fail mounting. Helper keeps this file under
    // the line cap.
    if d.vendor_id == 0x1AF4 && (d.device_id == 0x1001 || d.device_id == 0x1042)
        && (p.final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0
        && p.q0_desc_pa != 0 && p.q0_notify_va != 0
        && p.blk_cfg_valid
    {
        super::virtio_blk_cfg::register_blk(
            bdf.bus, bdf.device, bdf.function,
            p.q0_desc_pa, p.q0_driver_pa, p.q0_device_pa,
            p.q0_notify_va, p.q0_size, p.blk_capacity, p.blk_blk_size,
        );
        model_bind(&VIRTIO_BLK_DRV, bdf); // D1a: publish + bind
    }

    // D3.1: virtio-rng (entropy). Generic q0 setup above already gave this
    // device a programmed requestq + DRIVER_OK. Hand the persistent ring
    // addresses to drv-virtio-rng, then immediately pull ~32 bytes and mix
    // them into the kernel RNG so boot starts with real hardware entropy.
    // The /dev/hwrng source hook is wired in kmain after enumeration.
    if d.vendor_id == 0x1AF4 && d.device_id == 0x1044
        && (p.final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0
        && p.q0_desc_pa != 0 && p.q0_notify_va != 0
    {
        let hhdm = {
            #[cfg(target_arch = "x86_64")]
            { hal_x86_64::mmu_ops::hhdm_offset() }
            #[cfg(target_arch = "aarch64")]
            { hal_aarch64::mmu_ops::hhdm_offset() }
        };
        if drv_virtio_rng::install(
            p.q0_desc_pa, p.q0_driver_pa, p.q0_device_pa,
            p.q0_notify_va, p.q0_size, hhdm,
        ) {
            // Seed the kernel RNG with real entropy at bring-up.
            let mut seed = [0u8; 32];
            let n = drv_virtio_rng::fill(&mut seed);
            if n > 0 { devfs::misc::add_entropy(&seed[..n]); }
            model_bind(&VIRTIO_RNG_DRV, bdf); // D1a: publish + bind
            debug_boot! {
                klog::write_raw(b"[INFO]  virtio-rng installed seeded=");
                klog::write_dec_u64(n as u64);
                klog::write_raw(b" bytes\n");
            }
        }
    }

    // D3.3: virtio-vsock (0x1053). Hand q0(RX)+q1(TX) rings + guest CID
    // to drv-virtio-vsock (pre-posts RX, installs the net::vsock TX hook).
    let vsock_ok = d.vendor_id == 0x1AF4 && d.device_id == 0x1053
        && (p.final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0
        && p.q0_desc_pa != 0 && p.q0_notify_va != 0
        && p.q1_desc_pa != 0 && p.q1_notify_va != 0 && p.vsock_cid_valid
        && super::virtio_vsock_cfg::install_vsock(
            p.q0_desc_pa, p.q0_driver_pa, p.q0_device_pa, p.q0_notify_va, p.q0_size,
            p.q1_desc_pa, p.q1_driver_pa, p.q1_device_pa, p.q1_notify_va, p.q1_size,
            p.vsock_cid);
    if vsock_ok {
        model_bind(&VIRTIO_VSOCK_DRV, bdf); // D1a: publish + bind
        debug_boot! {
            klog::write_raw(b"[INFO]  virtio-vsock installed cid=");
            klog::write_dec_u64(p.vsock_cid);
            klog::write_raw(b"\n");
        }
    }

    // F01: virtio-input event-queue drain. Pre-fill q0 + install softirq.
    if d.vendor_id == 0x1AF4 && d.device_id == 0x1052
        && (p.final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0
        && p.q0_desc_pa != 0 && p.q0_notify_va != 0 && p.q0_size != 0
    {
        let hhdm = {
            #[cfg(target_arch = "x86_64")]
            { hal_x86_64::mmu_ops::hhdm_offset() }
            #[cfg(target_arch = "aarch64")]
            { hal_aarch64::mmu_ops::hhdm_offset() }
        };
        let bdf_word = (bdf.bus as u32) << 16 | (bdf.device as u32) << 8 | (bdf.function as u32);
        // SAFETY: boot path; PMM up; q0 PAs + notify VA valid; single-CPU.
        let _ = unsafe {
            drv_virtio_input::drain::install_q0(bdf_word, p.q0_size,
                p.q0_desc_pa, p.q0_driver_pa, p.q0_device_pa, p.q0_notify_va, hhdm)
        };
    }
}
