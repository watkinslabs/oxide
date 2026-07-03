// Modern virtio-pci transport bring-up. Split from pci_boot/mod.rs.
// klog calls gated under debug_boot! per R06.

use super::map_mmio_pages;
use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{Spinlock, TaskList as VirtioTransportLockClass};

struct MappedTransportPage {
    page_pa: u64,
    mapping: mmio_map::Mapping,
}

#[derive(Default)]
struct TransportMappings {
    pages: Vec<MappedTransportPage>,
}

impl TransportMappings {
    fn map_page(&mut self, page_pa: u64) -> u64 {
        if page_pa == 0 {
            return 0;
        }
        for page in &self.pages {
            if page.page_pa == page_pa {
                return page.mapping.base_va();
            }
        }
        // SAFETY: virtio-pci decoded this page from a BAR capability owned by
        // the bound transport. The owned Mapping is kept until probe failure or
        // child remove quiesces the device.
        let mapping = unsafe { mmio_map::map_owned(page_pa, 1) };
        let base_va = mapping.base_va();
        self.pages.push(MappedTransportPage { page_pa, mapping });
        base_va
    }

    fn unmap_all(&mut self) {
        self.pages.clear();
    }
}

struct TransportRecord {
    bdf: u32,
    _mappings: TransportMappings,
    vring_frames: Vec<u64>,
    msi_id: u32,
    msix_entry_va: u64,
    msix_cap_off: u8,
}

static TRANSPORT_MMIO: Spinlock<Vec<TransportRecord>, VirtioTransportLockClass> =
    Spinlock::new(Vec::new());

struct VirtioPciDrv;
impl drv::Driver for VirtioPciDrv {
    fn name(&self) -> &'static str { "virtio-pci" }

    fn matches(&self, dev: &drv::Device) -> bool {
        dev.bus == "pci" && virtio::is_modern(dev.vendor_id, dev.device_id)
    }

    fn probe(&self, dev: &Arc<drv::Device>) -> drv::KResult<()> {
        let Some(d) = pci_device_from_pci_model(dev) else { return Err(drv::Error::ProbeFailed); };
        if !virtio::is_modern(d.vendor_id, d.device_id) {
            return Err(drv::Error::NoMatch);
        }

        let vaddr = alloc::format!("virtio{}", super::virtio_seq());
        let Some(vdev_id) = virtio::modern_device_id(d.device_id) else {
            return Err(drv::Error::NoMatch);
        };
        let virtio_dev = drv::device_add(Arc::new(
            drv::Device::new("virtio", vaddr, d.vendor_id, vdev_id, 0)
                .with_parent("pci", dev.addr.clone()),
        ));

        // A PCI virtio transport may bind before the device-specific virtio
        // driver exists, or the child probe may fail independently. The child
        // remains an unbound virtio device in the model in both cases.
        let _ = drv::auto_bind(&virtio_dev);
        Ok(())
    }

    fn remove(&self, dev: &drv::Device) {
        for child in drv::devices() {
            if child.bus != "virtio" {
                continue;
            }
            let Some((parent_bus, parent_addr)) = child.parent() else { continue };
            if parent_bus != "pci" || parent_addr != dev.addr {
                continue;
            }
            drv::device_del(&child);
        }
    }
}
static VIRTIO_PCI_DRV: VirtioPciDrv = VirtioPciDrv;

struct VirtioGpuDrv;
impl drv::Driver for VirtioGpuDrv {
    fn bus(&self) -> &'static str { "virtio" }

    fn name(&self) -> &'static str { "virtio-gpu" }

    fn matches(&self, dev: &drv::Device) -> bool {
        dev.bus == "virtio" && dev.vendor_id == 0x1AF4 && dev.device_id == 16
    }

    fn probe(&self, dev: &Arc<drv::Device>) -> drv::KResult<()> {
        if drv_virtio_gpu::is_present() {
            return Err(drv::Error::Busy);
        }
        let d = pci_device_from_virtio_child(dev).ok_or(drv::Error::ProbeFailed)?;
        let mut p = virtio_init_arch(&d, None).ok_or(drv::Error::ProbeFailed)?;
        super::virtio_trace::trace_probe(d.bdf, &p);
        if (p.final_status & virtio::VIRTIO_STATUS_DRIVER_OK) == 0
            || p.cfg_va == 0
            || p.q0_desc_pa == 0
            || p.q0_driver_pa == 0
            || p.q0_device_pa == 0
            || p.q0_notify_va == 0
            || p.q0_size == 0
        {
            release_q0_after_failed_probe(&mut p);
            return Err(drv::Error::ProbeFailed);
        }
        let resources = p.resources(&[p.q0_resource()]);
        let ok = drv_virtio_gpu::post_init::get_display_info(
            d.bdf.bus,
            d.bdf.device,
            d.bdf.function,
            p.drv_features,
            resources,
        );
        if !ok {
            release_q0_after_failed_probe(&mut p);
            return Err(drv::Error::ProbeFailed);
        }
        debug_boot! {
            klog::write_raw(b"[INFO]  virtio-gpu installed feat=");
            klog::write_hex_u64(p.drv_features);
            klog::write_raw(b"\n");
        }
        publish_transport_mmio(&mut p);
        Ok(())
    }

    fn remove(&self, dev: &drv::Device) {
        let Some(bdf) = pci_parent_bdf(dev) else { return };
        let bdf_word = bdf_word(bdf);
        if drv_virtio_gpu::uninstall(bdf_word).is_none() {
            return;
        }
        let _ = drv_virtio_gpu::post_init::uninstall_scanout(bdf_word);
        unpublish_transport_mmio(bdf_word);
    }
}
static VIRTIO_GPU_DRV: VirtioGpuDrv = VirtioGpuDrv;

struct VirtioInputDrv;
impl drv::Driver for VirtioInputDrv {
    fn bus(&self) -> &'static str { "virtio" }

    fn name(&self) -> &'static str { "virtio-input" }

    fn matches(&self, dev: &drv::Device) -> bool {
        dev.bus == "virtio" && dev.vendor_id == 0x1AF4 && dev.device_id == 18
    }

    fn probe(&self, dev: &Arc<drv::Device>) -> drv::KResult<()> {
        let d = pci_device_from_virtio_child(dev).ok_or(drv::Error::ProbeFailed)?;
        let mut p =
            virtio_init_arch(&d, Some(drv_virtio_input::drain::raise_drain))
                .ok_or(drv::Error::ProbeFailed)?;
        super::virtio_trace::trace_probe(d.bdf, &p);
        if (p.final_status & virtio::VIRTIO_STATUS_DRIVER_OK) == 0
            || p.cfg_va == 0
            || p.input_cfg_va == 0
            || p.q0_desc_pa == 0
            || p.q0_driver_pa == 0
            || p.q0_device_pa == 0
            || p.q0_notify_va == 0
            || p.q0_size == 0
        {
            release_q0_after_failed_probe(&mut p);
            return Err(drv::Error::ProbeFailed);
        }
        let bdf_word = bdf_word(d.bdf);
        let evdev_id = match unsafe { drv_virtio_input::install_device(bdf_word, p.input_cfg_va) } {
            Some(id) => id,
            None => {
                release_q0_after_failed_probe(&mut p);
                return Err(drv::Error::ProbeFailed);
            }
        };
        let resources = p.resources(&[p.q0_resource()]);
        let installed = drv_virtio_input::drain::install_eventq(evdev_id, resources);
        if installed.is_err() {
            let _ = drv_virtio_input::remove_device(bdf_word);
            release_q0_after_failed_probe(&mut p);
            return Err(drv::Error::ProbeFailed);
        }
        debug_boot! {
            klog::write_raw(b"[INFO]  virtio-input installed evdev_id=");
            klog::write_dec_u64(evdev_id as u64);
            klog::write_raw(if drv_virtio_input::is_pointer(evdev_id) { b" pointer\n" } else { b" keyboard\n" });
        }
        publish_transport_mmio(&mut p);
        Ok(())
    }

    fn remove(&self, dev: &drv::Device) {
        let Some(bdf) = pci_parent_bdf(dev) else { return };
        let bdf_word = bdf_word(bdf);
        if let Some(evdev_id) = drv_virtio_input::evdev_id_for_bdf(bdf_word) {
            let _ = drv_virtio_input::drain::uninstall_eventq(evdev_id);
            let _ = drv_virtio_input::remove_device(bdf_word);
        }
        unpublish_transport_mmio(bdf_word);
    }
}
static VIRTIO_INPUT_DRV: VirtioInputDrv = VirtioInputDrv;

struct VirtioNetDrv;
impl drv::Driver for VirtioNetDrv {
    fn bus(&self) -> &'static str { "virtio" }

    fn name(&self) -> &'static str { "virtio-net" }

    fn matches(&self, dev: &drv::Device) -> bool {
        dev.bus == "virtio" && dev.vendor_id == 0x1AF4 && dev.device_id == 1
    }

    fn probe(&self, dev: &Arc<drv::Device>) -> drv::KResult<()> {
        let d = pci_device_from_virtio_child(dev).ok_or(drv::Error::ProbeFailed)?;
        let device_key = bdf_word(d.bdf);
        if drv_virtio_net::modern::is_modern_present_for(device_key) {
            return Err(drv::Error::Busy);
        }
        let mut p =
            virtio_init_arch(&d, Some(drv_virtio_net::modern::raise_rx))
                .ok_or(drv::Error::ProbeFailed)?;
        super::virtio_trace::trace_probe(d.bdf, &p);
        if (p.final_status & virtio::VIRTIO_STATUS_DRIVER_OK) == 0
            || p.q0_desc_pa == 0
            || p.q0_driver_pa == 0
            || p.q0_device_pa == 0
            || p.q1_desc_pa == 0
            || p.q1_driver_pa == 0
            || p.q1_device_pa == 0
            || p.q0_notify_va == 0
            || p.q1_notify_va == 0
            || p.q0_size == 0
            || p.q1_size == 0
            || p.rx0_buf_pa == 0
            || p.rx0_buf_len == 0
            || p.tx0_buf_pa == 0
            || !p.mac_valid
        {
            release_net_after_failed_probe(&mut p);
            return Err(drv::Error::ProbeFailed);
        }
        let resources = p.resources(&[p.q0_resource(), p.q1_resource()]);
        if !drv_virtio_net::modern::init_modern(
            device_key,
            resources,
            d.bdf.bus,
            d.bdf.device,
            d.bdf.function,
            p.rx0_buf_pa,
            p.rx0_buf_len,
            p.mac,
            p.mac_valid,
            p.tx0_buf_pa,
        ) {
            release_net_after_failed_probe(&mut p);
            return Err(drv::Error::ProbeFailed);
        }
        match drv_virtio_net::modern::register_netdev(device_key) {
            Some(id) => {
                #[cfg(not(feature = "debug-boot"))]
                let _ = id;
                debug_boot! {
                    klog::write_raw(b"[INFO]  virtio-net-iface registered id=");
                    klog::write_dec_u64(id.0 as u64);
                    klog::write_raw(b"\n");
                }
                publish_transport_mmio(&mut p);
                Ok(())
            }
            None => {
                let _ = drv_virtio_net::modern::uninstall_modern(device_key);
                unmap_probe_mmio(&mut p);
                Err(drv::Error::ProbeFailed)
            }
        }
    }

    fn remove(&self, _dev: &drv::Device) {
        if let Some(bdf) = pci_parent_bdf(_dev) {
            let device_key = bdf_word(bdf);
            if drv_virtio_net::modern::is_modern_present_for(device_key) {
                let _ = drv_virtio_net::modern::unregister_netdev(device_key);
                if drv_virtio_net::modern::uninstall_modern(device_key) {
                    unpublish_transport_mmio(device_key);
                }
            }
        }
    }
}
static VIRTIO_NET_DRV: VirtioNetDrv = VirtioNetDrv;

struct VirtioBlkDrv;
impl drv::Driver for VirtioBlkDrv {
    fn bus(&self) -> &'static str { "virtio" }

    fn name(&self) -> &'static str { "virtio-blk" }

    fn matches(&self, dev: &drv::Device) -> bool {
        dev.bus == "virtio" && dev.vendor_id == 0x1AF4 && dev.device_id == 2
    }

    fn probe(&self, dev: &Arc<drv::Device>) -> drv::KResult<()> {
        let d = pci_device_from_virtio_child(dev).ok_or(drv::Error::ProbeFailed)?;
        let mut p =
            virtio_init_arch(&d, Some(drv_virtio_blk::modern::wake_completions))
                .ok_or(drv::Error::ProbeFailed)?;
        super::virtio_trace::trace_probe(d.bdf, &p);
        if (p.final_status & virtio::VIRTIO_STATUS_DRIVER_OK) == 0
            || p.q0_desc_pa == 0
            || p.q0_driver_pa == 0
            || p.q0_device_pa == 0
            || p.q0_notify_va == 0
            || p.q0_size == 0
            || !p.blk_cfg_valid
        {
            release_q0_after_failed_probe(&mut p);
            return Err(drv::Error::ProbeFailed);
        }
        let resources = p.resources(&[p.q0_resource()]);
        let idx = super::virtio_blk_cfg::register_blk(
            d.bdf.bus, d.bdf.device, d.bdf.function,
            resources,
            p.blk_capacity,
            p.blk_blk_size,
        );
        if idx == 0 {
            release_q0_after_failed_probe(&mut p);
            return Err(drv::Error::ProbeFailed);
        }
        publish_transport_mmio(&mut p);
        Ok(())
    }

    fn remove(&self, dev: &drv::Device) {
        if let Some(bdf) = pci_parent_bdf(dev) {
            let _ = super::virtio_blk_cfg::remove_blk(bdf.bus, bdf.device, bdf.function);
            unpublish_transport_mmio(bdf_word(bdf));
        }
    }
}
static VIRTIO_BLK_DRV: VirtioBlkDrv = VirtioBlkDrv;

struct VirtioRngDrv;
impl drv::Driver for VirtioRngDrv {
    fn bus(&self) -> &'static str { "virtio" }

    fn name(&self) -> &'static str { "virtio-rng" }

    fn matches(&self, dev: &drv::Device) -> bool {
        dev.bus == "virtio" && dev.vendor_id == 0x1AF4 && dev.device_id == 4
    }

    fn probe(&self, dev: &Arc<drv::Device>) -> drv::KResult<()> {
        let d = pci_device_from_virtio_child(dev).ok_or(drv::Error::ProbeFailed)?;
        let mut p = virtio_init_arch(&d, None).ok_or(drv::Error::ProbeFailed)?;
        super::virtio_trace::trace_probe(d.bdf, &p);
        if (p.final_status & virtio::VIRTIO_STATUS_DRIVER_OK) == 0
            || p.cfg_va == 0
            || p.q0_desc_pa == 0
            || p.q0_driver_pa == 0
            || p.q0_device_pa == 0
            || p.q0_notify_va == 0
            || p.q0_size == 0
        {
            release_q0_after_failed_probe(&mut p);
            return Err(drv::Error::ProbeFailed);
        }
        let resources = p.resources(&[p.q0_resource()]);
        let bdf_word = bdf_word(d.bdf);
        let probe = match drv_virtio_rng::install(bdf_word, resources) {
            Some(probe) => probe,
            None => {
                release_q0_after_failed_probe(&mut p);
                return Err(drv::Error::ProbeFailed);
            }
        };
        if let Some(hwrng_dev) = probe.hwrng_dev {
            drv::device_add(hwrng_dev);
        }

        // Seed the kernel RNG with real entropy at bring-up. Read from the
        // just-bound device, not whichever hwrng is currently active.
        let mut seed = [0u8; 32];
        let n = drv_virtio_rng::fill_from_bdf(bdf_word, &mut seed);
        if n == 0 {
            if let Some(remove) = drv_virtio_rng::uninstall(bdf_word) {
                if let Some(hwrng_dev) = remove.hwrng_dev {
                    drv::device_del(&hwrng_dev);
                }
                if let Some(promoted) = remove.promoted_hwrng_dev {
                    drv::device_add(promoted);
                }
            }
            release_q0_after_failed_probe(&mut p);
            return Err(drv::Error::ProbeFailed);
        }
        devfs::misc::add_entropy(&seed[..n]);
        debug_boot! {
            klog::write_raw(b"[INFO]  virtio-rng installed seeded=");
            klog::write_dec_u64(n as u64);
            klog::write_raw(b" bytes\n");
        }
        publish_transport_mmio(&mut p);
        Ok(())
    }

    fn remove(&self, dev: &drv::Device) {
        if let Some(bdf) = pci_parent_bdf(dev) {
            let bdf_word = bdf_word(bdf);
            if let Some(remove) = drv_virtio_rng::uninstall(bdf_word) {
                if let Some(hwrng_dev) = remove.hwrng_dev {
                    drv::device_del(&hwrng_dev);
                }
                if let Some(promoted) = remove.promoted_hwrng_dev {
                    drv::device_add(promoted);
                }
            }
            unpublish_transport_mmio(bdf_word);
        }
    }
}
static VIRTIO_RNG_DRV: VirtioRngDrv = VirtioRngDrv;

struct VirtioVsockDrv;
impl drv::Driver for VirtioVsockDrv {
    fn bus(&self) -> &'static str { "virtio" }

    fn name(&self) -> &'static str { "virtio-vsock" }

    fn matches(&self, dev: &drv::Device) -> bool {
        dev.bus == "virtio" && dev.vendor_id == 0x1AF4 && dev.device_id == 19
    }

    fn probe(&self, dev: &Arc<drv::Device>) -> drv::KResult<()> {
        if drv_virtio_vsock::present() {
            return Err(drv::Error::Busy);
        }
        let d = pci_device_from_virtio_child(dev).ok_or(drv::Error::ProbeFailed)?;
        let device_key = bdf_word(d.bdf);
        let mut p =
            virtio_init_arch(&d, Some(drv_virtio_vsock::raise_rx))
                .ok_or(drv::Error::ProbeFailed)?;
        super::virtio_trace::trace_probe(d.bdf, &p);
        if (p.final_status & virtio::VIRTIO_STATUS_DRIVER_OK) == 0
            || p.cfg_va == 0
            || p.q0_desc_pa == 0
            || p.q0_driver_pa == 0
            || p.q0_device_pa == 0
            || p.q0_notify_va == 0
            || p.q0_size == 0
            || p.q1_desc_pa == 0
            || p.q1_driver_pa == 0
            || p.q1_device_pa == 0
            || p.q1_notify_va == 0
            || p.q1_size == 0
            || !p.vsock_cid_valid
        {
            release_vsock_after_failed_probe(&mut p);
            return Err(drv::Error::ProbeFailed);
        }
        let resources = p.resources(&[p.q0_resource(), p.q1_resource()]);
        if !super::virtio_vsock_cfg::install_vsock(device_key, resources, p.vsock_cid) {
            release_vsock_after_failed_probe(&mut p);
            return Err(drv::Error::ProbeFailed);
        }
        debug_boot! {
            klog::write_raw(b"[INFO]  virtio-vsock installed cid=");
            klog::write_dec_u64(p.vsock_cid);
            klog::write_raw(b"\n");
        }
        publish_transport_mmio(&mut p);
        Ok(())
    }

    fn remove(&self, dev: &drv::Device) {
        let Some(bdf) = pci_parent_bdf(dev) else { return };
        let device_key = bdf_word(bdf);
        if !drv_virtio_vsock::uninstall(device_key) {
            return;
        }
        unpublish_transport_mmio(device_key);
    }
}
static VIRTIO_VSOCK_DRV: VirtioVsockDrv = VirtioVsockDrv;

struct VirtioSndDrv;
impl drv::Driver for VirtioSndDrv {
    fn bus(&self) -> &'static str { "virtio" }

    fn name(&self) -> &'static str { "virtio-snd" }

    fn matches(&self, dev: &drv::Device) -> bool {
        dev.bus == "virtio" && dev.vendor_id == 0x1AF4 && dev.device_id == 25
    }

    fn probe(&self, dev: &Arc<drv::Device>) -> drv::KResult<()> {
        if drv_virtio_snd::present() {
            return Err(drv::Error::Busy);
        }
        let d = pci_device_from_virtio_child(dev).ok_or(drv::Error::ProbeFailed)?;
        let device_key = bdf_word(d.bdf);
        let mut p = virtio_init_arch(&d, None).ok_or(drv::Error::ProbeFailed)?;
        super::virtio_trace::trace_probe(d.bdf, &p);
        if (p.final_status & virtio::VIRTIO_STATUS_DRIVER_OK) == 0
            || p.cfg_va == 0
            || p.q0_desc_pa == 0
            || p.q0_driver_pa == 0
            || p.q0_device_pa == 0
            || p.q0_notify_va == 0
            || p.q0_size == 0
            || !p.snd_cfg_valid
        {
            release_snd_after_failed_probe(&mut p);
            return Err(drv::Error::ProbeFailed);
        }
        let resources = p.resources(&[
            p.q0_resource(),
            p.snd_q2_resource(),
            p.snd_q3_resource(),
        ]);
        let sp = super::virtio_snd_cfg::install_snd(
            device_key,
            resources,
            p.snd_jacks,
            p.snd_streams,
            p.snd_chmaps,
            p.snd_controls,
        ).ok_or_else(|| {
            release_snd_after_failed_probe(&mut p);
            drv::Error::ProbeFailed
        })?;
        #[cfg(not(feature = "debug-boot"))]
        let _ = &sp;
        debug_boot! {
            klog::write_raw(b"[INFO]  virtio-snd: bdf=0:");
            klog::write_dec_u64(d.bdf.device as u64);
            klog::write_raw(b".0 card=C0 streams=");
            klog::write_dec_u64(sp.streams as u64);
            klog::write_raw(b" out=");
            klog::write_dec_u64(sp.out as u64);
            klog::write_raw(b" in=");
            klog::write_dec_u64(sp.input as u64);
            klog::write_raw(b"\n");
            let beep_diag = drv_virtio_snd::beep_diag(440, 150);
            klog::write_raw(b"[INFO]  virtio-snd: boot-tone diag=");
            klog::write_dec_u64(beep_diag as u64);
            klog::write_raw(b"\n");
        }
        publish_transport_mmio(&mut p);
        Ok(())
    }

    fn remove(&self, dev: &drv::Device) {
        if let Some(bdf) = pci_parent_bdf(dev) {
            let device_key = bdf_word(bdf);
            if drv_virtio_snd::uninstall(device_key) {
                unpublish_transport_mmio(device_key);
            }
        }
    }
}
static VIRTIO_SND_DRV: VirtioSndDrv = VirtioSndDrv;

fn bdf_word(bdf: pci::Bdf) -> u32 {
    (bdf.bus as u32) << 16 | (bdf.device as u32) << 8 | (bdf.function as u32)
}

fn bdf_from_word(word: u32) -> pci::Bdf {
    pci::Bdf {
        bus: ((word >> 16) & 0xFF) as u8,
        device: ((word >> 8) & 0xFF) as u8,
        function: (word & 0xFF) as u8,
    }
}

#[derive(Clone, Copy)]
struct MsixBinding {
    id: u32,
    entry_va: u64,
    cap_off: u8,
}

fn bind_virtio_msix0(
    d: &pci::PciDevice,
    caps: &pci::heapless_caps::CapVec,
    bars: &[pci::Bar; 6],
    mappings: &mut TransportMappings,
    handler: fn(),
) -> Option<MsixBinding> {
    let c = caps.find(pci::CAP_ID_MSIX)?;
    let m = decode_msix_cap_arch(d.bdf, c.cfg_off)?;
    if m.table_size == 0 {
        return None;
    }
    let tbar_pa = bars.get(m.table_bir as usize).and_then(|b| b.mem_base())?;
    let tbl_pa = tbar_pa + m.table_offset as u64;
    let page_pa = tbl_pa & !0xFFF;
    let page_off = tbl_pa - page_pa;

    let (id, msg_addr, msg_data) = alloc_msi_message()?;
    if !register_msi_handler(id, handler) {
        free_msi_id(id);
        return None;
    }
    let base_va = mappings.map_page(page_pa);
    let entry_va = base_va + page_off;

    // SAFETY: entry_va is entry 0 of the mapped MSI-X table page. Each field
    // is naturally aligned within the 16-byte MSI-X table entry.
    unsafe {
        core::ptr::write_volatile(entry_va as *mut u32, (msg_addr & 0xFFFF_FFFF) as u32);
        core::ptr::write_volatile((entry_va + 4) as *mut u32, (msg_addr >> 32) as u32);
        core::ptr::write_volatile((entry_va + 8) as *mut u32, msg_data);
        core::ptr::write_volatile((entry_va + 12) as *mut u32, 0);
    }
    set_msix_enabled_arch(d.bdf, c.cfg_off, true);
    Some(MsixBinding { id, entry_va, cap_off: c.cfg_off })
}

fn release_msix_binding(rec: TransportRecord) {
    if rec.msix_entry_va != 0 {
        // SAFETY: this VA was recorded from the MSI-X table mapping while the
        // transport was bound and is still mapped until the caller unmaps the
        // transport MMIO pages.
        unsafe { core::ptr::write_volatile((rec.msix_entry_va + 12) as *mut u32, 1); }
    }
    if rec.msix_cap_off != 0 {
        set_msix_enabled_arch(bdf_from_word(rec.bdf), rec.msix_cap_off, false);
    }
    free_msi_id(rec.msi_id);
}

fn release_probe_msix(p: &VirtioProbe) {
    if p.msix_entry_va != 0 {
        // SAFETY: this VA was recorded from the MSI-X table mapping while the
        // probe-owned transport mappings are still live.
        unsafe { core::ptr::write_volatile((p.msix_entry_va + 12) as *mut u32, 1); }
    }
    if p.msix_cap_off != 0 {
        set_msix_enabled_arch(bdf_from_word(p.bdf_word), p.msix_cap_off, false);
    }
    free_msi_id(p.msi_id);
}

fn decode_msix_cap_arch(bdf: pci::Bdf, cfg_off: u8) -> Option<pci::MsixCap> {
    #[cfg(target_arch = "x86_64")]
    {
        let r = hal_x86_64::pci::LegacyPci;
        pci::decode_msix_cap(&r, bdf, cfg_off)
    }
    #[cfg(target_arch = "aarch64")]
    {
        hal_aarch64::pci::EcamPci::from_published()
            .and_then(|r| pci::decode_msix_cap(&r, bdf, cfg_off))
    }
}

fn set_msix_enabled_arch(bdf: pci::Bdf, cfg_off: u8, enabled: bool) {
    let off = cfg_off & 0xFC;
    #[cfg(target_arch = "x86_64")]
    {
        let r = hal_x86_64::pci::LegacyPci;
        use pci::ConfigSpaceReader as _;
        let cur = r.read32(bdf, off);
        let new = if enabled { cur | (1u32 << 31) } else { cur & !(1u32 << 31) };
        r.write32(bdf, off, new);
    }
    #[cfg(target_arch = "aarch64")]
    {
        if let Some(r) = hal_aarch64::pci::EcamPci::from_published() {
            let cur =
                <hal_aarch64::pci::EcamPci as pci::ConfigSpaceReader>::read32(&r, bdf, off);
            let new = if enabled { cur | (1u32 << 31) } else { cur & !(1u32 << 31) };
            <hal_aarch64::pci::EcamPci as pci::ConfigSpaceReader>::write32(&r, bdf, off, new);
        }
    }
}

fn alloc_msi_message() -> Option<(u32, u64, u32)> {
    #[cfg(target_arch = "x86_64")]
    {
        arch_irq::alloc_x86_vector().map(|vec| (vec as u32, 0xFEE0_0000u64, vec as u32))
    }
    #[cfg(target_arch = "aarch64")]
    {
        let spi = arch_irq::alloc_arm_spi()?;
        // SAFETY: SPI was allocated from arch-irq's GICv2m MSI range.
        unsafe { arch_irq::gic::enable_intid(spi); }
        let v2m_pa = firmware::acpi::GIC_MSI_FRAME_PA
            .load(core::sync::atomic::Ordering::Acquire);
        if v2m_pa == 0 {
            let _ = arch_irq::free_arm_spi(spi);
            return None;
        }
        Some((spi, v2m_pa + 0x40, spi))
    }
}

fn register_msi_handler(id: u32, handler: fn()) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        arch_irq::register_msi_handler(id as u8, handler).is_ok()
    }
    #[cfg(target_arch = "aarch64")]
    {
        arch_irq::register_msi_handler(id, handler).is_ok()
    }
}

fn free_msi_id(id: u32) {
    if id == 0 {
        return;
    }
    #[cfg(target_arch = "x86_64")]
    let _ = arch_irq::free_x86_vector(id as u8);
    #[cfg(target_arch = "aarch64")]
    let _ = arch_irq::free_arm_spi(id);
}

fn publish_transport_mmio(p: &mut VirtioProbe) {
    let rec = TransportRecord {
        bdf: p.bdf_word,
        _mappings: core::mem::take(&mut p.mappings),
        vring_frames: transport_vring_frames(p),
        msi_id: p.msi_id,
        msix_entry_va: p.msix_entry_va,
        msix_cap_off: p.msix_cap_off,
    };
    let mut records = TRANSPORT_MMIO.lock();
    if let Some(idx) = records.iter().position(|old| old.bdf == p.bdf_word) {
        let old = records.remove(idx);
        unmap_transport_record(old);
    }
    records.push(rec);
}

fn unmap_transport_record(rec: TransportRecord) {
    for frame in rec.vring_frames.iter().copied() {
        if frame == 0 {
            continue;
        }
        // SAFETY: these frames were allocated and programmed by the virtio-pci
        // transport for the child device. Child remove resets/quiesces the
        // device before unpublishing this transport record.
        unsafe { pmm::setup::free_one_frame(frame); }
    }
    release_msix_binding(rec);
}

fn transport_vring_frames(p: &VirtioProbe) -> Vec<u64> {
    let mut frames = Vec::new();
    for frame in [
        p.q0_desc_pa,
        p.q0_driver_pa,
        p.q0_device_pa,
        p.q1_desc_pa,
        p.q1_driver_pa,
        p.q1_device_pa,
        p.snd_q2_desc_pa,
        p.snd_q2_driver_pa,
        p.snd_q2_device_pa,
        p.snd_q3_desc_pa,
        p.snd_q3_driver_pa,
        p.snd_q3_device_pa,
    ] {
        if frame != 0 && !frames.iter().any(|existing| *existing == frame) {
            frames.push(frame);
        }
    }
    frames
}

fn unpublish_transport_mmio(bdf: u32) {
    let rec = {
        let mut records = TRANSPORT_MMIO.lock();
        records
            .iter()
            .position(|rec| rec.bdf == bdf)
            .map(|idx| records.remove(idx))
    };
    if let Some(rec) = rec {
        unmap_transport_record(rec);
    }
}

fn unmap_probe_mmio(p: &mut VirtioProbe) {
    release_probe_msix(p);
    p.mappings.unmap_all();
}

fn release_q0_after_failed_probe(p: &mut VirtioProbe) {
    release_gpu_transport(p.cfg_va, p.q0_desc_pa, p.q0_driver_pa, p.q0_device_pa);
    unmap_probe_mmio(p);
}

fn release_net_after_failed_probe(p: &mut VirtioProbe) {
    release_virtio_transport(
        p.cfg_va,
        &[
            p.q0_desc_pa,
            p.q0_driver_pa,
            p.q0_device_pa,
            p.q1_desc_pa,
            p.q1_driver_pa,
            p.q1_device_pa,
            p.rx0_buf_pa,
            p.tx0_buf_pa,
        ],
    );
    unmap_probe_mmio(p);
}

fn release_vsock_after_failed_probe(p: &mut VirtioProbe) {
    release_virtio_transport(
        p.cfg_va,
        &[
            p.q0_desc_pa,
            p.q0_driver_pa,
            p.q0_device_pa,
            p.q1_desc_pa,
            p.q1_driver_pa,
            p.q1_device_pa,
        ],
    );
    unmap_probe_mmio(p);
}

fn release_snd_after_failed_probe(p: &mut VirtioProbe) {
    release_virtio_transport(
        p.cfg_va,
        &[
            p.q0_desc_pa,
            p.q0_driver_pa,
            p.q0_device_pa,
            p.snd_q2_desc_pa,
            p.snd_q2_driver_pa,
            p.snd_q2_device_pa,
            p.snd_q3_desc_pa,
            p.snd_q3_driver_pa,
            p.snd_q3_device_pa,
        ],
    );
    unmap_probe_mmio(p);
}

fn release_gpu_transport(cfg_va: u64, q0_desc_pa: u64, q0_driver_pa: u64, q0_device_pa: u64) {
    release_virtio_transport(cfg_va, &[q0_desc_pa, q0_driver_pa, q0_device_pa]);
}

fn release_virtio_transport(cfg_va: u64, frames: &[u64]) {
    if cfg_va != 0 {
        // SAFETY: cfg_va is a mapped virtio common-cfg window returned by
        // virtio_init_arch; device_status is a u8 at +0x14.
        unsafe { core::ptr::write_volatile((cfg_va + 0x14) as *mut u8, 0u8); }
    }
    for frame in frames.iter().copied() {
        if frame == 0 {
            continue;
        }
        // SAFETY: non-zero frames passed here were allocated by the failed
        // virtio probe and have not been retained by runtime driver state.
        unsafe { pmm::setup::free_one_frame(frame); }
    }
}

fn notify_va_owned(
    mappings: &mut TransportMappings,
    notify_cap: &virtio::VirtioPciCap,
    bars: &[pci::Bar; 6],
    notify_off: u16,
) -> u64 {
    let Some(nfy_pa) = virtio::notify_pa(notify_cap, bars, notify_off) else {
        return 0;
    };
    let n_page_pa = nfy_pa & !0xFFF;
    let n_page_off = nfy_pa - n_page_pa;
    mappings.map_page(n_page_pa) + n_page_off
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex_byte(s: &[u8]) -> Option<u8> {
    Some((hex_nibble(*s.first()?)? << 4) | hex_nibble(*s.get(1)?)?)
}

fn parse_pci_addr(addr: &str) -> Option<pci::Bdf> {
    let b = addr.as_bytes();
    if b.len() != 12 || b[4] != b':' || b[7] != b':' || b[10] != b'.' {
        return None;
    }
    Some(pci::Bdf {
        bus: hex_byte(&b[5..7])?,
        device: hex_byte(&b[8..10])?,
        function: hex_nibble(b[11])?,
    })
}

fn pci_device_from_pci_model(dev: &drv::Device) -> Option<pci::PciDevice> {
    if dev.bus != "pci" {
        return None;
    }
    pci_device_from_bdf(parse_pci_addr(&dev.addr)?)
}

fn pci_parent_bdf(dev: &drv::Device) -> Option<pci::Bdf> {
    let (bus, addr) = dev.parent()?;
    if bus != "pci" {
        return None;
    }
    parse_pci_addr(addr)
}

fn pci_device_from_virtio_child(dev: &drv::Device) -> Option<pci::PciDevice> {
    pci_device_from_bdf(pci_parent_bdf(dev)?)
}

fn pci_device_from_bdf(bdf: pci::Bdf) -> Option<pci::PciDevice> {
    #[cfg(target_arch = "x86_64")]
    {
        let r = hal_x86_64::pci::LegacyPci;
        pci::PciDevice::from_config(&r, bdf)
    }
    #[cfg(target_arch = "aarch64")]
    {
        match hal_aarch64::pci::EcamPci::from_published() {
            Some(r) => pci::PciDevice::from_config(&r, bdf),
            None => None,
        }
    }
}

/// Register virtio drivers whose bring-up is owned by `Driver::probe`.
/// # C: O(N_drivers)
pub(super) fn register_model_drivers() {
    drv::register_driver(&VIRTIO_PCI_DRV);
    drv::register_driver(&VIRTIO_NET_DRV);
    drv::register_driver(&VIRTIO_BLK_DRV);
    drv::register_driver(&VIRTIO_RNG_DRV);
    drv::register_driver(&VIRTIO_VSOCK_DRV);
    drv::register_driver(&VIRTIO_SND_DRV);
    drv::register_driver(&VIRTIO_INPUT_DRV);
    drv::register_driver(&VIRTIO_GPU_DRV);
}

// pub(super) so the trace (virtio_trace.rs) can read the fields without
// re-deriving them; virtio model-driver probes are the producers.
pub(super) struct VirtioProbe {
    pub(super) bdf_word: u32,
    mappings: TransportMappings,
    pub(super) msi_id: u32,
    pub(super) msix_entry_va: u64,
    pub(super) msix_cap_off: u8,
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
    // F454: virtio_snd_config (docs/58§4, le32 ×4 at device-cfg offset 0).
    pub(super) snd_jacks:     u32,
    pub(super) snd_streams:   u32,
    pub(super) snd_chmaps:    u32,
    pub(super) snd_controls:  u32,
    pub(super) snd_cfg_valid: bool,
    // F455: virtio-snd TXQ(2) playback ring + notify VA. 0 if not snd or
    // the queue didn't program. (eventq/rxq land with events/capture.)
    pub(super) snd_q2_desc_pa:   u64,
    pub(super) snd_q2_driver_pa: u64,
    pub(super) snd_q2_device_pa: u64,
    pub(super) snd_q2_notify_va: u64,
    pub(super) snd_q2_notify_off: u16,
    pub(super) snd_q2_size:      u16,
    // F457: virtio-snd RXQ(3) capture ring + notify VA. 0 if not snd.
    pub(super) snd_q3_desc_pa:   u64,
    pub(super) snd_q3_driver_pa: u64,
    pub(super) snd_q3_device_pa: u64,
    pub(super) snd_q3_notify_va: u64,
    pub(super) snd_q3_notify_off: u16,
    pub(super) snd_q3_size:      u16,
    pub(super) input_cfg_va:     u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VirtioChildKind {
    Net,
    Block,
    Rng,
    Gpu,
    Input,
    Vsock,
    Snd,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct VirtioProbePlan {
    kind: VirtioChildKind,
}

impl VirtioProbePlan {
    fn from_device(d: &pci::PciDevice) -> Self {
        let kind = if d.vendor_id != 0x1AF4 {
            VirtioChildKind::Other
        } else {
            match d.device_id {
                0x1041 => VirtioChildKind::Net,
                0x1042 => VirtioChildKind::Block,
                0x1044 => VirtioChildKind::Rng,
                0x1050 => VirtioChildKind::Gpu,
                0x1052 => VirtioChildKind::Input,
                0x1053 => VirtioChildKind::Vsock,
                0x1059 => VirtioChildKind::Snd,
                _ => VirtioChildKind::Other,
            }
        };
        Self { kind }
    }

    fn wanted_features(self) -> u64 {
        let mut want = virtio::VIRTIO_F_VERSION_1;
        if self.kind == VirtioChildKind::Net {
            want |= virtio::VIRTIO_NET_F_MAC | virtio::VIRTIO_NET_F_STATUS;
        }
        want
    }

    fn needs_queue1(self) -> bool {
        matches!(self.kind, VirtioChildKind::Net | VirtioChildKind::Vsock)
    }

    fn needs_snd_data_queues(self) -> bool {
        self.kind == VirtioChildKind::Snd
    }

    fn needs_net_rx_seed(self) -> bool {
        self.kind == VirtioChildKind::Net
    }

    fn needs_net_tx_seed(self) -> bool {
        self.kind == VirtioChildKind::Net
    }

    fn needs_vsock_q1_notify(self) -> bool {
        self.kind == VirtioChildKind::Vsock
    }

    fn needs_net_config(self) -> bool {
        self.kind == VirtioChildKind::Net
    }

    fn needs_blk_config(self) -> bool {
        self.kind == VirtioChildKind::Block
    }

    fn needs_vsock_config(self) -> bool {
        self.kind == VirtioChildKind::Vsock
    }

    fn needs_snd_config(self) -> bool {
        self.kind == VirtioChildKind::Snd
    }

    fn needs_input_config_map(self) -> bool {
        self.kind == VirtioChildKind::Input
    }
}

fn virtio_hhdm_offset() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        hal_x86_64::mmu_ops::hhdm_offset()
    }
    #[cfg(target_arch = "aarch64")]
    {
        hal_aarch64::mmu_ops::hhdm_offset()
    }
}

impl VirtioProbe {
    fn resources(&self, queues: &[virtio::VirtQueueResource]) -> virtio::VirtioResources {
        virtio::VirtioResources::from_queues(self.cfg_va, virtio_hhdm_offset(), queues)
    }

    fn q0_resource(&self) -> virtio::VirtQueueResource {
        virtio::VirtQueueResource::new(
            0,
            self.q0_size,
            self.q0_desc_pa,
            self.q0_driver_pa,
            self.q0_device_pa,
            self.q0_notify_va,
            self.q0_notify_off,
        )
    }

    fn q1_resource(&self) -> virtio::VirtQueueResource {
        virtio::VirtQueueResource::new(
            1,
            self.q1_size,
            self.q1_desc_pa,
            self.q1_driver_pa,
            self.q1_device_pa,
            self.q1_notify_va,
            self.q1_notify_off,
        )
    }

    fn snd_q2_resource(&self) -> virtio::VirtQueueResource {
        virtio::VirtQueueResource::new(
            2,
            self.snd_q2_size,
            self.snd_q2_desc_pa,
            self.snd_q2_driver_pa,
            self.snd_q2_device_pa,
            self.snd_q2_notify_va,
            self.snd_q2_notify_off,
        )
    }

    fn snd_q3_resource(&self) -> virtio::VirtQueueResource {
        virtio::VirtQueueResource::new(
            3,
            self.snd_q3_size,
            self.snd_q3_desc_pa,
            self.snd_q3_driver_pa,
            self.snd_q3_device_pa,
            self.snd_q3_notify_va,
            self.snd_q3_notify_off,
        )
    }
}

/// Drive one modern virtio-pci device through FEATURES_OK and
/// scan its queue layout. Returns Some(probe) on success.
/// # SAFETY: caller is the boot path; PMM ready; single-CPU; IRQs masked.
/// # C: O(BAR pages mapped + ~num_queues u32 reads)
fn virtio_init_arch(d: &pci::PciDevice, msix0_handler: Option<fn()>) -> Option<VirtioProbe> {
    if !virtio::is_modern(d.vendor_id, d.device_id) { return None; }
    let bdf = d.bdf;
    let mut mappings = TransportMappings::default();
    let plan = VirtioProbePlan::from_device(d);

    // Re-walk caps + decode virtio cfgs + decode BARs.
    let (caps, vcaps, bars) = {
        #[cfg(target_arch = "x86_64")]
        {
            let r = hal_x86_64::pci::LegacyPci;
            let c = pci::capabilities(&r, bdf);
            let v = virtio::decode_all(&r, bdf, &c);
            let b = pci::decode_bars(&r, bdf);
            (c, v, b)
        }
        #[cfg(target_arch = "aarch64")]
        {
            match hal_aarch64::pci::EcamPci::from_published() {
                Some(r) => {
                    let c = pci::capabilities(&r, bdf);
                    let v = virtio::decode_all(&r, bdf, &c);
                    let b = pci::decode_bars(&r, bdf);
                    (c, v, b)
                }
                None => return None,
            }
        }
    };

    // Enable the PCI function only after the virtio-pci driver has claimed it.
    let cmd_orig = {
        #[cfg(target_arch = "x86_64")]
        { let r = hal_x86_64::pci::LegacyPci;
          pci::enable_mem_bus_master(&r, bdf) as u32 }
        #[cfg(target_arch = "aarch64")]
        { match hal_aarch64::pci::EcamPci::from_published() {
            Some(r) => pci::enable_mem_bus_master(&r, bdf) as u32,
            None => return None,
        } }
    };
    let cmd_new = (cmd_orig & 0xFFFF) | (pci::COMMAND_MEMORY | pci::COMMAND_BUS_MASTER) as u32;

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
    let base_va = mappings.map_page(page_pa);
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
    w8(0x14, 0);                                                   // reset
    let _ = r32(0x14);
    w8(0x14, virtio::VIRTIO_STATUS_ACKNOWLEDGE);
    w8(0x14, virtio::VIRTIO_STATUS_ACKNOWLEDGE
             | virtio::VIRTIO_STATUS_DRIVER);

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
    let drv_features: u64 = dev_features & plan.wanted_features();
    w32(0x08, 1); w32(0x0C, (drv_features >> 32) as u32);
    w32(0x08, 0); w32(0x0C, (drv_features & 0xFFFF_FFFF) as u32);
    w8(0x14, virtio::VIRTIO_STATUS_ACKNOWLEDGE
             | virtio::VIRTIO_STATUS_DRIVER
             | virtio::VIRTIO_STATUS_FEATURES_OK);

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
    // F455: virtio-snd TXQ(2) state captured when snd programs it below.
    let mut snd_q2_desc_pa_local:   u64 = 0;
    let mut snd_q2_driver_pa_local: u64 = 0;
    let mut snd_q2_device_pa_local: u64 = 0;
    let mut snd_q2_notify_va_local: u64 = 0;
    let mut snd_q2_notify_off_local: u16 = 0;
    let mut snd_q2_size_local:      u16 = 0;
    let mut snd_q3_desc_pa_local:   u64 = 0;
    let mut snd_q3_driver_pa_local: u64 = 0;
    let mut snd_q3_device_pa_local: u64 = 0;
    let mut snd_q3_notify_va_local: u64 = 0;
    let mut snd_q3_notify_off_local: u16 = 0;
    let mut snd_q3_size_local:      u16 = 0;
    let q0_size = if queues_len > 0 { queues[0].1 } else { 0 };
    let msix = if features_ok {
        msix0_handler.and_then(|handler| {
            bind_virtio_msix0(d, &caps, &bars, &mut mappings, handler)
        })
    } else { None };
    let q0_msix_vec = if msix.is_some() { 0 } else { 0xFFFF };
    let (q0_desc_pa, q0_driver_pa, q0_device_pa, q0_notify_off, final_status) = if features_ok {
        // q0 uses MSI-X table entry 0 only after the transport has
        // successfully allocated and programmed that entry.
        match super::virtio_qsetup::program_queue(cfg_va, 0, q0_msix_vec, hhdm) {
            Some(r0) => {
                //: for virtio-net / virtio-vsock, also stand up queue 1
                // (TX) so we can post outgoing frames. queue 0 = RX,
                // queue 1 = TX by spec §5.1.6 Device Operation. q1 polls
                // used.idx, so bind VIRTIO_MSI_NO_VECTOR (0xFFFF).
                if plan.needs_queue1() {
                    if let Some(r1) = super::virtio_qsetup::program_queue(cfg_va, 1, 0xFFFF, hhdm) {
                        q1_desc_pa = r1.desc_pa;
                        q1_driver_pa = r1.driver_pa;
                        q1_device_pa = r1.device_pa;
                        q1_notify_off_local = r1.notify_off;
                    }
                }

                // F455/F457: virtio-snd queues (CONTROLQ=0, EVENTQ=1, TXQ=2,
                // RXQ=3 per docs/58§2). Program TXQ(2, playback) + RXQ(3,
                // capture) + map each notify window. Poll used.idx →
                // VIRTIO_MSI_NO_VECTOR (0xFFFF).
                if plan.needs_snd_data_queues() {
                    let ncap = vcaps.find(virtio::VIRTIO_PCI_CAP_NOTIFY_CFG);
                    if let Some(r2) = super::virtio_qsetup::program_queue(cfg_va, 2, 0xFFFF, hhdm) {
                        snd_q2_desc_pa_local = r2.desc_pa;
                        snd_q2_driver_pa_local = r2.driver_pa;
                        snd_q2_device_pa_local = r2.device_pa;
                        snd_q2_notify_off_local = r2.notify_off;
                        snd_q2_size_local = r2.size;
                        if let Some(ncap) = ncap.as_ref() {
                            snd_q2_notify_va_local =
                                notify_va_owned(&mut mappings, ncap, &bars, r2.notify_off);
                        }
                    }
                    if let Some(r3) = super::virtio_qsetup::program_queue(cfg_va, 3, 0xFFFF, hhdm) {
                        snd_q3_desc_pa_local = r3.desc_pa;
                        snd_q3_driver_pa_local = r3.driver_pa;
                        snd_q3_device_pa_local = r3.device_pa;
                        snd_q3_notify_off_local = r3.notify_off;
                        snd_q3_size_local = r3.size;
                        if let Some(ncap) = ncap.as_ref() {
                            snd_q3_notify_va_local =
                                notify_va_owned(&mut mappings, ncap, &bars, r3.notify_off);
                        }
                    }
                }

                // DRIVER_OK
                w8(0x14, virtio::VIRTIO_STATUS_ACKNOWLEDGE
                         | virtio::VIRTIO_STATUS_DRIVER
                         | virtio::VIRTIO_STATUS_FEATURES_OK
                         | virtio::VIRTIO_STATUS_DRIVER_OK);
                let final_status = (r32(0x14) & 0xFF) as u8;
                (r0.desc_pa, r0.driver_pa, r0.device_pa, r0.notify_off, final_status)
            }
            None => (0, 0, 0, 0, post_status as u8),
        }
    } else {
        (0, 0, 0, 0, post_status as u8)
    };
    // virtio-blk modern-only 0x1042: device-cfg is harvested below; the
    // persistent engine (drv-virtio-blk) owns all reads/writes once registered.
    // For virtio-net modern-only 0x1041, post one RX buffer descriptor on
    // queue 0 and bump avail.idx before kicking. For other devices the queue
    // stays empty so the kick is a no-op nudge.
    let mut avail_idx_posted = 0u16;
    // F59-02: persisted RX-buffer info for runtime rx_poll. Set when
    // the virtio-net branch below allocates the boot-time RX page;
    // 0/0 if no virtio-net device or DRIVER_OK didn't land.
    let mut rx0_buf_pa_local: u64 = 0;
    let mut rx0_buf_len_local: u16 = 0;
    if plan.needs_net_rx_seed()
        && q0_desc_pa != 0
        && (final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0
    {
        if let Some(rx_pa) = pmm::setup::alloc_raw_frame() {
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
                let kick_va = notify_va_owned(&mut mappings, &notify_cap, &bars, q0_notify_off);
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
    if plan.needs_net_tx_seed()
        && q1_desc_pa != 0
        && (final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0
    {
        if let Some(tx_pa) = pmm::setup::alloc_raw_frame() {
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
                        let kick_va = notify_va_owned(
                            &mut mappings,
                            &notify_cap,
                            &bars,
                            q1_notify_off_local,
                        );
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
    if plan.needs_vsock_q1_notify()
        && q1_desc_pa != 0
        && (final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0
    {
        if let Some(notify_cap) = vcaps.find(virtio::VIRTIO_PCI_CAP_NOTIFY_CFG) {
            q1_notify_va_local =
                notify_va_owned(&mut mappings, &notify_cap, &bars, q1_notify_off_local);
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
                let status = unsafe { core::ptr::read_volatile(isr_va as *const u8) };
                // SAFETY: this was a temporary one-page ISR mapping used only
                // for the read-to-clear observation above.
                unsafe { mmio_map::unmap_pages(i_va, 1); }
                status
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
    if plan.needs_net_config() {
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
                // SAFETY: this was a temporary one-page device-cfg mapping
                // used only to harvest the MAC. Runtime net code keeps the
                // copied MAC bytes, not this VA.
                unsafe { mmio_map::unmap_pages(d_va, 1); }
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
    if plan.needs_vsock_config() {
        if let Some(devcfg_cap) = vcaps.find(virtio::VIRTIO_PCI_CAP_DEVICE_CFG) {
            let (cid, valid) = super::virtio_vsock_cfg::harvest_cid(&devcfg_cap, &bars);
            vsock_cid_local = cid;
            vsock_cid_valid_local = valid;
        }
    }

    let mut blk_capacity_local: u64 = 0;
    let mut blk_blk_size_local: u32 = virtio::VIRTIO_BLK_SECTOR_BYTES;
    let mut blk_cfg_valid_local: bool = false;
    if plan.needs_blk_config() {
        if let Some(devcfg_cap) = vcaps.find(virtio::VIRTIO_PCI_CAP_DEVICE_CFG) {
            let (cap, bs, valid) =
                super::virtio_blk_cfg::harvest(&devcfg_cap, &bars, drv_features);
            blk_capacity_local = cap;
            blk_blk_size_local = bs;
            blk_cfg_valid_local = valid;
        }
    }

    // F454: harvest virtio_snd_config (docs/58§4): le32 jacks/streams/
    // chmaps/controls at device-cfg offset 0. Same window pattern as MAC.
    let mut snd_jacks_local: u32 = 0;
    let mut snd_streams_local: u32 = 0;
    let mut snd_chmaps_local: u32 = 0;
    let mut snd_controls_local: u32 = 0;
    let mut snd_cfg_valid_local: bool = false;
    if plan.needs_snd_config() {
        if let Some(devcfg_cap) = vcaps.find(virtio::VIRTIO_PCI_CAP_DEVICE_CFG) {
            if let Some((j, s, c, ct)) = super::virtio_snd_cfg::harvest(&devcfg_cap, &bars) {
                snd_jacks_local = j;
                snd_streams_local = s;
                snd_chmaps_local = c;
                snd_controls_local = ct;
                snd_cfg_valid_local = true;
            }
        }
    }

    let mut input_cfg_va_local: u64 = 0;
    if plan.needs_input_config_map() {
        if let Some(devcfg_cap) = vcaps.find(virtio::VIRTIO_PCI_CAP_DEVICE_CFG) {
            let dbar_pa = match bars[devcfg_cap.bar as usize] {
                pci::Bar::Mem32 { base, .. } => base as u64,
                pci::Bar::Mem64 { base, .. } => base,
                _ => 0,
            };
            if dbar_pa != 0 {
                let d_pa = dbar_pa + devcfg_cap.offset as u64;
                let d_page_pa = d_pa & !0xFFF;
                let d_va = mappings.map_page(d_page_pa);
                input_cfg_va_local = d_va + (d_pa - d_page_pa);
            }
        }
    }


    //: read used.idx after the kick.
    let used_idx_observed = if avail_idx_posted > 0 && q0_device_pa != 0 {
        if hhdm != 0 {
            let used = (hhdm.wrapping_add(q0_device_pa)) as *const u16;
            // used.idx at +0x02 (u16 offset 1).
            // SAFETY: HHDM-mapped frame; aligned u16 load.
            unsafe { core::ptr::read_volatile(used.add(1)) }
        } else { 0 }
    } else { 0 };

    Some(VirtioProbe {
        bdf_word: bdf_word(bdf),
        mappings,
        msi_id: msix.map(|m| m.id).unwrap_or(0),
        msix_entry_va: msix.map(|m| m.entry_va).unwrap_or(0),
        msix_cap_off: msix.map(|m| m.cap_off).unwrap_or(0),
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
        snd_jacks:     snd_jacks_local,
        snd_streams:   snd_streams_local,
        snd_chmaps:    snd_chmaps_local,
        snd_controls:  snd_controls_local,
        snd_cfg_valid: snd_cfg_valid_local,
        snd_q2_desc_pa:   snd_q2_desc_pa_local,
        snd_q2_driver_pa: snd_q2_driver_pa_local,
        snd_q2_device_pa: snd_q2_device_pa_local,
        snd_q2_notify_va: snd_q2_notify_va_local,
        snd_q2_notify_off: snd_q2_notify_off_local,
        snd_q2_size:      snd_q2_size_local,
        snd_q3_desc_pa:   snd_q3_desc_pa_local,
        snd_q3_driver_pa: snd_q3_driver_pa_local,
        snd_q3_device_pa: snd_q3_device_pa_local,
        snd_q3_notify_va: snd_q3_notify_va_local,
        snd_q3_notify_off: snd_q3_notify_off_local,
        snd_q3_size:      snd_q3_size_local,
        input_cfg_va:     input_cfg_va_local,
    })
}
