// Modern virtio-pci transport bring-up. Split from pci_boot/mod.rs.
// klog calls gated under debug_boot! per R06.

use super::map_mmio_pages;
use super::virtio_qsetup::{ProgrammedQueues, QueuePlan, QueueRing};
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
    msix: Option<MsixBinding>,
}

static TRANSPORT_MMIO: Spinlock<Vec<TransportRecord>, VirtioTransportLockClass> =
    Spinlock::new(Vec::new());

#[derive(Clone, Copy)]
enum Q1NotifyPolicy {
    None,
    NetBootTx,
    PersistentTx,
}

#[derive(Clone, Copy)]
struct VirtioProbeProfile {
    drv_features: u64,
    msix0_handler: Option<fn()>,
    extra_queues: [Option<QueuePlan>; 3],
    q1_notify_policy: Q1NotifyPolicy,
    needs_net_boot_buffers: bool,
}

impl VirtioProbeProfile {
    const VERSION_ONLY: u64 = virtio::VIRTIO_F_VERSION_1;
    const NET_FEATURES: u64 =
        virtio::VIRTIO_F_VERSION_1 | virtio::VIRTIO_NET_F_MAC | virtio::VIRTIO_NET_F_STATUS;

    const fn generic(msix0_handler: Option<fn()>) -> Self {
        Self {
            drv_features: Self::VERSION_ONLY,
            msix0_handler,
            extra_queues: [None, None, None],
            q1_notify_policy: Q1NotifyPolicy::None,
            needs_net_boot_buffers: false,
        }
    }

    const fn net(msix0_handler: Option<fn()>) -> Self {
        Self {
            drv_features: Self::NET_FEATURES,
            msix0_handler,
            extra_queues: [Some(QueuePlan::new(1, 0xFFFF, false)), None, None],
            q1_notify_policy: Q1NotifyPolicy::NetBootTx,
            needs_net_boot_buffers: true,
        }
    }

    const fn input(msix0_handler: Option<fn()>) -> Self {
        Self {
            drv_features: Self::VERSION_ONLY,
            msix0_handler,
            extra_queues: [None, None, None],
            q1_notify_policy: Q1NotifyPolicy::None,
            needs_net_boot_buffers: false,
        }
    }

    const fn block(msix0_handler: Option<fn()>) -> Self {
        Self {
            drv_features: Self::VERSION_ONLY,
            msix0_handler,
            extra_queues: [None, None, None],
            q1_notify_policy: Q1NotifyPolicy::None,
            needs_net_boot_buffers: false,
        }
    }

    const fn rng(msix0_handler: Option<fn()>) -> Self {
        Self::generic(msix0_handler)
    }

    const fn vsock(msix0_handler: Option<fn()>) -> Self {
        Self {
            drv_features: Self::VERSION_ONLY,
            msix0_handler,
            extra_queues: [Some(QueuePlan::new(1, 0xFFFF, false)), None, None],
            q1_notify_policy: Q1NotifyPolicy::PersistentTx,
            needs_net_boot_buffers: false,
        }
    }

    const fn snd(msix0_handler: Option<fn()>) -> Self {
        Self {
            drv_features: Self::VERSION_ONLY,
            msix0_handler,
            extra_queues: [
                Some(QueuePlan::new(2, 0xFFFF, true)),
                Some(QueuePlan::new(3, 0xFFFF, true)),
                None,
            ],
            q1_notify_policy: Q1NotifyPolicy::None,
            needs_net_boot_buffers: false,
        }
    }
}

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

    fn shutdown(&self, dev: &drv::Device) {
        let Some(d) = pci_device_from_pci_model(dev) else { return };
        disable_pci_command(d.bdf);
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
        let mut p = virtio_init_arch(&d, VirtioProbeProfile::generic(None))
            .ok_or(drv::Error::ProbeFailed)?;
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

    fn shutdown(&self, dev: &drv::Device) {
        let Some(bdf) = pci_parent_bdf(dev) else { return };
        let _ = drv_virtio_gpu::shutdown(bdf_word(bdf));
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
        let mut p = virtio_init_arch(&d, VirtioProbeProfile::input(Some(drv_virtio_input::drain::raise_drain)))
            .ok_or(drv::Error::ProbeFailed)?;
        super::virtio_trace::trace_probe(d.bdf, &p);
        if (p.final_status & virtio::VIRTIO_STATUS_DRIVER_OK) == 0
            || p.cfg_va == 0
            || p.device_cfg_va == 0
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
        let resources = p.resources(&[p.q0_resource()]);
        let evdev_id = match drv_virtio_input::install_device(bdf_word, resources) {
            Some(id) => id,
            None => {
                release_q0_after_failed_probe(&mut p);
                return Err(drv::Error::ProbeFailed);
            }
        };
        if !drv_virtio_input::register_node(evdev_id) {
            let _ = drv_virtio_input::remove_device(bdf_word);
            release_q0_after_failed_probe(&mut p);
            return Err(drv::Error::ProbeFailed);
        }
        let installed = drv_virtio_input::drain::install_eventq(evdev_id, resources);
        if installed.is_err() {
            let _ = drv_virtio_input::unregister_node(evdev_id);
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
            let _ = drv_virtio_input::unregister_node(evdev_id);
            let _ = drv_virtio_input::remove_device(bdf_word);
        }
        unpublish_transport_mmio(bdf_word);
    }

    fn shutdown(&self, dev: &drv::Device) {
        let Some(bdf) = pci_parent_bdf(dev) else { return };
        let bdf_word = bdf_word(bdf);
        if let Some(evdev_id) = drv_virtio_input::evdev_id_for_bdf(bdf_word) {
            let _ = drv_virtio_input::drain::shutdown_eventq(evdev_id);
        }
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
        if drv_virtio_net::modern::is_modern_present() {
            return Err(drv::Error::Busy);
        }
        let d = pci_device_from_virtio_child(dev).ok_or(drv::Error::ProbeFailed)?;
        let device_key = bdf_word(d.bdf);
        let mut p = virtio_init_arch(&d, VirtioProbeProfile::net(Some(drv_virtio_net::modern::raise_rx)))
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
                    klog::write_raw(b" name=eth0\n");
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

    fn shutdown(&self, dev: &drv::Device) {
        if let Some(bdf) = pci_parent_bdf(dev) {
            let device_key = bdf_word(bdf);
            let _ = drv_virtio_net::modern::shutdown_modern(device_key);
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
        let mut p = virtio_init_arch(&d, VirtioProbeProfile::block(Some(drv_virtio_blk::modern::wake_completions)))
            .ok_or(drv::Error::ProbeFailed)?;
        super::virtio_trace::trace_probe(d.bdf, &p);
        if (p.final_status & virtio::VIRTIO_STATUS_DRIVER_OK) == 0
            || p.q0_desc_pa == 0
            || p.q0_driver_pa == 0
            || p.q0_device_pa == 0
            || p.q0_notify_va == 0
            || p.q0_size == 0
            || p.device_cfg_va == 0
        {
            release_q0_after_failed_probe(&mut p);
            return Err(drv::Error::ProbeFailed);
        }
        let resources = p.resources(&[p.q0_resource()]);
        let idx = super::virtio_blk_cfg::register_blk(
            d.bdf.bus, d.bdf.device, d.bdf.function,
            resources,
            p.drv_features,
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

    fn shutdown(&self, dev: &drv::Device) {
        if let Some(bdf) = pci_parent_bdf(dev) {
            let _ = super::virtio_blk_cfg::shutdown_blk(bdf.bus, bdf.device, bdf.function);
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
        let mut p = virtio_init_arch(&d, VirtioProbeProfile::rng(None))
            .ok_or(drv::Error::ProbeFailed)?;
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

    fn shutdown(&self, dev: &drv::Device) {
        if let Some(bdf) = pci_parent_bdf(dev) {
            let _ = drv_virtio_rng::shutdown(bdf_word(bdf));
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
        let mut p = virtio_init_arch(&d, VirtioProbeProfile::vsock(Some(drv_virtio_vsock::raise_rx)))
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
            || p.device_cfg_va == 0
        {
            release_vsock_after_failed_probe(&mut p);
            return Err(drv::Error::ProbeFailed);
        }
        let resources = p.resources(&[p.q0_resource(), p.q1_resource()]);
        if !super::virtio_vsock_cfg::install_vsock(device_key, resources) {
            release_vsock_after_failed_probe(&mut p);
            return Err(drv::Error::ProbeFailed);
        }
        debug_boot! {
            klog::write_raw(b"[INFO]  virtio-vsock installed cid=");
            klog::write_dec_u64(drv_virtio_vsock::guest_cid());
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

    fn shutdown(&self, dev: &drv::Device) {
        let Some(bdf) = pci_parent_bdf(dev) else { return };
        let device_key = bdf_word(bdf);
        let _ = drv_virtio_vsock::shutdown(device_key);
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
        let mut p = virtio_init_arch(&d, VirtioProbeProfile::snd(None))
            .ok_or(drv::Error::ProbeFailed)?;
        super::virtio_trace::trace_probe(d.bdf, &p);
        if (p.final_status & virtio::VIRTIO_STATUS_DRIVER_OK) == 0
            || p.cfg_va == 0
            || p.q0_desc_pa == 0
            || p.q0_driver_pa == 0
            || p.q0_device_pa == 0
            || p.q0_notify_va == 0
            || p.q0_size == 0
            || p.device_cfg_va == 0
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

    fn shutdown(&self, dev: &drv::Device) {
        if let Some(bdf) = pci_parent_bdf(dev) {
            let _ = drv_virtio_snd::shutdown(bdf_word(bdf));
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

fn release_msix_binding(bdf: pci::Bdf, binding: MsixBinding) {
    // SAFETY: entry_va was recorded from the MSI-X table mapping while the
    // transport was bound and is still mapped until the caller releases the
    // transport MMIO mappings.
    unsafe { core::ptr::write_volatile((binding.entry_va + 12) as *mut u32, 1); }
    set_msix_enabled_arch(bdf, binding.cap_off, false);
    free_msi_id(binding.id);
}

fn release_probe_msix(p: &mut VirtioProbe) {
    if let Some(binding) = p.msix.take() {
        release_msix_binding(bdf_from_word(p.bdf_word), binding);
    }
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
        msix: p.msix.take(),
    };
    let mut records = TRANSPORT_MMIO.lock();
    if let Some(idx) = records.iter().position(|old| old.bdf == p.bdf_word) {
        let old = records.remove(idx);
        unmap_transport_record(old);
    }
    records.push(rec);
}

fn disable_pci_command(bdf: pci::Bdf) {
    #[cfg(target_arch = "x86_64")]
    {
        let r = hal_x86_64::pci::LegacyPci;
        let cur = pci::read_command(&r, bdf);
        let restored = cur & !(pci::COMMAND_MEMORY | pci::COMMAND_BUS_MASTER);
        if restored != cur {
            pci::write_command(&r, bdf, restored);
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if let Some(r) = hal_aarch64::pci::EcamPci::from_published() {
            let cur = pci::read_command(&r, bdf);
            let restored = cur & !(pci::COMMAND_MEMORY | pci::COMMAND_BUS_MASTER);
            if restored != cur {
                pci::write_command(&r, bdf, restored);
            }
        }
    }
}

fn abandon_probe_transport(bdf: pci::Bdf, mappings: &mut TransportMappings) -> Option<VirtioProbe> {
    disable_pci_command(bdf);
    mappings.unmap_all();
    None
}

fn unmap_transport_record(rec: TransportRecord) {
    let bdf = bdf_from_word(rec.bdf);
    if let Some(binding) = rec.msix {
        release_msix_binding(bdf, binding);
    }
    disable_pci_command(bdf);
    for frame in rec.vring_frames.iter().copied() {
        if frame == 0 {
            continue;
        }
        // SAFETY: these frames were allocated and programmed by the virtio-pci
        // transport for the child device. Child remove resets/quiesces the
        // device before unpublishing this transport record.
        unsafe { pmm::setup::free_one_frame(frame); }
    }
}

fn push_unique_frame(frames: &mut Vec<u64>, frame: u64) {
    if frame != 0 && !frames.iter().any(|existing| *existing == frame) {
        frames.push(frame);
    }
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
        push_unique_frame(&mut frames, frame);
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
    disable_pci_command(bdf_from_word(p.bdf_word));
    p.mappings.unmap_all();
}

fn release_failed_probe_frames(p: &mut VirtioProbe, payload_frames: &[u64]) {
    let mut frames = transport_vring_frames(p);
    for frame in payload_frames.iter().copied() {
        push_unique_frame(&mut frames, frame);
    }
    release_virtio_transport(p.cfg_va, &frames);
    unmap_probe_mmio(p);
}

fn release_q0_after_failed_probe(p: &mut VirtioProbe) {
    release_failed_probe_frames(p, &[]);
}

fn release_net_after_failed_probe(p: &mut VirtioProbe) {
    let payload_frames = [p.rx0_buf_pa, p.tx0_buf_pa];
    release_failed_probe_frames(p, &payload_frames);
}

fn release_vsock_after_failed_probe(p: &mut VirtioProbe) {
    release_failed_probe_frames(p, &[]);
}

fn release_snd_after_failed_probe(p: &mut VirtioProbe) {
    release_failed_probe_frames(p, &[]);
}

fn release_virtio_transport(cfg_va: u64, frames: &[u64]) {
    super::virtio_qsetup::reset_device(cfg_va);
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

fn map_queue_notify_va(
    mappings: &mut TransportMappings,
    notify_cap: Option<&virtio::VirtioPciCap>,
    bars: &[pci::Bar; 6],
    notify_off: u16,
) -> u64 {
    let Some(notify_cap) = notify_cap else { return 0 };
    notify_va_owned(mappings, notify_cap, bars, notify_off)
}

fn kick_queue_notify(notify_va: u64, queue_index: u16) -> bool {
    if notify_va == 0 {
        return false;
    }
    // SAFETY: notify_va is a Device-attr virtio notify location decoded from
    // the transport NOTIFY cap. Modern virtio-pci notify stores are u16 queue
    // indexes at the per-queue notify address.
    unsafe { core::ptr::write_volatile(notify_va as *mut u16, queue_index); }
    true
}

#[derive(Clone, Copy, Default)]
struct NetRxBootBuffer {
    buf_pa: u64,
    buf_len: u16,
    avail_idx_posted: u16,
}

fn post_net_rx_boot_buffer(hhdm: u64, q0_desc_pa: u64, q0_driver_pa: u64) -> NetRxBootBuffer {
    const RX_BUF_LEN: u16 = 2048;
    if hhdm == 0 || q0_desc_pa == 0 || q0_driver_pa == 0 {
        return NetRxBootBuffer::default();
    }
    let Some(rx_pa) = pmm::setup::alloc_raw_frame() else {
        return NetRxBootBuffer::default();
    };

    // Descriptor[0]: addr=rx_pa, len=2048, flags=WRITE, next=0.
    let desc0 = (hhdm.wrapping_add(q0_desc_pa)) as *mut u8;
    // SAFETY: HHDM maps the freshly allocated RX frame and queue-0 descriptor
    // table. The transport owns descriptor 0 until the child driver takes the
    // resource handoff.
    unsafe {
        core::ptr::write_volatile(desc0 as *mut u64, rx_pa);
        core::ptr::write_volatile((desc0.add(8)) as *mut u32, RX_BUF_LEN as u32);
        core::ptr::write_volatile((desc0.add(12)) as *mut u16, virtio::VRING_DESC_F_WRITE);
        core::ptr::write_volatile((desc0.add(14)) as *mut u16, 0u16);
    }

    let avail = (hhdm.wrapping_add(q0_driver_pa)) as *mut u16;
    // SAFETY: HHDM maps the queue-0 avail ring frame. ring[0] is u16 offset 2
    // and idx is u16 offset 1.
    unsafe { core::ptr::write_volatile(avail.add(2), 0u16); }
    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
    // SAFETY: same avail ring; idx publishes descriptor 0 after the release
    // fence made descriptor and ring writes observable.
    unsafe { core::ptr::write_volatile(avail.add(1), 1u16); }
    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);

    NetRxBootBuffer {
        buf_pa: rx_pa,
        buf_len: RX_BUF_LEN,
        avail_idx_posted: 1,
    }
}

fn alloc_net_tx_boot_buffer(
    hhdm: u64,
    q1_desc_pa: u64,
    q1_driver_pa: u64,
    q1_device_pa: u64,
    q1_notify_va: u64,
) -> u64 {
    if hhdm == 0
        || q1_desc_pa == 0
        || q1_driver_pa == 0
        || q1_device_pa == 0
        || q1_notify_va == 0
    {
        return 0;
    }
    pmm::setup::alloc_raw_frame().unwrap_or(0)
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
struct VirtioProbeState {
    bdf_word: u32,
    mappings: TransportMappings,
    cfg_va: u64,
    device_cfg_va: u64,
    msix: Option<MsixBinding>,
}

#[derive(Default)]
struct PlannedNotifyMappings {
    q2: u64,
    q3: u64,
}

impl VirtioProbeState {
    fn new(bdf: pci::Bdf, mappings: TransportMappings, cfg_va: u64, device_cfg_va: u64) -> Self {
        Self {
            bdf_word: bdf_word(bdf),
            mappings,
            cfg_va,
            device_cfg_va,
            msix: None,
        }
    }

    fn bind_msix0(
        &mut self,
        d: &pci::PciDevice,
        caps: &pci::heapless_caps::CapVec,
        bars: &[pci::Bar; 6],
        handler: Option<fn()>,
    ) -> bool {
        let Some(handler) = handler else {
            return false;
        };
        self.msix = bind_virtio_msix0(d, caps, bars, &mut self.mappings, handler);
        self.msix.is_some()
    }

    fn map_notify(
        &mut self,
        notify_cap: Option<&virtio::VirtioPciCap>,
        bars: &[pci::Bar; 6],
        notify_off: u16,
    ) -> u64 {
        map_queue_notify_va(&mut self.mappings, notify_cap, bars, notify_off)
    }

    fn kick_queue(
        &mut self,
        notify_cap: Option<&virtio::VirtioPciCap>,
        bars: &[pci::Bar; 6],
        notify_off: u16,
        queue_index: u16,
    ) -> u64 {
        let notify_va = self.map_notify(notify_cap, bars, notify_off);
        if kick_queue_notify(notify_va, queue_index) {
            notify_va
        } else {
            0
        }
    }

    fn map_planned_extra_notifies(
        &mut self,
        queue_plans: &[Option<QueuePlan>; 3],
        programmed_queues: Option<&ProgrammedQueues>,
        notify_cap: Option<&virtio::VirtioPciCap>,
        bars: &[pci::Bar; 6],
    ) -> PlannedNotifyMappings {
        let mut mappings = PlannedNotifyMappings::default();
        let Some(programmed) = programmed_queues else {
            return mappings;
        };

        for queue in queue_plans {
            let Some(queue) = queue else { continue };
            if !queue.map_notify {
                continue;
            }
            let Some(ring) = programmed.extra_queue(queue.index) else {
                continue;
            };
            let notify_va = self.map_notify(notify_cap, bars, ring.notify_off);
            match queue.index {
                2 => mappings.q2 = notify_va,
                3 => mappings.q3 = notify_va,
                _ => {}
            }
        }

        mappings
    }

    fn map_q1_notify(
        &mut self,
        policy: Q1NotifyPolicy,
        q1_ring: Option<QueueRing>,
        final_status: u8,
        notify_cap: Option<&virtio::VirtioPciCap>,
        bars: &[pci::Bar; 6],
    ) -> u64 {
        if (final_status & virtio::VIRTIO_STATUS_DRIVER_OK) == 0 {
            return 0;
        }
        match policy {
            Q1NotifyPolicy::None => 0,
            Q1NotifyPolicy::NetBootTx | Q1NotifyPolicy::PersistentTx => {
                let Some(ring) = q1_ring else { return 0 };
                self.map_notify(notify_cap, bars, ring.notify_off)
            }
        }
    }

    fn finish(self, result: VirtioProbeResult) -> VirtioProbe {
        VirtioProbe {
            bdf_word: self.bdf_word,
            mappings: self.mappings,
            msix: self.msix,
            cfg_va: self.cfg_va,
            device_cfg_va: self.device_cfg_va,
            cmd_orig: result.cmd_orig,
            cmd_new: result.cmd_new,
            dev_features: result.dev_features,
            drv_features: result.drv_features,
            post_status: result.post_status,
            features_ok: result.features_ok,
            msix_cfg: result.msix_cfg,
            num_queues: result.num_queues,
            queues: result.queues,
            queues_len: result.queues_len,
            q0_desc_pa: result.q0_desc_pa,
            q0_driver_pa: result.q0_driver_pa,
            q0_device_pa: result.q0_device_pa,
            final_status: result.final_status,
            q0_notify_off: result.q0_notify_off,
            q0_notify_va: result.q0_notify_va,
            post_notify_status: result.post_notify_status,
            avail_idx_posted: result.avail_idx_posted,
            used_idx_observed: result.used_idx_observed,
            isr_status: result.isr_status,
            q1_notify_va: result.q1_notify_va,
            q1_notify_off: result.q1_notify_off,
            q0_size: result.q0_size,
            q1_size: result.q1_size,
            q1_desc_pa: result.q1_desc_pa,
            q1_driver_pa: result.q1_driver_pa,
            q1_device_pa: result.q1_device_pa,
            rx0_buf_pa: result.rx0_buf_pa,
            rx0_buf_len: result.rx0_buf_len,
            tx0_buf_pa: result.tx0_buf_pa,
            snd_q2_desc_pa: result.snd_q2_desc_pa,
            snd_q2_driver_pa: result.snd_q2_driver_pa,
            snd_q2_device_pa: result.snd_q2_device_pa,
            snd_q2_notify_va: result.snd_q2_notify_va,
            snd_q2_notify_off: result.snd_q2_notify_off,
            snd_q2_size: result.snd_q2_size,
            snd_q3_desc_pa: result.snd_q3_desc_pa,
            snd_q3_driver_pa: result.snd_q3_driver_pa,
            snd_q3_device_pa: result.snd_q3_device_pa,
            snd_q3_notify_va: result.snd_q3_notify_va,
            snd_q3_notify_off: result.snd_q3_notify_off,
            snd_q3_size: result.snd_q3_size,
        }
    }
}

struct VirtioProbeResult {
    cmd_orig: u16,
    cmd_new: u16,
    dev_features: u64,
    drv_features: u64,
    post_status: u32,
    features_ok: bool,
    msix_cfg: u16,
    num_queues: u16,
    queues: [(u16, u16); 8],
    queues_len: usize,
    q0_desc_pa: u64,
    q0_driver_pa: u64,
    q0_device_pa: u64,
    final_status: u8,
    q0_notify_off: u16,
    q0_notify_va: u64,
    post_notify_status: u8,
    avail_idx_posted: u16,
    used_idx_observed: u16,
    isr_status: u8,
    q1_notify_va: u64,
    q1_notify_off: u16,
    q0_size: u16,
    q1_size: u16,
    q1_desc_pa: u64,
    q1_driver_pa: u64,
    q1_device_pa: u64,
    rx0_buf_pa: u64,
    rx0_buf_len: u16,
    tx0_buf_pa: u64,
    snd_q2_desc_pa: u64,
    snd_q2_driver_pa: u64,
    snd_q2_device_pa: u64,
    snd_q2_notify_va: u64,
    snd_q2_notify_off: u16,
    snd_q2_size: u16,
    snd_q3_desc_pa: u64,
    snd_q3_driver_pa: u64,
    snd_q3_device_pa: u64,
    snd_q3_notify_va: u64,
    snd_q3_notify_off: u16,
    snd_q3_size: u16,
}

pub(super) struct VirtioProbe {
    pub(super) bdf_word: u32,
    mappings: TransportMappings,
    msix: Option<MsixBinding>,
    pub(super) cmd_orig: u16,
    pub(super) cmd_new:  u16,
    pub(super) cfg_va:   u64,
    pub(super) device_cfg_va: u64,
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
    pub(super) q1_notify_va: u64,
    pub(super) q1_notify_off: u16,
    pub(super) q0_size: u16,
    pub(super) q1_size: u16,
    pub(super) q1_desc_pa:   u64,
    pub(super) q1_driver_pa: u64,
    pub(super) q1_device_pa: u64,
    pub(super) rx0_buf_pa:  u64,
    pub(super) rx0_buf_len: u16,
    pub(super) tx0_buf_pa: u64,
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
            .with_device_cfg_va(self.device_cfg_va)
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
fn virtio_init_arch(d: &pci::PciDevice, profile: VirtioProbeProfile) -> Option<VirtioProbe> {
    if !virtio::is_modern(d.vendor_id, d.device_id) { return None; }
    let bdf = d.bdf;
    let mut mappings = TransportMappings::default();
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
    let common = match vcaps.find(virtio::VIRTIO_PCI_CAP_COMMON_CFG) {
        Some(common) => common,
        None => return abandon_probe_transport(bdf, &mut mappings),
    };
    let bar_pa = match bars[common.bar as usize] {
        pci::Bar::Mem32 { base, .. } => base as u64,
        pci::Bar::Mem64 { base, .. } => base,
        _ => return abandon_probe_transport(bdf, &mut mappings),
    };
    let common_pa = bar_pa + common.offset as u64;
    let page_pa = common_pa & !0xFFF;
    let page_off = (common_pa - page_pa) as u64;
    // SAFETY: BAR PA decoded from device BAR reg; bump VA is exclusive.
    let base_va = mappings.map_page(page_pa);
    let cfg_va = base_va + page_off;
    let device_cfg_va = match vcaps.find(virtio::VIRTIO_PCI_CAP_DEVICE_CFG) {
        Some(devcfg) => {
            let dbar_pa = match bars[devcfg.bar as usize] {
                pci::Bar::Mem32 { base, .. } => base as u64,
                pci::Bar::Mem64 { base, .. } => base,
                _ => 0,
            };
            if dbar_pa == 0 {
                0
            } else {
                let d_pa = dbar_pa + devcfg.offset as u64;
                let d_page_pa = d_pa & !0xFFF;
                mappings.map_page(d_page_pa) + (d_pa - d_page_pa)
            }
        }
        None => 0,
    };
    let mut state = VirtioProbeState::new(bdf, mappings, cfg_va, device_cfg_va);

    let negotiated = super::virtio_qsetup::negotiate_features(state.cfg_va, profile.drv_features);
    let dev_features = negotiated.dev_features;
    let drv_features = negotiated.drv_features;
    let post_status = negotiated.post_status;
    let features_ok = negotiated.features_ok;
    let msix_cfg = negotiated.msix_cfg;
    let num_queues = negotiated.num_queues;
    let (queues, queues_len) = super::virtio_qsetup::scan_queue_sizes(state.cfg_va, num_queues);

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
    let q0_size = if queues_len > 0 { queues[0].1 } else { 0 };
    let notify_cap = vcaps.find(virtio::VIRTIO_PCI_CAP_NOTIFY_CFG);
    let msix_bound = features_ok && state.bind_msix0(d, &caps, &bars, profile.msix0_handler);
    let q0_msix_vec = if msix_bound { 0 } else { 0xFFFF };
    let programmed_queues = if features_ok {
        super::virtio_qsetup::program_queue_set(
            state.cfg_va,
            hhdm,
            q0_msix_vec,
            &profile.extra_queues,
        )
    } else {
        None
    };
    let extra_notify_mappings = state.map_planned_extra_notifies(
        &profile.extra_queues,
        programmed_queues.as_ref(),
        notify_cap.as_ref(),
        &bars,
    );
    let snd_q2_notify_va_local = extra_notify_mappings.q2;
    let snd_q3_notify_va_local = extra_notify_mappings.q3;
    let final_status = if programmed_queues.is_some() {
        super::virtio_qsetup::set_driver_ok(state.cfg_va)
    } else {
        post_status as u8
    };
    let q0_ring = programmed_queues.as_ref().map(|p| p.q0);
    let q1_ring = programmed_queues.as_ref().and_then(|p| p.extra_queue(1));
    let q2_ring = programmed_queues.as_ref().and_then(|p| p.extra_queue(2));
    let q3_ring = programmed_queues.as_ref().and_then(|p| p.extra_queue(3));
    let q0_desc_pa = q0_ring.map(|q| q.desc_pa).unwrap_or(0);
    let q0_driver_pa = q0_ring.map(|q| q.driver_pa).unwrap_or(0);
    let q0_device_pa = q0_ring.map(|q| q.device_pa).unwrap_or(0);
    let q0_notify_off = q0_ring.map(|q| q.notify_off).unwrap_or(0);
    let q1_desc_pa = q1_ring.map(|q| q.desc_pa).unwrap_or(0);
    let q1_driver_pa = q1_ring.map(|q| q.driver_pa).unwrap_or(0);
    let q1_device_pa = q1_ring.map(|q| q.device_pa).unwrap_or(0);
    let q1_notify_off_local = q1_ring.map(|q| q.notify_off).unwrap_or(0);
    let snd_q2_desc_pa_local = q2_ring.map(|q| q.desc_pa).unwrap_or(0);
    let snd_q2_driver_pa_local = q2_ring.map(|q| q.driver_pa).unwrap_or(0);
    let snd_q2_device_pa_local = q2_ring.map(|q| q.device_pa).unwrap_or(0);
    let snd_q2_notify_off_local = q2_ring.map(|q| q.notify_off).unwrap_or(0);
    let snd_q2_size_local = q2_ring.map(|q| q.size).unwrap_or(0);
    let snd_q3_desc_pa_local = q3_ring.map(|q| q.desc_pa).unwrap_or(0);
    let snd_q3_driver_pa_local = q3_ring.map(|q| q.driver_pa).unwrap_or(0);
    let snd_q3_device_pa_local = q3_ring.map(|q| q.device_pa).unwrap_or(0);
    let snd_q3_notify_off_local = q3_ring.map(|q| q.notify_off).unwrap_or(0);
    let snd_q3_size_local = q3_ring.map(|q| q.size).unwrap_or(0);
    let net_rx_boot = if profile.needs_net_boot_buffers
        && (final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0
    {
        post_net_rx_boot_buffer(hhdm, q0_desc_pa, q0_driver_pa)
    } else {
        NetRxBootBuffer::default()
    };
    let avail_idx_posted = net_rx_boot.avail_idx_posted;
    let rx0_buf_pa_local = net_rx_boot.buf_pa;
    let rx0_buf_len_local = net_rx_boot.buf_len;

    let (q0_notify_va, post_notify_status) = if final_status & virtio::VIRTIO_STATUS_FAILED == 0
        && (final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0
    {
        let kick_va = state.kick_queue(notify_cap.as_ref(), &bars, q0_notify_off, 0);
        if kick_va != 0 {
            // Brief observation window for any device-driven RX completion
            // (QEMU user-net delivers nothing without packets, so used.idx
            // will normally stay 0).
            for _ in 0..1_000_000 { core::hint::spin_loop(); }
            let st = super::virtio_qsetup::read_status(state.cfg_va);
            (kick_va, st)
        } else {
            (0u64, final_status)
        }
    } else {
        (0u64, final_status)
    };

    let q1_notify_va_local = state.map_q1_notify(
        profile.q1_notify_policy,
        q1_ring,
        final_status,
        notify_cap.as_ref(),
        &bars,
    );
    let tx0_buf_pa_local = if matches!(profile.q1_notify_policy, Q1NotifyPolicy::NetBootTx)
        && (final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0
    {
        alloc_net_tx_boot_buffer(
            hhdm,
            q1_desc_pa,
            q1_driver_pa,
            q1_device_pa,
            q1_notify_va_local,
        )
    } else {
        0
    };

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

    Some(state.finish(VirtioProbeResult {
        cmd_orig: (cmd_orig & 0xFFFF) as u16,
        cmd_new:  (cmd_new  & 0xFFFF) as u16,
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
        q1_notify_va: q1_notify_va_local,
        q1_notify_off: q1_notify_off_local,
        q0_size,
        q1_size: if queues_len > 1 { queues[1].1 } else { 0 },
        q1_desc_pa,
        q1_driver_pa,
        q1_device_pa,
        rx0_buf_pa:  rx0_buf_pa_local,
        rx0_buf_len: rx0_buf_len_local,
        tx0_buf_pa: tx0_buf_pa_local,
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
    }))
}
