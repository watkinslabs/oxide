//! Virtio child model drivers.
//!
//! These are still wired to the boot virtio-pci transport, but keeping child
//! driver binding out of the PCI transport module is the next step toward a
//! real virtio bus/core split.

use super::virtio_drv::{
    bdf_word, pci_device_from_virtio_child, pci_parent_bdf, publish_transport_mmio,
    unpublish_transport_mmio, virtio_init_arch,
};
use alloc::sync::Arc;

struct VirtioGpuDrv;
impl drv::Driver for VirtioGpuDrv {
    fn bus(&self) -> &'static str { "virtio" }

    fn name(&self) -> &'static str { "virtio-gpu" }

    fn matches(&self, dev: &drv::Device) -> bool {
        dev.bus == "virtio" && dev.vendor_id == 0x1AF4 && dev.device_id == 16
    }

    fn probe(&self, dev: &Arc<drv::Device>) -> drv::KResult<()> {
        let d = pci_device_from_virtio_child(dev).ok_or(drv::Error::ProbeFailed)?;
        let profile =
            virtio::VirtioTransportProfile::q0(drv_virtio_gpu::wanted_features(), None);
        let mut p = virtio_init_arch(&d, profile).ok_or(drv::Error::ProbeFailed)?;
        super::virtio_trace::trace_probe(d.bdf, &p);
        let Some(resources) = p.child_resources(profile.child_requirements) else {
            p.release_failed_child(profile.child_requirements);
            return Err(drv::Error::ProbeFailed);
        };
        let ok = drv_virtio_gpu::post_init::get_display_info(
            d.bdf.bus,
            d.bdf.device,
            d.bdf.function,
            p.drv_features,
            resources,
        );
        if !ok {
            p.release_failed_child(profile.child_requirements);
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
        let profile = virtio::VirtioTransportProfile::q0_device_cfg(
            drv_virtio_input::wanted_features(),
            Some(drv_virtio_input::drain::raise_drain),
        );
        let mut p = virtio_init_arch(&d, profile).ok_or(drv::Error::ProbeFailed)?;
        super::virtio_trace::trace_probe(d.bdf, &p);
        let bdf_word = bdf_word(d.bdf);
        let Some(resources) = p.child_resources(profile.child_requirements) else {
            p.release_failed_child(profile.child_requirements);
            return Err(drv::Error::ProbeFailed);
        };
        let evdev_id = match drv_virtio_input::install_device(bdf_word, resources) {
            Some(id) => id,
            None => {
                p.release_failed_child(profile.child_requirements);
                return Err(drv::Error::ProbeFailed);
            }
        };
        let installed = drv_virtio_input::drain::install_eventq(evdev_id, resources);
        if installed.is_err() {
            let _ = drv_virtio_input::remove_device(bdf_word);
            p.release_failed_child(profile.child_requirements);
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
        let d = pci_device_from_virtio_child(dev).ok_or(drv::Error::ProbeFailed)?;
        let device_key = bdf_word(d.bdf);
        let profile = virtio::VirtioTransportProfile::net(
            drv_virtio_net::modern::wanted_features(),
            Some(drv_virtio_net::modern::raise_rx),
        );
        let mut p = virtio_init_arch(&d, profile).ok_or(drv::Error::ProbeFailed)?;
        super::virtio_trace::trace_probe(d.bdf, &p);
        let Some(resources) = p.child_resources(profile.child_requirements) else {
            p.release_failed_child(profile.child_requirements);
            return Err(drv::Error::ProbeFailed);
        };
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
            p.release_failed_child(profile.child_requirements);
            return Err(drv::Error::ProbeFailed);
        }
        publish_transport_mmio(&mut p);
        Ok(())
    }

    fn remove(&self, dev: &drv::Device) {
        if let Some(bdf) = pci_parent_bdf(dev) {
            let device_key = bdf_word(bdf);
            if drv_virtio_net::modern::is_modern_present_for(device_key) {
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
        let profile = virtio::VirtioTransportProfile::q0_device_cfg(
            drv_virtio_blk::modern::wanted_features(),
            Some(drv_virtio_blk::modern::wake_completions),
        );
        let mut p = virtio_init_arch(&d, profile).ok_or(drv::Error::ProbeFailed)?;
        super::virtio_trace::trace_probe(d.bdf, &p);
        let Some(resources) = p.child_resources(profile.child_requirements) else {
            p.release_failed_child(profile.child_requirements);
            return Err(drv::Error::ProbeFailed);
        };
        let device_key = bdf_word(d.bdf);
        let idx = drv_virtio_blk::modern::init_blk(drv_virtio_blk::modern::BlkInit {
            device_key,
            resources,
            drv_features: p.drv_features,
        });
        if idx == 0 {
            p.release_failed_child(profile.child_requirements);
            return Err(drv::Error::ProbeFailed);
        }
        publish_transport_mmio(&mut p);
        Ok(())
    }

    fn remove(&self, dev: &drv::Device) {
        if let Some(bdf) = pci_parent_bdf(dev) {
            let device_key = bdf_word(bdf);
            let _ = drv_virtio_blk::modern::remove_blk(device_key);
            unpublish_transport_mmio(device_key);
        }
    }

    fn shutdown(&self, dev: &drv::Device) {
        if let Some(bdf) = pci_parent_bdf(dev) {
            let _ = drv_virtio_blk::modern::shutdown_blk(bdf_word(bdf));
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
        let profile =
            virtio::VirtioTransportProfile::q0(drv_virtio_rng::wanted_features(), None);
        let mut p = virtio_init_arch(&d, profile).ok_or(drv::Error::ProbeFailed)?;
        super::virtio_trace::trace_probe(d.bdf, &p);
        let Some(resources) = p.child_resources(profile.child_requirements) else {
            p.release_failed_child(profile.child_requirements);
            return Err(drv::Error::ProbeFailed);
        };
        let bdf_word = bdf_word(d.bdf);
        match drv_virtio_rng::install(bdf_word, resources) {
            Some(()) => {}
            None => {
                p.release_failed_child(profile.child_requirements);
                return Err(drv::Error::ProbeFailed);
            }
        }

        let mut seed = [0u8; 32];
        let n = drv_virtio_rng::fill_from_bdf(bdf_word, &mut seed);
        if n == 0 {
            let _ = drv_virtio_rng::uninstall(bdf_word);
            p.release_failed_child(profile.child_requirements);
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
            let _ = drv_virtio_rng::uninstall(bdf_word);
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
        let d = pci_device_from_virtio_child(dev).ok_or(drv::Error::ProbeFailed)?;
        let device_key = bdf_word(d.bdf);
        let profile = virtio::VirtioTransportProfile::vsock(
            drv_virtio_vsock::wanted_features(),
            Some(drv_virtio_vsock::raise_rx),
        );
        let mut p = virtio_init_arch(&d, profile).ok_or(drv::Error::ProbeFailed)?;
        super::virtio_trace::trace_probe(d.bdf, &p);
        let Some(resources) = p.child_resources(profile.child_requirements) else {
            p.release_failed_child(profile.child_requirements);
            return Err(drv::Error::ProbeFailed);
        };
        if !drv_virtio_vsock::install(device_key, resources) {
            p.release_failed_child(profile.child_requirements);
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
        let d = pci_device_from_virtio_child(dev).ok_or(drv::Error::ProbeFailed)?;
        let device_key = bdf_word(d.bdf);
        let profile = virtio::VirtioTransportProfile::snd(
            drv_virtio_snd::wanted_features(),
            None,
            Some(drv_virtio_snd::raise_event),
        );
        let mut p = virtio_init_arch(&d, profile).ok_or(drv::Error::ProbeFailed)?;
        super::virtio_trace::trace_probe(d.bdf, &p);
        let Some(resources) = p.child_resources(profile.child_requirements) else {
            p.release_failed_child(profile.child_requirements);
            return Err(drv::Error::ProbeFailed);
        };
        let sp = drv_virtio_snd::install(drv_virtio_snd::SndInstall {
            device_key,
            resources,
        }).ok_or_else(|| {
            p.release_failed_child(profile.child_requirements);
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

/// Register virtio child drivers whose bring-up is owned by `Driver::probe`.
/// # C: O(N_drivers)
pub(super) fn register_model_drivers() {
    drv::register_driver(&VIRTIO_NET_DRV);
    drv::register_driver(&VIRTIO_BLK_DRV);
    drv::register_driver(&VIRTIO_RNG_DRV);
    drv::register_driver(&VIRTIO_VSOCK_DRV);
    drv::register_driver(&VIRTIO_SND_DRV);
    drv::register_driver(&VIRTIO_INPUT_DRV);
    drv::register_driver(&VIRTIO_GPU_DRV);
}
