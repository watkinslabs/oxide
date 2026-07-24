//! Virtio child model driver callbacks for the boot virtio-pci bus.

use super::virtio_bus::{parent_key, unpublish_transport, VirtioChildSession};
use virtio::VirtioChildTransportSession;

struct PciVirtioChildBus;
impl virtio::VirtioChildBus for PciVirtioChildBus {
    type Session = VirtioChildSession;

    fn begin_session(
        dev: &drv::Device,
        profile: virtio::VirtioTransportProfile,
    ) -> drv::KResult<Self::Session> {
        VirtioChildSession::begin(dev, profile)
    }

    fn parent_key(dev: &drv::Device) -> Option<virtio::VirtioChildDeviceKey> {
        parent_key(dev)
    }

    fn unpublish_transport(device_key: virtio::VirtioChildDeviceKey) {
        unpublish_transport(device_key);
    }
}

struct VirtioGpuOps;
impl virtio::VirtioChildDriverOps<VirtioChildSession> for VirtioGpuOps {
    const DRIVER_ID: virtio::VirtioChildDriverId = drv_virtio_gpu::DRIVER_ID;

    fn profile() -> virtio::VirtioTransportProfile {
        drv_virtio_gpu::transport_profile()
    }

    fn probe_child(session: &mut VirtioChildSession) -> drv::KResult<()> {
        let pci_bdf = session.pci_bdf();
        let device_key = session.device_key();
        let Some(resources) = session.child_resources() else {
            return Err(drv::Error::ProbeFailed);
        };
        let ok = drv_virtio_gpu::post_init::get_display_info(
            device_key,
            pci_bdf.bus,
            pci_bdf.device,
            pci_bdf.function,
            "virtio",
            alloc::string::String::from(session.device_addr()),
            session.drv_features(),
            resources,
        );
        if !ok {
            return Err(drv::Error::ProbeFailed);
        }
        debug_boot! {
            klog::write_raw(b"[INFO]  virtio-gpu installed feat=");
            klog::write_hex_u64(session.drv_features());
            klog::write_raw(b"\n");
        }
        Ok(())
    }

    fn remove_child(device_key: virtio::VirtioChildDeviceKey) {
        let result = drv_virtio_gpu::hot_remove(device_key);
        let removed = result.device_removed;
        let scanout = result.scanout_removed;
        debug_boot! {
            klog::write_raw(b"[INFO]  virtio-gpu remove key=");
            klog::write_hex_u64(device_key.raw() as u64);
            klog::write_raw(b" device=");
            klog::write_dec_u64(removed as u64);
            klog::write_raw(b" scanout=");
            klog::write_dec_u64(scanout as u64);
            klog::write_raw(b"\n");
        }
        let _ = (removed, scanout);
    }

    fn shutdown_child(device_key: virtio::VirtioChildDeviceKey) {
        let _ = drv_virtio_gpu::shutdown(device_key);
    }
}
static VIRTIO_GPU_DRV: virtio::VirtioChildDriver<PciVirtioChildBus, VirtioGpuOps> =
    virtio::VirtioChildDriver::new();

struct VirtioInputOps;
impl virtio::VirtioChildDriverOps<VirtioChildSession> for VirtioInputOps {
    const DRIVER_ID: virtio::VirtioChildDriverId = drv_virtio_input::DRIVER_ID;

    fn profile() -> virtio::VirtioTransportProfile {
        drv_virtio_input::transport_profile()
    }

    fn probe_child(session: &mut VirtioChildSession) -> drv::KResult<()> {
        let device_key = session.device_key();
        let Some(resources) = session.child_resources() else {
            return Err(drv::Error::ProbeFailed);
        };
        let evdev_id = match drv_virtio_input::install_device_with_parent(
            device_key,
            resources,
            Some(("virtio", alloc::string::String::from(session.device_addr()))),
        ) {
            Some(id) => id,
            None => {
                return Err(drv::Error::ProbeFailed);
            }
        };
        let installed = drv_virtio_input::drain::install_eventq(device_key, evdev_id, resources);
        if installed.is_err() {
            let _ = drv_virtio_input::remove_device_with_node(device_key);
            return Err(drv::Error::ProbeFailed);
        }
        debug_boot! {
            klog::write_raw(b"[INFO]  virtio-input installed evdev_id=");
            klog::write_dec_u64(evdev_id as u64);
            klog::write_raw(if drv_virtio_input::is_pointer(evdev_id) { b" pointer\n" } else { b" keyboard\n" });
        }
        Ok(())
    }

    fn remove_child(device_key: virtio::VirtioChildDeviceKey) {
        let _ = drv_virtio_input::drain::uninstall_eventq(device_key);
        let _ = drv_virtio_input::remove_device_with_node(device_key);
    }

    fn shutdown_child(device_key: virtio::VirtioChildDeviceKey) {
        let _ = drv_virtio_input::drain::shutdown_eventq(device_key);
    }
}
static VIRTIO_INPUT_DRV: virtio::VirtioChildDriver<PciVirtioChildBus, VirtioInputOps> =
    virtio::VirtioChildDriver::new();

struct VirtioNetOps;
impl virtio::VirtioChildDriverOps<VirtioChildSession> for VirtioNetOps {
    const DRIVER_ID: virtio::VirtioChildDriverId = drv_virtio_net::modern::DRIVER_ID;

    fn profile() -> virtio::VirtioTransportProfile {
        drv_virtio_net::modern::transport_profile()
    }

    fn probe_child(session: &mut VirtioChildSession) -> drv::KResult<()> {
        let device_key = session.device_key();
        let payloads = session.net_boot_payloads();
        let Some(resources) = session.child_resources() else {
            return Err(drv::Error::ProbeFailed);
        };
        let rx_bufs = payloads.rx_bufs[..payloads.rx_bufs_len.min(virtio::VIRTIO_NET_RX_BOOT_POOL)]
            .iter()
            .copied()
            .collect();
        let ok = drv_virtio_net::modern::init_modern_with_rx_pool(
            device_key,
            resources,
            rx_bufs,
            payloads.tx_buf_pa,
        );
        #[cfg(feature = "debug-boot")]
        {
            klog::write_raw(b"[INFO]  virtio-net probe_child ok=");
            klog::write_dec_u64(ok as u64);
            klog::write_raw(b" rx_bufs=");
            klog::write_dec_u64(payloads.rx_bufs_len as u64);
            klog::write_raw(b" tx_buf_pa=");
            klog::write_hex_u64(payloads.tx_buf_pa);
            klog::write_raw(b"\n");
        }
        if !ok {
            return Err(drv::Error::ProbeFailed);
        }
        Ok(())
    }

    fn remove_child(device_key: virtio::VirtioChildDeviceKey) {
        let _ = drv_virtio_net::modern::uninstall_modern(device_key);
    }

    fn shutdown_child(device_key: virtio::VirtioChildDeviceKey) {
        let _ = drv_virtio_net::modern::shutdown_modern(device_key);
    }
}
static VIRTIO_NET_DRV: virtio::VirtioChildDriver<PciVirtioChildBus, VirtioNetOps> =
    virtio::VirtioChildDriver::new();

struct VirtioBlkOps;
impl virtio::VirtioChildDriverOps<VirtioChildSession> for VirtioBlkOps {
    const DRIVER_ID: virtio::VirtioChildDriverId = drv_virtio_blk::modern::DRIVER_ID;

    fn profile() -> virtio::VirtioTransportProfile {
        drv_virtio_blk::modern::transport_profile()
    }

    fn probe_child(session: &mut VirtioChildSession) -> drv::KResult<()> {
        let Some(resources) = session.child_resources() else {
            return Err(drv::Error::ProbeFailed);
        };
        let device_key = session.device_key();
        let idx = drv_virtio_blk::modern::init_blk(drv_virtio_blk::modern::BlkInit {
            device_key,
            resources,
            drv_features: session.drv_features(),
        });
        if idx == 0 {
            return Err(drv::Error::ProbeFailed);
        }
        Ok(())
    }

    fn remove_child(device_key: virtio::VirtioChildDeviceKey) {
        let _ = drv_virtio_blk::modern::remove_blk(device_key);
    }

    fn shutdown_child(device_key: virtio::VirtioChildDeviceKey) {
        let _ = drv_virtio_blk::modern::shutdown_blk(device_key);
    }
}
static VIRTIO_BLK_DRV: virtio::VirtioChildDriver<PciVirtioChildBus, VirtioBlkOps> =
    virtio::VirtioChildDriver::new();

struct VirtioRngOps;
impl virtio::VirtioChildDriverOps<VirtioChildSession> for VirtioRngOps {
    const DRIVER_ID: virtio::VirtioChildDriverId = drv_virtio_rng::DRIVER_ID;

    fn profile() -> virtio::VirtioTransportProfile {
        drv_virtio_rng::transport_profile()
    }

    fn probe_child(session: &mut VirtioChildSession) -> drv::KResult<()> {
        let Some(resources) = session.child_resources() else {
            return Err(drv::Error::ProbeFailed);
        };
        let device_key = session.device_key();
        let seeded = match drv_virtio_rng::install(device_key, resources) {
            Some(seeded) => seeded,
            None => {
                return Err(drv::Error::ProbeFailed);
            }
        };
        debug_boot! {
            klog::write_raw(b"[INFO]  virtio-rng installed seeded=");
            klog::write_dec_u64(seeded as u64);
            klog::write_raw(b" bytes\n");
        }
        Ok(())
    }

    fn remove_child(device_key: virtio::VirtioChildDeviceKey) {
        let _ = drv_virtio_rng::uninstall(device_key);
    }

    fn shutdown_child(device_key: virtio::VirtioChildDeviceKey) {
        let _ = drv_virtio_rng::shutdown(device_key);
    }
}
static VIRTIO_RNG_DRV: virtio::VirtioChildDriver<PciVirtioChildBus, VirtioRngOps> =
    virtio::VirtioChildDriver::new();

struct VirtioVsockOps;
impl virtio::VirtioChildDriverOps<VirtioChildSession> for VirtioVsockOps {
    const DRIVER_ID: virtio::VirtioChildDriverId = drv_virtio_vsock::DRIVER_ID;

    fn profile() -> virtio::VirtioTransportProfile {
        drv_virtio_vsock::transport_profile()
    }

    fn probe_child(session: &mut VirtioChildSession) -> drv::KResult<()> {
        let device_key = session.device_key();
        let Some(resources) = session.child_resources() else {
            return Err(drv::Error::ProbeFailed);
        };
        if !drv_virtio_vsock::install(device_key, resources, session.drv_features()) {
            return Err(drv::Error::ProbeFailed);
        }
        let cid = drv_virtio_vsock::guest_cid_for(device_key);
        debug_boot! {
            klog::write_raw(b"[INFO]  virtio-vsock installed cid=");
            klog::write_dec_u64(cid);
            klog::write_raw(b"\n");
        }
        let _ = cid;
        Ok(())
    }

    fn remove_child(device_key: virtio::VirtioChildDeviceKey) {
        let _ = drv_virtio_vsock::uninstall(device_key);
    }

    fn shutdown_child(device_key: virtio::VirtioChildDeviceKey) {
        let _ = drv_virtio_vsock::shutdown(device_key);
    }
}
static VIRTIO_VSOCK_DRV: virtio::VirtioChildDriver<PciVirtioChildBus, VirtioVsockOps> =
    virtio::VirtioChildDriver::new();

struct VirtioSndOps;
impl virtio::VirtioChildDriverOps<VirtioChildSession> for VirtioSndOps {
    const DRIVER_ID: virtio::VirtioChildDriverId = drv_virtio_snd::DRIVER_ID;

    fn profile() -> virtio::VirtioTransportProfile {
        drv_virtio_snd::transport_profile()
    }

    fn probe_child(session: &mut VirtioChildSession) -> drv::KResult<()> {
        let device_key = session.device_key();
        let Some(resources) = session.child_resources() else {
            return Err(drv::Error::ProbeFailed);
        };
        let sp = match drv_virtio_snd::install(drv_virtio_snd::SndInstall {
            device_key,
            resources,
        }) {
            Some(sp) => sp,
            None => return Err(drv::Error::ProbeFailed),
        };
        #[cfg(not(feature = "debug-boot"))]
        let _ = &sp;
        debug_boot! {
            klog::write_raw(b"[INFO]  virtio-snd: key=");
            klog::write_hex_u64(device_key.raw() as u64);
            klog::write_raw(b" card=C0 streams=");
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
        Ok(())
    }

    fn remove_child(device_key: virtio::VirtioChildDeviceKey) {
        let _ = drv_virtio_snd::uninstall(device_key);
    }

    fn shutdown_child(device_key: virtio::VirtioChildDeviceKey) {
        let _ = drv_virtio_snd::shutdown(device_key);
    }
}
static VIRTIO_SND_DRV: virtio::VirtioChildDriver<PciVirtioChildBus, VirtioSndOps> =
    virtio::VirtioChildDriver::new();

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
