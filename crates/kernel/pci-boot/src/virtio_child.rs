//! Virtio child model drivers.
//!
//! These are still wired to the boot virtio-pci transport, but keeping child
//! driver binding out of the PCI transport module is the next step toward a
//! real virtio bus/core split.

use super::virtio_bus::{parent_key, unpublish_transport, VirtioChildSession};
use alloc::sync::Arc;
use core::marker::PhantomData;
use virtio::VirtioChildTransportSession;

trait VirtioChildOps: Sync {
    const DRIVER_ID: virtio::VirtioChildDriverId;

    fn profile() -> virtio::VirtioTransportProfile;
    fn probe_child(session: &mut dyn virtio::VirtioChildTransportSession) -> drv::KResult<()>;
    fn remove_child(device_key: u32);
    fn shutdown_child(device_key: u32);
}

struct VirtioChildDriver<O> {
    _ops: PhantomData<O>,
}

impl<O> VirtioChildDriver<O> {
    const fn new() -> Self {
        Self { _ops: PhantomData }
    }
}

impl<O: VirtioChildOps> drv::Driver for VirtioChildDriver<O> {
    fn bus(&self) -> &'static str { virtio::VIRTIO_CHILD_BUS }

    fn name(&self) -> &'static str { O::DRIVER_ID.name }

    fn matches(&self, dev: &drv::Device) -> bool {
        O::DRIVER_ID.matches_device(&dev.bus, dev.vendor_id, dev.device_id)
    }

    fn probe(&self, dev: &Arc<drv::Device>) -> drv::KResult<()> {
        let mut session = VirtioChildSession::begin(dev, O::profile())?;
        match O::probe_child(&mut session) {
            Ok(()) => {
                session.publish();
                Ok(())
            }
            Err(e) => {
                session.release_failed_child();
                Err(e)
            }
        }
    }

    fn remove(&self, dev: &drv::Device) {
        if let Some(device_key) = parent_key(dev) {
            O::remove_child(device_key);
            unpublish_transport(device_key);
        }
    }

    fn shutdown(&self, dev: &drv::Device) {
        if let Some(device_key) = parent_key(dev) {
            O::shutdown_child(device_key);
        }
    }
}

struct VirtioGpuOps;
impl VirtioChildOps for VirtioGpuOps {
    const DRIVER_ID: virtio::VirtioChildDriverId = drv_virtio_gpu::DRIVER_ID;

    fn profile() -> virtio::VirtioTransportProfile {
        drv_virtio_gpu::transport_profile()
    }

    fn probe_child(session: &mut dyn virtio::VirtioChildTransportSession) -> drv::KResult<()> {
        let location = session.location();
        let Some(resources) = session.child_resources() else {
            return Err(drv::Error::ProbeFailed);
        };
        let ok = drv_virtio_gpu::post_init::get_display_info(
            location.bus,
            location.device,
            location.function,
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

    fn remove_child(device_key: u32) {
        if drv_virtio_gpu::uninstall(device_key).is_some() {
            let _ = drv_virtio_gpu::post_init::uninstall_scanout(device_key);
        }
    }

    fn shutdown_child(device_key: u32) {
        let _ = drv_virtio_gpu::shutdown(device_key);
    }
}
static VIRTIO_GPU_DRV: VirtioChildDriver<VirtioGpuOps> = VirtioChildDriver::new();

struct VirtioInputOps;
impl VirtioChildOps for VirtioInputOps {
    const DRIVER_ID: virtio::VirtioChildDriverId = drv_virtio_input::DRIVER_ID;

    fn profile() -> virtio::VirtioTransportProfile {
        drv_virtio_input::transport_profile()
    }

    fn probe_child(session: &mut dyn virtio::VirtioChildTransportSession) -> drv::KResult<()> {
        let bdf_word = session.device_key();
        let Some(resources) = session.child_resources() else {
            return Err(drv::Error::ProbeFailed);
        };
        let evdev_id = match drv_virtio_input::install_device(bdf_word, resources) {
            Some(id) => id,
            None => {
                return Err(drv::Error::ProbeFailed);
            }
        };
        let installed = drv_virtio_input::drain::install_eventq(evdev_id, resources);
        if installed.is_err() {
            let _ = drv_virtio_input::remove_device(bdf_word);
            return Err(drv::Error::ProbeFailed);
        }
        debug_boot! {
            klog::write_raw(b"[INFO]  virtio-input installed evdev_id=");
            klog::write_dec_u64(evdev_id as u64);
            klog::write_raw(if drv_virtio_input::is_pointer(evdev_id) { b" pointer\n" } else { b" keyboard\n" });
        }
        Ok(())
    }

    fn remove_child(device_key: u32) {
        if let Some(evdev_id) = drv_virtio_input::evdev_id_for_bdf(device_key) {
            let _ = drv_virtio_input::drain::uninstall_eventq(evdev_id);
            let _ = drv_virtio_input::remove_device(device_key);
        }
    }

    fn shutdown_child(device_key: u32) {
        if let Some(evdev_id) = drv_virtio_input::evdev_id_for_bdf(device_key) {
            let _ = drv_virtio_input::drain::shutdown_eventq(evdev_id);
        }
    }
}
static VIRTIO_INPUT_DRV: VirtioChildDriver<VirtioInputOps> = VirtioChildDriver::new();

struct VirtioNetOps;
impl VirtioChildOps for VirtioNetOps {
    const DRIVER_ID: virtio::VirtioChildDriverId = drv_virtio_net::modern::DRIVER_ID;

    fn profile() -> virtio::VirtioTransportProfile {
        drv_virtio_net::modern::transport_profile()
    }

    fn probe_child(session: &mut dyn virtio::VirtioChildTransportSession) -> drv::KResult<()> {
        let location = session.location();
        let device_key = session.device_key();
        let payloads = session.net_boot_payloads();
        let Some(resources) = session.child_resources() else {
            return Err(drv::Error::ProbeFailed);
        };
        if !drv_virtio_net::modern::init_modern(
            device_key,
            resources,
            location.bus,
            location.device,
            location.function,
            payloads.rx_buf_pa,
            payloads.rx_buf_len,
            payloads.tx_buf_pa,
        ) {
            return Err(drv::Error::ProbeFailed);
        }
        Ok(())
    }

    fn remove_child(device_key: u32) {
        if drv_virtio_net::modern::is_modern_present_for(device_key) {
            let _ = drv_virtio_net::modern::uninstall_modern(device_key);
        }
    }

    fn shutdown_child(device_key: u32) {
        let _ = drv_virtio_net::modern::shutdown_modern(device_key);
    }
}
static VIRTIO_NET_DRV: VirtioChildDriver<VirtioNetOps> = VirtioChildDriver::new();

struct VirtioBlkOps;
impl VirtioChildOps for VirtioBlkOps {
    const DRIVER_ID: virtio::VirtioChildDriverId = drv_virtio_blk::modern::DRIVER_ID;

    fn profile() -> virtio::VirtioTransportProfile {
        drv_virtio_blk::modern::transport_profile()
    }

    fn probe_child(session: &mut dyn virtio::VirtioChildTransportSession) -> drv::KResult<()> {
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

    fn remove_child(device_key: u32) {
        let _ = drv_virtio_blk::modern::remove_blk(device_key);
    }

    fn shutdown_child(device_key: u32) {
        let _ = drv_virtio_blk::modern::shutdown_blk(device_key);
    }
}
static VIRTIO_BLK_DRV: VirtioChildDriver<VirtioBlkOps> = VirtioChildDriver::new();

struct VirtioRngOps;
impl VirtioChildOps for VirtioRngOps {
    const DRIVER_ID: virtio::VirtioChildDriverId = drv_virtio_rng::DRIVER_ID;

    fn profile() -> virtio::VirtioTransportProfile {
        drv_virtio_rng::transport_profile()
    }

    fn probe_child(session: &mut dyn virtio::VirtioChildTransportSession) -> drv::KResult<()> {
        let Some(resources) = session.child_resources() else {
            return Err(drv::Error::ProbeFailed);
        };
        let bdf_word = session.device_key();
        match drv_virtio_rng::install(bdf_word, resources) {
            Some(()) => {}
            None => {
                return Err(drv::Error::ProbeFailed);
            }
        }

        let mut seed = [0u8; 32];
        let n = drv_virtio_rng::fill_from_bdf(bdf_word, &mut seed);
        if n == 0 {
            let _ = drv_virtio_rng::uninstall(bdf_word);
            return Err(drv::Error::ProbeFailed);
        }
        devfs::misc::add_entropy(&seed[..n]);
        debug_boot! {
            klog::write_raw(b"[INFO]  virtio-rng installed seeded=");
            klog::write_dec_u64(n as u64);
            klog::write_raw(b" bytes\n");
        }
        Ok(())
    }

    fn remove_child(device_key: u32) {
        let _ = drv_virtio_rng::uninstall(device_key);
    }

    fn shutdown_child(device_key: u32) {
        let _ = drv_virtio_rng::shutdown(device_key);
    }
}
static VIRTIO_RNG_DRV: VirtioChildDriver<VirtioRngOps> = VirtioChildDriver::new();

struct VirtioVsockOps;
impl VirtioChildOps for VirtioVsockOps {
    const DRIVER_ID: virtio::VirtioChildDriverId = drv_virtio_vsock::DRIVER_ID;

    fn profile() -> virtio::VirtioTransportProfile {
        drv_virtio_vsock::transport_profile()
    }

    fn probe_child(session: &mut dyn virtio::VirtioChildTransportSession) -> drv::KResult<()> {
        let device_key = session.device_key();
        let Some(resources) = session.child_resources() else {
            return Err(drv::Error::ProbeFailed);
        };
        if !drv_virtio_vsock::install(device_key, resources) {
            return Err(drv::Error::ProbeFailed);
        }
        debug_boot! {
            klog::write_raw(b"[INFO]  virtio-vsock installed cid=");
            klog::write_dec_u64(drv_virtio_vsock::guest_cid());
            klog::write_raw(b"\n");
        }
        Ok(())
    }

    fn remove_child(device_key: u32) {
        let _ = drv_virtio_vsock::uninstall(device_key);
    }

    fn shutdown_child(device_key: u32) {
        let _ = drv_virtio_vsock::shutdown(device_key);
    }
}
static VIRTIO_VSOCK_DRV: VirtioChildDriver<VirtioVsockOps> = VirtioChildDriver::new();

struct VirtioSndOps;
impl VirtioChildOps for VirtioSndOps {
    const DRIVER_ID: virtio::VirtioChildDriverId = drv_virtio_snd::DRIVER_ID;

    fn profile() -> virtio::VirtioTransportProfile {
        drv_virtio_snd::transport_profile()
    }

    fn probe_child(session: &mut dyn virtio::VirtioChildTransportSession) -> drv::KResult<()> {
        let location = session.location();
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
        let _ = &location;
        #[cfg(not(feature = "debug-boot"))]
        let _ = &sp;
        debug_boot! {
            klog::write_raw(b"[INFO]  virtio-snd: bdf=0:");
            klog::write_dec_u64(location.device as u64);
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
        Ok(())
    }

    fn remove_child(device_key: u32) {
        let _ = drv_virtio_snd::uninstall(device_key);
    }

    fn shutdown_child(device_key: u32) {
        let _ = drv_virtio_snd::shutdown(device_key);
    }
}
static VIRTIO_SND_DRV: VirtioChildDriver<VirtioSndOps> = VirtioChildDriver::new();

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
