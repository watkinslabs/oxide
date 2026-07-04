// Modern virtio-pci transport bring-up. Split from pci_boot/mod.rs.
// klog calls gated under debug_boot! per R06.

use super::virtio_transport::{
    alloc_net_tx_boot_buffer, bind_msix_vector, disable_pci_command, kick_queue_notify,
    post_net_rx_boot_buffer, program_queue_set, publish_transport_record, read_queue_used_idx,
    release_failed_probe, release_msix_bindings, unpublish_transport_record, MsixBinding,
    NetRxBootBuffer, ProgrammedQueues, QueueRing, TransportMappings,
};
use alloc::sync::Arc;
use alloc::vec::Vec;

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

    fn remove(&self, _dev: &drv::Device) {
        if let Some(bdf) = pci_parent_bdf(_dev) {
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

        // Seed the kernel RNG with real entropy at bring-up. Read from the
        // just-bound device, not whichever hwrng is currently active.
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

const VIRTIO_MSIX_Q0_VECTOR: u16 = 0;

fn release_probe_msix(p: &mut VirtioProbe) {
    release_msix_bindings(bdf_from_word(p.bdf_word), &mut p.msix);
}

fn publish_transport_mmio(p: &mut VirtioProbe) {
    publish_transport_record(
        p.bdf_word,
        core::mem::take(&mut p.mappings),
        p.transport_vring_frames(),
        core::mem::take(&mut p.msix),
    );
}

fn abandon_probe_transport(bdf: pci::Bdf, mappings: &mut TransportMappings) -> Option<VirtioProbe> {
    disable_pci_command(bdf);
    mappings.unmap_all();
    None
}

fn push_unique_frame(frames: &mut Vec<u64>, frame: u64) {
    if frame != 0 && !frames.iter().any(|existing| *existing == frame) {
        frames.push(frame);
    }
}

fn unpublish_transport_mmio(bdf: u32) {
    unpublish_transport_record(bdf);
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
    msix: Vec<MsixBinding>,
}

#[derive(Default)]
struct PlannedNotifyMappings {
    q2: u64,
    q3: u64,
}

struct VirtioTransportBringup {
    negotiated: virtio::FeatureNegotiation,
    queues: [(u16, u16); 8],
    queues_len: usize,
    programmed_queues: Option<ProgrammedQueues>,
    final_status: u8,
}

impl VirtioProbeState {
    fn new(bdf: pci::Bdf, mappings: TransportMappings, cfg_va: u64, device_cfg_va: u64) -> Self {
        Self {
            bdf_word: bdf_word(bdf),
            mappings,
            cfg_va,
            device_cfg_va,
            msix: Vec::new(),
        }
    }

    fn bind_msix_queue(
        &mut self,
        d: &pci::PciDevice,
        caps: &pci::heapless_caps::CapVec,
        bars: &[pci::Bar; 6],
        queue_vector: u16,
        handler: Option<fn()>,
    ) -> Option<u16> {
        let Some(handler) = handler else {
            return None;
        };
        if let Some(binding) = self
            .msix
            .iter()
            .find(|binding| binding.queue_vector == queue_vector)
        {
            return Some(binding.queue_vector);
        }
        if let Some(binding) = bind_msix_vector(
                d,
                caps,
                bars,
                &mut self.mappings,
                queue_vector,
                handler,
        ) {
            let queue_vector = binding.queue_vector;
            self.msix.push(binding);
            return Some(queue_vector);
        }
        None
    }

    fn bind_msix0(
        &mut self,
        d: &pci::PciDevice,
        caps: &pci::heapless_caps::CapVec,
        bars: &[pci::Bar; 6],
        handler: Option<fn()>,
    ) -> Option<u16> {
        self.bind_msix_queue(d, caps, bars, VIRTIO_MSIX_Q0_VECTOR, handler)
    }

    fn resolve_extra_queue_msix(
        &mut self,
        d: &pci::PciDevice,
        caps: &pci::heapless_caps::CapVec,
        bars: &[pci::Bar; 6],
        extra_queues: &[Option<virtio::VirtioQueuePlan>; 3],
    ) -> [Option<virtio::VirtioQueuePlan>; 3] {
        let mut resolved = *extra_queues;
        for plan in resolved.iter_mut().flatten() {
            let msix_vec = self
                .bind_msix_queue(d, caps, bars, plan.index, plan.msix_handler)
                .unwrap_or(virtio::VIRTIO_MSI_NO_VECTOR);
            *plan = plan.with_msix_vec(msix_vec);
        }
        resolved
    }

    fn negotiate_and_program(
        &mut self,
        d: &pci::PciDevice,
        caps: &pci::heapless_caps::CapVec,
        bars: &[pci::Bar; 6],
        profile: virtio::VirtioTransportProfile,
        hhdm: u64,
    ) -> VirtioTransportBringup {
        let negotiated = virtio::negotiate_features(self.cfg_va, profile.drv_features);
        let (queues, queues_len) = virtio::scan_queue_sizes(self.cfg_va, negotiated.num_queues);

        let q0_msix_vec = if negotiated.features_ok {
            self.bind_msix0(d, caps, bars, profile.msix0_handler)
                .unwrap_or(virtio::VIRTIO_MSI_NO_VECTOR)
        } else {
            virtio::VIRTIO_MSI_NO_VECTOR
        };
        let extra_queues = if negotiated.features_ok {
            self.resolve_extra_queue_msix(d, caps, bars, &profile.extra_queues)
        } else {
            profile.extra_queues
        };
        let programmed_queues = if negotiated.features_ok {
            program_queue_set(self.cfg_va, hhdm, q0_msix_vec, &extra_queues)
        } else {
            None
        };
        let final_status = if !negotiated.features_ok {
            virtio::set_failed(self.cfg_va)
        } else if programmed_queues.is_some() {
            virtio::set_driver_ok(self.cfg_va)
        } else {
            virtio::set_failed(self.cfg_va)
        };

        VirtioTransportBringup {
            negotiated,
            queues,
            queues_len,
            programmed_queues,
            final_status,
        }
    }

    fn map_notify(
        &mut self,
        notify_cap: Option<&virtio::VirtioPciCap>,
        bars: &[pci::Bar; 6],
        notify_off: u16,
    ) -> u64 {
        self.mappings
            .map_queue_notify_va(notify_cap, bars, notify_off)
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

    fn kick_queue_and_observe_status(
        &mut self,
        notify_cap: Option<&virtio::VirtioPciCap>,
        bars: &[pci::Bar; 6],
        notify_off: u16,
        queue_index: u16,
        fallback_status: u8,
    ) -> (u64, u8) {
        let kick_va = self.kick_queue(notify_cap, bars, notify_off, queue_index);
        if kick_va == 0 {
            return (0, fallback_status);
        }
        // Brief observation window for device-driven completion. QEMU user-net
        // normally has no packet ready here, so q0 used.idx may stay 0.
        for _ in 0..1_000_000 {
            core::hint::spin_loop();
        }
        (kick_va, virtio::read_status(self.cfg_va))
    }

    fn read_isr_status(
        &mut self,
        isr_cap: Option<&virtio::VirtioPciCap>,
        bars: &[pci::Bar; 6],
    ) -> u8 {
        self.mappings.read_isr_status(isr_cap, bars)
    }

    fn map_planned_extra_notifies(
        &mut self,
        queue_plans: &[Option<virtio::VirtioQueuePlan>; 3],
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
        policy: virtio::VirtioQ1NotifyPolicy,
        q1_ring: Option<QueueRing>,
        final_status: u8,
        notify_cap: Option<&virtio::VirtioPciCap>,
        bars: &[pci::Bar; 6],
    ) -> u64 {
        if (final_status & virtio::VIRTIO_STATUS_DRIVER_OK) == 0 {
            return 0;
        }
        match policy {
            virtio::VirtioQ1NotifyPolicy::None => 0,
            virtio::VirtioQ1NotifyPolicy::NetBootTx
            | virtio::VirtioQ1NotifyPolicy::PersistentTx
            | virtio::VirtioQ1NotifyPolicy::PersistentEvent => {
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
    msix: Vec<MsixBinding>,
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
    fn queue_resource(&self, index: u16) -> Option<virtio::VirtQueueResource> {
        match index {
            0 => Some(self.q0_resource()),
            1 => Some(self.q1_resource()),
            2 => Some(self.snd_q2_resource()),
            3 => Some(self.snd_q3_resource()),
            _ => None,
        }
    }

    fn child_queues_ready(&self, requirements: virtio::VirtioChildRequirements) -> bool {
        for (index, required) in requirements.required_queues.iter().copied().enumerate() {
            if !required {
                continue;
            }
            let Some(queue) = self.queue_resource(index as u16) else {
                return false;
            };
            if !queue.is_runtime_valid() {
                return false;
            }
        }
        true
    }

    fn net_payloads_ready(&self) -> bool {
        self.rx0_buf_pa != 0 && self.rx0_buf_len != 0 && self.tx0_buf_pa != 0
    }

    fn ready_for_child(&self, requirements: virtio::VirtioChildRequirements) -> bool {
        (self.final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0
            && self.cfg_va != 0
            && self.child_queues_ready(requirements)
            && (!requirements.needs_device_cfg || self.device_cfg_va != 0)
            && (!requirements.needs_net_boot_payloads || self.net_payloads_ready())
    }

    fn child_resources(
        &self,
        requirements: virtio::VirtioChildRequirements,
    ) -> Option<virtio::VirtioResources> {
        if !self.ready_for_child(requirements) {
            return None;
        }

        let mut resources =
            virtio::VirtioResources::new(self.cfg_va, virtio_hhdm_offset())
                .with_device_cfg_va(self.device_cfg_va);
        for (index, required) in requirements.required_queues.iter().copied().enumerate() {
            if !required {
                continue;
            }
            resources.set_queue(self.queue_resource(index as u16)?);
        }
        Some(resources)
    }

    fn transport_vring_frames(&self) -> Vec<u64> {
        let mut frames = Vec::new();
        for frame in [
            self.q0_desc_pa,
            self.q0_driver_pa,
            self.q0_device_pa,
            self.q1_desc_pa,
            self.q1_driver_pa,
            self.q1_device_pa,
            self.snd_q2_desc_pa,
            self.snd_q2_driver_pa,
            self.snd_q2_device_pa,
            self.snd_q3_desc_pa,
            self.snd_q3_driver_pa,
            self.snd_q3_device_pa,
        ] {
            push_unique_frame(&mut frames, frame);
        }
        frames
    }

    fn release_failed_transport(&mut self, payload_frames: &[u64]) {
        let mut frames = self.transport_vring_frames();
        for frame in payload_frames.iter().copied() {
            push_unique_frame(&mut frames, frame);
        }
        release_failed_probe(self.cfg_va, &frames);
        release_probe_msix(self);
        disable_pci_command(bdf_from_word(self.bdf_word));
        self.mappings.unmap_all();
    }

    fn release_failed_transport_with_net_payloads(&mut self) {
        self.release_failed_transport(&[self.rx0_buf_pa, self.tx0_buf_pa]);
    }

    fn release_failed_child(&mut self, requirements: virtio::VirtioChildRequirements) {
        if requirements.needs_net_boot_payloads {
            self.release_failed_transport_with_net_payloads();
        } else {
            self.release_failed_transport(&[]);
        }
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
fn virtio_init_arch(
    d: &pci::PciDevice,
    profile: virtio::VirtioTransportProfile,
) -> Option<VirtioProbe> {
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

    // Per-arch HHDM offset, hoisted once for all queue programming. The
    // virtio core programs EVERY virtqueue uniformly through the transport:
    // q0 for all devices, q1 for net/vsock TX or snd EVENTQ, and q2/q3 for
    // multi-queue devices such as virtio-snd.
    let hhdm = {
        #[cfg(target_arch = "x86_64")]
        { hal_x86_64::mmu_ops::hhdm_offset() }
        #[cfg(target_arch = "aarch64")]
        { hal_aarch64::mmu_ops::hhdm_offset() }
    };
    let bringup = state.negotiate_and_program(d, &caps, &bars, profile, hhdm);
    let dev_features = bringup.negotiated.dev_features;
    let drv_features = bringup.negotiated.drv_features;
    let post_status = bringup.negotiated.post_status;
    let features_ok = bringup.negotiated.features_ok;
    let msix_cfg = bringup.negotiated.msix_cfg;
    let num_queues = bringup.negotiated.num_queues;
    let queues = bringup.queues;
    let queues_len = bringup.queues_len;
    let q0_size = if queues_len > 0 { queues[0].1 } else { 0 };
    let notify_cap = vcaps.find(virtio::VIRTIO_PCI_CAP_NOTIFY_CFG);
    let extra_notify_mappings = state.map_planned_extra_notifies(
        &profile.extra_queues,
        bringup.programmed_queues.as_ref(),
        notify_cap.as_ref(),
        &bars,
    );
    let snd_q2_notify_va_local = extra_notify_mappings.q2;
    let snd_q3_notify_va_local = extra_notify_mappings.q3;
    let final_status = bringup.final_status;
    let q0_ring = bringup.programmed_queues.as_ref().map(|p| p.q0);
    let q1_ring = bringup.programmed_queues.as_ref().and_then(|p| p.extra_queue(1));
    let q2_ring = bringup.programmed_queues.as_ref().and_then(|p| p.extra_queue(2));
    let q3_ring = bringup.programmed_queues.as_ref().and_then(|p| p.extra_queue(3));
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
        post_net_rx_boot_buffer(hhdm, q0_ring)
    } else {
        NetRxBootBuffer::default()
    };
    let avail_idx_posted = net_rx_boot.avail_idx_posted;
    let rx0_buf_pa_local = net_rx_boot.buf_pa;
    let rx0_buf_len_local = net_rx_boot.buf_len;

    let (q0_notify_va, post_notify_status) = if final_status & virtio::VIRTIO_STATUS_FAILED == 0
        && (final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0
    {
        state.kick_queue_and_observe_status(notify_cap.as_ref(), &bars, q0_notify_off, 0, final_status)
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
    let tx0_buf_pa_local = if matches!(
        profile.q1_notify_policy,
        virtio::VirtioQ1NotifyPolicy::NetBootTx
    )
        && (final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0
    {
        alloc_net_tx_boot_buffer(hhdm, q1_ring, q1_notify_va_local)
    } else {
        0
    };

    let isr_status = if avail_idx_posted > 0 {
        state.read_isr_status(vcaps.find(virtio::VIRTIO_PCI_CAP_ISR_CFG).as_ref(), &bars)
    } else { 0 };

    let used_idx_observed = if avail_idx_posted > 0 {
        read_queue_used_idx(hhdm, q0_ring)
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
