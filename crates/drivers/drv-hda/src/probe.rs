// PCI probe: match the HD-Audio class, map BAR0, allocate the command ring,
// the two BDLs and the two stream buffers, bring the controller up, and
// publish the ALSA card.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::card::{self, Device};
use crate::controller::Hda;
use crate::regs::Regs;
use crate::stream::{Stream, BUFFER_ORDER};
use crate::transport::Rings;
use crate::uapi::*;

const BAR_PAGE_SIZE: u64 = hal::PAGE_SIZE_BYTES;
const BAR_PAGE_OFFSET_MASK: u64 = BAR_PAGE_SIZE - 1;
const BAR_PAGE_BASE_MASK: u64 = !BAR_PAGE_OFFSET_MASK;
/// DMA structures are placed below 4 GiB unless the controller says it can
/// address more, which is what the 64-bit capability bit means.
const DMA32_LIMIT: u64 = 1 << 32;

/// Frames one controller owns, so a probe failure frees exactly what it took.
struct Frames {
    ring: u64,
    playback_bdl: u64,
    capture_bdl: u64,
    playback_buffer: u64,
    capture_buffer: u64,
}

fn alloc_page(addr64: bool) -> Option<u64> {
    if addr64 { pmm::setup::alloc_contig(pmm::Order(0)) }
    else { pmm::setup::alloc_contig_below(pmm::Order(0), DMA32_LIMIT) }
}

fn alloc_buffer(addr64: bool) -> Option<u64> {
    if addr64 { pmm::setup::alloc_contig(pmm::Order(BUFFER_ORDER as u8)) }
    else { pmm::setup::alloc_contig_below(pmm::Order(BUFFER_ORDER as u8), DMA32_LIMIT) }
}

fn frame_list(frames: &Frames) -> alloc::vec::Vec<(u64, u8)> {
    [(frames.ring, 0u8), (frames.playback_bdl, 0), (frames.capture_bdl, 0),
     (frames.playback_buffer, BUFFER_ORDER as u8), (frames.capture_buffer, BUFFER_ORDER as u8)]
        .into_iter().filter(|(pa, _)| *pa != 0).collect()
}

fn free_frames(frames: &Frames) {
    for (pa, order) in frame_list(frames) {
        // SAFETY: every address here came from this probe's own
        // `alloc_contig` at the same order and is unmapped from any device.
        unsafe { pmm::setup::free_contig(pa, pmm::Order(order)); }
    }
}

fn alloc_frames(addr64: bool) -> Option<Frames> {
    let mut frames = Frames { ring: 0, playback_bdl: 0, capture_bdl: 0,
                              playback_buffer: 0, capture_buffer: 0 };
    let take = |slot: &mut u64, page: Option<u64>| -> bool {
        match page { Some(pa) => { *slot = pa; true } None => false }
    };
    let ok = take(&mut frames.ring, alloc_page(addr64))
        && take(&mut frames.playback_bdl, alloc_page(addr64))
        && take(&mut frames.capture_bdl, alloc_page(addr64))
        && take(&mut frames.playback_buffer, alloc_buffer(addr64))
        && take(&mut frames.capture_buffer, alloc_buffer(addr64));
    if ok { Some(frames) } else { free_frames(&frames); None }
}

/// The controller whose interrupt the shared handler services. One HD-Audio
/// function is the normal case; a second is left polled.
static IRQ_OWNER: AtomicU32 = AtomicU32::new(0);

fn hard_handler() {
    let raw = IRQ_OWNER.load(Ordering::Acquire);
    let Some(owner) = sound::SoundOwnerKey::from_raw(raw) else { return; };
    card::with_device(owner, |device| device.hda.handle_interrupt());
}

fn bring_up(bdf: pci::Bdf, mmio_base: u64, mapping: mmio_map::Mapping) -> bool {
    let regs = Regs::new(mmio_base);
    let addr64 = regs.addr64();
    let Some(frames) = alloc_frames(addr64) else { return false; };
    let hhdm = crate::platform::hhdm();
    let Some(owner) = card::owner_key(bdf) else { free_frames(&frames); return false; };

    // Output stream descriptors follow the input and bidirectional blocks.
    let inputs = regs.input_streams();
    let bidir = regs.bidir_streams();
    let outputs = regs.output_streams();
    if inputs == 0 || outputs == 0 { free_frames(&frames); return false; }
    let playback_index = inputs + bidir;
    let streams = inputs + bidir + outputs;

    let mut hda = Hda {
        regs,
        rings: Rings::new(frames.ring, hhdm + frames.ring),
        playback: Stream::new(playback_index, playback_index + 1, frames.playback_bdl,
                              hhdm + frames.playback_bdl, frames.playback_buffer,
                              hhdm + frames.playback_buffer),
        // Stream tags are one-based and live in a four-bit field; the two
        // streams have distinct descriptor indices, so index+1 is distinct too.
        capture: Stream::new(0, 1, frames.capture_bdl, hhdm + frames.capture_bdl,
                             frames.capture_buffer, hhdm + frames.capture_buffer),
        codec: None,
        plan: None,
        jack_tags: [(0, 0); crate::controller::MAX_JACKS],
        jack_count: 0,
        jack_present: [false; crate::controller::MAX_JACKS],
        streams,
        interrupts: false,
    };

    let irq = pci_irq::request_msi_only(bdf, arch_irq::DeviceAction::Hda, hard_handler);
    if irq.is_some() { IRQ_OWNER.store(owner.raw(), Ordering::Release); }
    hda.interrupts = irq.is_some();

    let Some(present) = hda.bring_up() else {
        if let Some(binding) = irq { binding.release(); }
        free_frames(&frames);
        return false;
    };
    if !hda.enumerate(present) {
        hda.quiesce();
        if let Some(binding) = irq { binding.release(); }
        free_frames(&frames);
        return false;
    }
    hda.apply_plan();
    let vendor_id = hda.codec.as_ref().map(|codec| codec.vendor_id).unwrap_or(0);

    if !sound::reserve_card(owner) {
        hda.quiesce();
        if let Some(binding) = irq { binding.release(); }
        free_frames(&frames);
        return false;
    }
    card::insert(Device { key: bdf, owner, hda, vendor_id, jack_elems: alloc::vec::Vec::new(),
                          frames: frame_list(&frames), mapping: Some(mapping) });
    if !sound::ops::register(owner, &card::SOUND_OPS) {
        teardown(bdf, &frames, irq);
        return false;
    }
    card::register_controls(owner);
    if !sound::register_card(owner) {
        sound::elem::unregister_card(owner);
        teardown(bdf, &frames, irq);
        return false;
    }
    true
}

fn teardown(bdf: pci::Bdf, frames: &Frames, irq: Option<pci_irq::Binding>) {
    if let Some(mut device) = card::remove(bdf) { device.hda.quiesce(); }
    let _ = card::owner_key(bdf).map(sound::cancel_card_reservation);
    if let Some(binding) = irq { binding.release(); }
    free_frames(frames);
}

/// PCI driver for the HD-Audio controller class.
pub struct HdaDriver;

impl drv::Driver for HdaDriver {
    fn name(&self) -> &'static str { "snd_hda_intel" }

    fn matches(&self, dev: &drv::Device) -> bool {
        dev.bus == "pci" && dev.class == HDA_CLASS24
    }

    fn probe(&self, dev: &Arc<drv::Device>) -> drv::KResult<()> {
        let bdf = pci::parse_bdf_addr(&dev.addr).ok_or(drv::Error::ProbeFailed)?;
        #[cfg(target_arch = "x86_64")]
        let reader = hal_x86_64::pci::EcamPci::from_published().ok_or(drv::Error::ProbeFailed)?;
        #[cfg(target_arch = "aarch64")]
        let reader = hal_aarch64::pci::EcamPci::from_published().ok_or(drv::Error::ProbeFailed)?;
        let command_orig = pci::enable_mem_bus_master(&reader, bdf);
        // The controller must arbitrate at the default traffic class, which
        // is what clearing the select field asks for.
        {
            use pci::ConfigSpaceReader;
            let tcsel = reader.read8_ext(bdf, PCI_TCSEL);
            reader.write8_ext(bdf, PCI_TCSEL, tcsel & !PCI_TCSEL_MASK);
        }

        let Some(resource) = dev.resources.iter()
            .find(|resource| resource.bar == 0 && resource.flags & drv::IORESOURCE_MEM != 0) else {
                let _ = pci::restore_mem_bus_master(&reader, bdf, command_orig);
                return Err(drv::Error::ProbeFailed);
            };
        let bar_pa = resource.start;
        let bar_bytes = resource.end.checked_sub(resource.start)
            .and_then(|bytes| bytes.checked_add(1)).ok_or(drv::Error::ProbeFailed)?;
        let map_bytes = (bar_pa & BAR_PAGE_OFFSET_MASK).checked_add(bar_bytes)
            .ok_or(drv::Error::ProbeFailed)?;
        let pages = map_bytes.div_ceil(BAR_PAGE_SIZE);
        // SAFETY: BAR0 was enumerated for this HD-Audio function; this
        // mapping owns its complete page-rounded register aperture.
        let mmio = unsafe { mmio_map::map_owned(bar_pa & BAR_PAGE_BASE_MASK, pages as u64) };
        let base = mmio.base_va() + (bar_pa & BAR_PAGE_OFFSET_MASK);
        if !bring_up(bdf, base, mmio) {
            let _ = pci::restore_mem_bus_master(&reader, bdf, command_orig);
            return Err(drv::Error::ProbeFailed);
        }
        Ok(())
    }

    fn remove(&self, dev: &drv::Device) {
        let Some(bdf) = pci::parse_bdf_addr(&dev.addr) else { return; };
        if let Some(owner) = card::owner_of(bdf) {
            sound::unregister_card(owner);
            sound::elem::unregister_card(owner);
        }
        if let Some(mut device) = card::remove(bdf) {
            device.hda.quiesce();
            for (pa, order) in device.frames.iter() {
                // SAFETY: each address came from this driver's own probe-time
                // `alloc_contig` at the same order, and the controller was
                // quiesced above so no engine still reads them.
                unsafe { pmm::setup::free_contig(*pa, pmm::Order(*order)); }
            }
            if let Some(mut mapping) = device.mapping.take() { mapping.unmap(); }
        }
    }

    fn shutdown(&self, dev: &drv::Device) {
        let Some(bdf) = pci::parse_bdf_addr(&dev.addr) else { return; };
        if let Some(owner) = card::owner_of(bdf) {
            card::with_device(owner, |device| device.hda.quiesce());
        }
    }
}

/// Singleton driver instance for registration. # C: O(1)
pub static HDA_DRIVER: HdaDriver = HdaDriver;
