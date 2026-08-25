// The ALSA card: the sound-core operations table, the mixer and jack
// elements built from the routing plan, and the owner-keyed device registry.

#![cfg(target_os = "oxide-kernel")]

use alloc::{sync::Arc, vec::Vec};
use core::ops::DerefMut;
use core::sync::atomic::{AtomicBool, Ordering};
use sync::{Devices as HdaRegistryClass, Spinlock};

use crate::controller::{Hda, IrqEndpoint};
use crate::ctlname;
use crate::elemkey::{self, ElemKind};
use crate::ownership::ControllerLocks;
use crate::stream;
use crate::transport::Rings;
use crate::widget;

/// One probed controller.
pub struct Device {
    pub key: pci::Bdf,
    pub owner: sound::SoundOwnerKey,
    online: AtomicBool,
    locks: ControllerLocks<DeviceState, Rings>,
    irq: IrqEndpoint,
}

/// Process-context state for one controller.
pub struct DeviceState {
    pub hda: Hda,
    /// Codec vendor id, kept for the card identity string.
    pub vendor_id: u32,
    /// Jack elements, so a presence change can name the control that moved.
    pub jack_elems: Vec<(usize, u8, u32, sound::elem::ElemId)>,
    /// Physical output followers controlled by the Linux virtual master.
    pub master_followers: Vec<MasterFollower>,
    /// Software attenuation and mute state of the virtual master.
    pub master_volume: u8,
    pub master_mute: bool,
    pub beep_generation: u32,
    /// `(physical address, order)` of every DMA frame this controller owns,
    /// so removal frees exactly what the probe took.
    pub frames: Vec<(u64, u8, bool)>,
    /// The BAR0 mapping, released with the device.
    pub mapping: Option<mmio_map::Mapping>,
}

#[derive(Clone, Debug)]
pub struct MasterFollower {
    pub codec: usize,
    pub nid: u8,
    pub output: bool,
    pub caps: widget::AmpCaps,
    pub left: u8,
    pub right: u8,
    pub left_muted: bool,
    pub right_muted: bool,
}

impl Device {
    /// # C: O(1)
    pub fn new(key: pci::Bdf, owner: sound::SoundOwnerKey, hda: Hda, vendor_id: u32,
               frames: Vec<(u64, u8, bool)>, mapping: mmio_map::Mapping) -> Self {
        let irq = IrqEndpoint::new(&hda);
        let reg = Arc::clone(&hda.rings);
        Self {
            key, owner, online: AtomicBool::new(true), irq,
            locks: ControllerLocks::from_reg(DeviceState {
                hda, vendor_id, jack_elems: Vec::new(), master_followers: Vec::new(),
                master_volume: 0, master_mute: false, beep_generation: 0, frames, mapping: Some(mapping),
            }, reg),
        }
    }

    /// Run cleanup after this controller has left the lookup registry.
    /// # C: O(1) plus callback
    pub fn with_offline<R>(&self, f: impl FnOnce(&mut DeviceState) -> R) -> R {
        // SAFETY: remove set `online=false` and unpublished this handle; this
        // process-context acquire waits for any operation already in flight.
        let mut state = unsafe { self.locks.process.lock() };
        f(&mut state)
    }
}

pub type DeviceHandle = Arc<Device>;

static DEVICES: Spinlock<Vec<DeviceHandle>, HdaRegistryClass> = Spinlock::new(Vec::new());

/// Acquire the controller directory with its hard-IRQ lookup excluded. The
/// guard covers lookup/publish only and is dropped before controller work.
/// # C: O(1) plus contention
fn lock_devices() -> impl DerefMut<Target = Vec<DeviceHandle>> {
    #[cfg(target_arch = "x86_64")]
    { DEVICES.lock_irqsave::<hal_x86_64::X86IrqGate>() }
    #[cfg(target_arch = "aarch64")]
    { DEVICES.lock_irqsave::<hal_aarch64::ArmIrqGate>() }
}

/// Owner keys carry a tag so they cannot collide with another sound
/// transport's key space.
const OWNER_TAG: u32 = 0x4844_0000;

/// Stable sound-owner key for a PCI function. # C: O(1)
pub fn owner_key(bdf: pci::Bdf) -> Option<sound::SoundOwnerKey> {
    let raw = OWNER_TAG | (u32::from(bdf.bus) << 8) | (u32::from(bdf.device) << 3)
        | u32::from(bdf.function);
    sound::SoundOwnerKey::from_raw(raw)
}

/// Run `f` over the device owning `owner`. # C: O(devices)
pub fn with_device<R>(owner: sound::SoundOwnerKey,
                      f: impl FnOnce(&mut DeviceState) -> R) -> Option<R> {
    let device = lock_devices().iter().find(|device| device.owner == owner).cloned()?;
    // SAFETY: sound callbacks run in process context and hold no spinlock;
    // registry lookup ended before this possibly sleeping acquisition.
    let mut state = unsafe { device.locks.process.lock() };
    if !device.online.load(Ordering::Acquire) { return None; }
    Some(f(&mut state))
}

/// Publish a probed controller. # C: O(devices)
pub fn insert(device: Device) { lock_devices().push(Arc::new(device)); }

/// Remove a controller, returning it so the caller can free its frames.
/// # C: O(devices)
pub fn remove(key: pci::Bdf) -> Option<DeviceHandle> {
    let mut guard = lock_devices();
    let index = guard.iter().position(|device| device.key == key)?;
    guard[index].online.store(false, Ordering::Release);
    Some(guard.remove(index))
}

/// Owner of the controller at `key`. # C: O(devices)
pub fn owner_of(key: pci::Bdf) -> Option<sound::SoundOwnerKey> {
    lock_devices().iter().find(|device| device.key == key).map(|device| device.owner)
}

/// Service one IRQ without acquiring process state. # C: O(devices + responses)
pub fn handle_interrupt(owner: sound::SoundOwnerKey) -> bool {
    let Some(device) = lock_devices().iter().find(|device| device.owner == owner).cloned()
        else { return false; };
    if !device.online.load(Ordering::Acquire) { return false; }
    device.irq.handle(&device.locks.reg)
}

/// Drain any queued jack events and publish a control notification for each
/// jack whose presence changed. The codec round trip a re-sense needs cannot
/// run in the interrupt that queued the event, so it runs here, from the
/// paths userspace already drives.
/// # C: O(queued events + jack elements)
pub fn service_jacks(owner: sound::SoundOwnerKey) {
    let Some(changes) = with_device(owner, |device| device.hda.refresh_jacks()) else { return; };
    if changes.is_empty() { return; }
    let Some(elems) = with_device(owner, |device| device.jack_elems.clone()) else { return; };
    for (codec, pin, _) in changes {
        for (elem_codec, elem_pin, numid, id) in elems.iter() {
            if *elem_codec == codec && *elem_pin == pin { sound::control::notify(owner, *numid, id); }
        }
    }
}

/// Drain unsolicited codec events for every live HDA card. This is installed
/// as the process-only softirq handler because jack sensing issues codec
/// commands and publishes sound-control notifications.
pub fn drain_jack_events() {
    let owners: Vec<_> = lock_devices().iter()
        .filter(|device| device.online.load(Ordering::Acquire))
        .map(|device| device.owner)
        .collect();
    for owner in owners { service_jacks(owner); }
}

fn stop_beep(arg: usize) {
    let owner_raw = arg as u32;
    let generation = (arg >> 32) as u32;
    let Some(owner) = sound::SoundOwnerKey::from_raw(owner_raw) else { return; };
    let _ = with_device(owner, |device| {
        if device.beep_generation == generation { device.hda.beep(0); }
    });
}

/// Route VT's PC-beep request to each HDA codec that owns a beep widget.
/// # C: O(cards) plus one delayed work item per active tone
pub fn beep(hz: u32, milliseconds: u32) -> bool {
    let devices: Vec<_> = lock_devices().iter()
        .filter(|device| device.online.load(Ordering::Acquire))
        .cloned().collect();
    let mut handled = false;
    for device in devices {
        let owner = device.owner;
        let (ok, generation) = unsafe {
            let mut state = device.locks.process.lock();
            state.beep_generation = state.beep_generation.wrapping_add(1);
            (state.hda.beep(hz), state.beep_generation)
        };
        if !ok { continue; }
        handled = true;
        if milliseconds != 0 && hz != 0 {
            let arg = ((generation as usize) << 32) | owner.raw() as usize;
            let _ = sched::live::queue_delayed_work_on(
                0, stop_beep, arg, sched::deadline::clock::now_ns(),
                u64::from(milliseconds) * 1_000_000);
        }
    }
    handled
}

mod pcm;
mod mixer;

pub use mixer::register_controls;
pub use pcm::{PCM_DEVICE_OPS, SOUND_OPS};
