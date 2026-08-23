// The ALSA card: the sound-core operations table, the mixer and jack
// elements built from the routing plan, and the owner-keyed device registry.

#![cfg(target_os = "oxide-kernel")]

use alloc::{sync::Arc, vec::Vec};
use core::ops::DerefMut;
use core::sync::atomic::{AtomicBool, Ordering};
use sync::{Devices as HdaRegistryClass, Spinlock};

use crate::controller::{Hda, IrqEndpoint};
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
    pub jack_elems: Vec<(u8, u32, sound::elem::ElemId)>,
    /// `(physical address, order)` of every DMA frame this controller owns,
    /// so removal frees exactly what the probe took.
    pub frames: Vec<(u64, u8)>,
    /// The BAR0 mapping, released with the device.
    pub mapping: Option<mmio_map::Mapping>,
}

impl Device {
    /// # C: O(1)
    pub fn new(key: pci::Bdf, owner: sound::SoundOwnerKey, hda: Hda, vendor_id: u32,
               frames: Vec<(u64, u8)>, mapping: mmio_map::Mapping) -> Self {
        let irq = IrqEndpoint::new(&hda);
        let reg = Arc::clone(&hda.rings);
        Self {
            key, owner, online: AtomicBool::new(true), irq,
            locks: ControllerLocks::from_reg(DeviceState {
                hda, vendor_id, jack_elems: Vec::new(), frames, mapping: Some(mapping),
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

fn hex4(value: u32, out: &mut [u8; 4]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = DIGITS[((value >> (12 - 4 * index)) & 0xf) as usize];
    }
}

fn identity(owner: sound::SoundOwnerKey) -> sound::CardIdentity {
    let vendor = with_device(owner, |device| device.vendor_id).unwrap_or(0);
    let mut components = [0u8; 13];
    components[..4].copy_from_slice(b"HDA:");
    let mut digits = [0u8; 4];
    hex4(vendor >> 16, &mut digits);
    components[4..8].copy_from_slice(&digits);
    hex4(vendor & 0xffff, &mut digits);
    components[8..12].copy_from_slice(&digits);
    sound::CardIdentity::new(b"HDA", b"HDA-Intel", b"HD-Audio Generic",
                             b"HD-Audio Generic at PCI", b"HD-Audio Generic",
                             &components[..12], b"HD-Audio Analog")
}

fn caps(owner: sound::SoundOwnerKey, playback: bool, device_number: u32) -> sound::ops::Caps {
    with_device(owner, |device| {
        let codec = device.hda.codec.as_ref()?;
        let plan = device.hda.plan.as_ref()?;
        let nid = if playback { plan.output_for(device_number)?.dac } else { plan.capture_for(device_number)?.adc };
        let par_pcm = codec.pcm_caps_of(nid);
        let formats = crate::stream_fmt::pcm_format_mask(par_pcm);
        let rates = crate::stream_fmt::pcm_rate_mask(par_pcm);
        if formats == 0 || rates == 0 { return None; }
        let channels = codec.widget(nid).map(|w| widget::widget_channels(w.wcaps)).unwrap_or(2);
        Some((formats, rates, 1, channels.min(u8::MAX as u32) as u8))
    })?
}

fn pcm_caps(owner: sound::SoundOwnerKey) -> sound::ops::Caps { caps(owner, true, 0) }
fn cap_caps(owner: sound::SoundOwnerKey) -> sound::ops::Caps { caps(owner, false, 0) }

fn pcm_devices(owner: sound::SoundOwnerKey) -> u32 {
    with_device(owner, |device| {
        let Some(plan) = device.hda.plan.as_ref() else { return 0; };
        let outputs = plan.all_outputs().count();
        let capture = usize::from(!plan.captures.is_empty());
        outputs.max(capture) as u32
    }).unwrap_or(0)
}

fn pcm_caps_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice) -> sound::ops::Caps { caps(owner, true, device) }
fn cap_caps_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice) -> sound::ops::Caps {
    if device == 0 { caps(owner, false, 0) } else { None }
}

fn hw_limits(_owner: sound::SoundOwnerKey) -> sound::ops::HwLimits {
    (stream::MAX_PERIOD_BYTES, stream::BUFFER_BYTES)
}

fn hw_limits_for(_owner: sound::SoundOwnerKey, _device: sound::ops::PcmDevice) -> sound::ops::HwLimits { hw_limits(_owner) }

/// The stream engine can be halted and restarted without losing its ring
/// position, which is exactly what SNDRV_PCM_IOCTL_PAUSE asks for.
fn info_flags(_owner: sound::SoundOwnerKey) -> u32 { sound::uapi::PCM_INFO_PAUSE }
fn info_flags_for(_owner: sound::SoundOwnerKey, _device: sound::ops::PcmDevice) -> u32 { info_flags(_owner) }

fn period_bytes(_owner: sound::SoundOwnerKey) -> usize { stream::MAX_PERIOD_BYTES as usize }
fn period_bytes_for(_owner: sound::SoundOwnerKey, _device: sound::ops::PcmDevice) -> usize { period_bytes(_owner) }

fn config(_owner: sound::SoundOwnerKey) -> Option<(u32, u32, u32, u32)> { None }

fn pcm_hw_params(owner: sound::SoundOwnerKey, format: u32, rate_hz: u32, channels: u8,
                 period_bytes: u32, _buffer_bytes: u32) -> bool {
    pcm_hw_params_for(owner, 0, format, rate_hz, channels, period_bytes, _buffer_bytes)
}

fn pcm_hw_params_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice,
                     format: u32, rate_hz: u32, channels: u8, period_bytes: u32,
                     _buffer_bytes: u32) -> bool {
    with_device(owner, |state| state.hda.prepare_playback(device, format, rate_hz, channels, period_bytes))
        .unwrap_or(false)
}

fn cap_hw_params(owner: sound::SoundOwnerKey, format: u32, rate_hz: u32, channels: u8,
                 period_bytes: u32, _buffer_bytes: u32) -> bool {
    cap_hw_params_for(owner, 0, format, rate_hz, channels, period_bytes, _buffer_bytes)
}

fn cap_hw_params_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice,
                     format: u32, rate_hz: u32, channels: u8, period_bytes: u32,
                     _buffer_bytes: u32) -> bool {
    with_device(owner, |state| state.hda.prepare_capture(device, format, rate_hz, channels, period_bytes))
        .unwrap_or(false)
}

fn pcm_prepare(owner: sound::SoundOwnerKey) -> bool {
    pcm_prepare_for(owner, 0)
}

fn pcm_prepare_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice) -> bool {
    with_device(owner, |device_state| {
        let Some(stream) = device_state.hda.playback.get_mut(device as usize) else { return false; };
        let regs = device_state.hda.regs;
        stream.stop(&regs);
        stream.write_off = 0;
        stream.laps = 0;
        stream.last_position = 0;
        stream.silence();
        true
    }).unwrap_or(false)
}

fn cap_prepare(owner: sound::SoundOwnerKey) -> bool {
    cap_prepare_for(owner, 0)
}

fn cap_prepare_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice) -> bool {
    with_device(owner, |device_state| {
        let Some(stream) = device_state.hda.capture.get_mut(device as usize) else { return false; };
        let regs = device_state.hda.regs;
        stream.stop(&regs);
        stream.write_off = 0;
        stream.laps = 0;
        stream.last_position = 0;
        true
    }).unwrap_or(false)
}

fn pcm_trigger(owner: sound::SoundOwnerKey, start: bool) -> bool {
    pcm_trigger_for(owner, 0, start)
}

fn pcm_trigger_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice, start: bool) -> bool {
    with_device(owner, |device_state| {
        let Some(stream) = device_state.hda.playback.get_mut(device as usize) else { return false; };
        let regs = device_state.hda.regs;
        if start { stream.start(&regs) } else { stream.stop(&regs) }
        true
    }).unwrap_or(false)
}

fn cap_trigger(owner: sound::SoundOwnerKey, start: bool) -> bool {
    cap_trigger_for(owner, 0, start)
}

fn cap_trigger_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice, start: bool) -> bool {
    with_device(owner, |device_state| {
        let Some(stream) = device_state.hda.capture.get_mut(device as usize) else { return false; };
        let regs = device_state.hda.regs;
        if start { stream.start(&regs) } else { stream.stop(&regs) }
        true
    }).unwrap_or(false)
}

fn pcm_pause(owner: sound::SoundOwnerKey, pause: bool) -> bool {
    pcm_pause_for(owner, 0, pause)
}

fn pcm_pause_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice, pause: bool) -> bool {
    with_device(owner, |device_state| {
        let Some(stream) = device_state.hda.playback.get_mut(device as usize) else { return false; };
        let regs = device_state.hda.regs;
        if pause { stream.pause(&regs) } else { stream.start(&regs) }
        true
    }).unwrap_or(false)
}

/// Wait for the hardware to consume what the ring already holds. # C: O(buffer)
fn pcm_drain(owner: sound::SoundOwnerKey) -> bool {
    pcm_drain_for(owner, 0)
}

fn pcm_drain_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice) -> bool {
    with_device(owner, |device_state| {
        let Some(stream) = device_state.hda.playback.get_mut(device as usize) else { return false; };
        let regs = device_state.hda.regs;
        let size = stream.geometry.buffer_bytes();
        if size == 0 || !stream.running { return true; }
        let deadline = crate::platform::now_ns() + 1_000_000_000;
        while stream.position(&regs) != stream.write_off {
            if crate::platform::now_ns() >= deadline { break; }
            crate::platform::udelay(100);
        }
        true
    }).unwrap_or(false)
}

fn pcm_pointer(owner: sound::SoundOwnerKey) -> Option<u64> {
    pcm_pointer_for(owner, 0)
}

fn pcm_pointer_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice) -> Option<u64> {
    with_device(owner, |device_state| {
        let stream = device_state.hda.playback.get_mut(device as usize)?;
        let regs = device_state.hda.regs;
        Some(stream.frames(&regs))
    })?
}

fn cap_pointer(owner: sound::SoundOwnerKey) -> Option<u64> {
    cap_pointer_for(owner, 0)
}

fn cap_pointer_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice) -> Option<u64> {
    with_device(owner, |device_state| {
        let stream = device_state.hda.capture.get_mut(device as usize)?;
        let regs = device_state.hda.regs;
        Some(stream.frames(&regs))
    })?
}

fn pcm_hw_free(owner: sound::SoundOwnerKey) -> bool {
    pcm_hw_free_for(owner, 0)
}

fn pcm_hw_free_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice) -> bool {
    with_device(owner, |device_state| {
        let Some(stream) = device_state.hda.playback.get_mut(device as usize) else { return false; };
        let regs = device_state.hda.regs;
        stream.stop(&regs);
        device_state.hda.release(device, true);
        true
    }).unwrap_or(false)
}

fn cap_hw_free(owner: sound::SoundOwnerKey) -> bool {
    cap_hw_free_for(owner, 0)
}

fn cap_hw_free_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice) -> bool {
    with_device(owner, |device_state| {
        let Some(stream) = device_state.hda.capture.get_mut(device as usize) else { return false; };
        let regs = device_state.hda.regs;
        stream.stop(&regs);
        device_state.hda.release(device, false);
        true
    }).unwrap_or(false)
}

fn pcm_submit(owner: sound::SoundOwnerKey, bytes: &[u8]) -> usize {
    pcm_submit_for(owner, 0, bytes)
}

fn pcm_submit_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice, bytes: &[u8]) -> usize {
    // A stream in flight is the one path guaranteed to run often, so it is
    // where a jack change is noticed while audio is playing.
    service_jacks(owner);
    with_device(owner, |device_state| {
        let Some(stream) = device_state.hda.playback.get_mut(device as usize) else { return 0; };
        let regs = device_state.hda.regs;
        stream.write(&regs, bytes)
    }).unwrap_or(0)
}

fn pcm_recv(owner: sound::SoundOwnerKey, out: &mut [u8]) -> usize {
    pcm_recv_for(owner, 0, out)
}

fn pcm_recv_for(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice, out: &mut [u8]) -> usize {
    with_device(owner, |device_state| {
        let Some(stream) = device_state.hda.capture.get_mut(device as usize) else { return 0; };
        let regs = device_state.hda.regs;
        stream.read(&regs, out)
    }).unwrap_or(0)
}

fn pcm_mmap_frame(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice, capture: bool, offset: u64) -> Option<u64> {
    with_device(owner, |device_state| {
        let stream = if capture { device_state.hda.capture.get(device as usize) }
                     else { device_state.hda.playback.get(device as usize) }?;
        let size = u64::from(stream.geometry.buffer_bytes());
        if offset & (hal::PAGE_SIZE_BYTES - 1) != 0 || offset >= size || size - offset < hal::PAGE_SIZE_BYTES { return None; }
        Some(stream.buffer_pa + offset)
    })?
}

/// The sound core's view of this card. # C: O(1)
pub static SOUND_OPS: sound::ops::SoundOps = sound::ops::SoundOps {
    identity,
    config,
    pcm_caps,
    cap_caps,
    hw_limits,
    info_flags,
    period_bytes,
    pcm_hw_params,
    pcm_prepare,
    pcm_trigger,
    pcm_pause,
    pcm_drain,
    pcm_pointer,
    pcm_hw_free,
    pcm_submit,
    cap_hw_params,
    cap_prepare,
    cap_trigger,
    cap_pointer,
    cap_hw_free,
    pcm_recv,
};

/// Per-PCM-device operations. The legacy table above remains the device-zero
/// compatibility surface for OSS; ALSA nodes use this table so every route
/// owns an independent stream descriptor and converter binding.
pub static PCM_DEVICE_OPS: sound::ops::PcmDeviceOps = sound::ops::PcmDeviceOps {
    pcm_devices,
    pcm_caps: pcm_caps_for,
    cap_caps: cap_caps_for,
    hw_limits: hw_limits_for,
    info_flags: info_flags_for,
    period_bytes: period_bytes_for,
    pcm_hw_params: pcm_hw_params_for,
    pcm_prepare: pcm_prepare_for,
    pcm_trigger: pcm_trigger_for,
    pcm_pause: pcm_pause_for,
    pcm_drain: pcm_drain_for,
    pcm_pointer: pcm_pointer_for,
    pcm_hw_free: pcm_hw_free_for,
    pcm_submit: pcm_submit_for,
    cap_hw_params: cap_hw_params_for,
    cap_prepare: cap_prepare_for,
    cap_trigger: cap_trigger_for,
    cap_pointer: cap_pointer_for,
    cap_hw_free: cap_hw_free_for,
    pcm_recv: pcm_recv_for,
    pcm_mmap_frame,
};

/// Drain any queued jack events and publish a control notification for each
/// jack whose presence changed. The codec round trip a re-sense needs cannot
/// run in the interrupt that queued the event, so it runs here, from the
/// paths userspace already drives.
/// # C: O(queued events + jack elements)
pub fn service_jacks(owner: sound::SoundOwnerKey) {
    let Some(changes) = with_device(owner, |device| device.hda.refresh_jacks()) else { return; };
    if changes.is_empty() { return; }
    let Some(elems) = with_device(owner, |device| device.jack_elems.clone()) else { return; };
    for (pin, _) in changes {
        for (elem_pin, numid, id) in elems.iter() {
            if *elem_pin == pin { sound::control::notify(owner, *numid, id); }
        }
    }
}

fn elem_get(owner: sound::SoundOwnerKey, private: u32, out: &mut sound::elem::ElemValues) -> bool {
    let (nid, output, kind) = elemkey::unpack(private);
    if kind == ElemKind::Jack { service_jacks(owner); }
    with_device(owner, |device| match kind {
        ElemKind::Jack => {
            out[0] = i64::from(device.hda.jack_sense(nid));
            true
        }
        ElemKind::Volume => {
            let Some((_, left)) = device.hda.amp_read(nid, output, 0, true) else { return false; };
            let right = device.hda.amp_read(nid, output, 0, false).map(|(_, gain)| gain).unwrap_or(left);
            out[0] = i64::from(left);
            out[1] = i64::from(right);
            true
        }
        ElemKind::Switch => {
            let Some((left_muted, _)) = device.hda.amp_read(nid, output, 0, true) else { return false; };
            let right_muted = device.hda.amp_read(nid, output, 0, false).map(|(muted, _)| muted).unwrap_or(left_muted);
            // ALSA switches are "on means audible", the inverse of the mute bit.
            out[0] = i64::from(!left_muted);
            out[1] = i64::from(!right_muted);
            true
        }
    }).unwrap_or(false)
}

fn elem_put(owner: sound::SoundOwnerKey, private: u32, values: &sound::elem::ElemValues) -> bool {
    let (nid, output, kind) = elemkey::unpack(private);
    with_device(owner, |device| match kind {
        ElemKind::Jack => false,
        ElemKind::Volume => {
            let muted = device.hda.amp_read(nid, output, 0, true).map(|(muted, _)| muted).unwrap_or(false);
            device.hda.amp_write(nid, output, 0, true, false, muted, values[0] as u8)
                && device.hda.amp_write(nid, output, 0, false, true, muted, values[1] as u8)
        }
        ElemKind::Switch => {
            let gain = device.hda.amp_read(nid, output, 0, true).map(|(_, gain)| gain).unwrap_or(0);
            device.hda.amp_write(nid, output, 0, true, false, values[0] == 0, gain)
                && device.hda.amp_write(nid, output, 0, false, true, values[1] == 0, gain)
        }
    }).unwrap_or(false)
}

fn elem_enum(_owner: sound::SoundOwnerKey, _private: u32, _item: u32,
             _out: &mut [u8; sound::elem::ENUM_NAME_WIDTH]) -> bool { false }

static ELEM_OPS: sound::elem::ElemOps =
    sound::elem::ElemOps { get: elem_get, put: elem_put, enum_name: elem_enum };

fn register_amp(owner: sound::SoundOwnerKey, control: &elemkey::AmpControl) {
    let (nid, output, caps) = (control.nid, control.output, control.caps);
    if caps.num_steps != 0 && !control.volume_name.is_empty() {
        sound::elem::register(owner, sound::elem::ElemDesc {
            id: sound::elem::ElemId::mixer(&control.volume_name, 0),
            etype: sound::uapi::CTL_ELEM_TYPE_INTEGER,
            access: sound::uapi::CTL_ELEM_ACCESS_READWRITE | sound::uapi::CTL_ELEM_ACCESS_TLV_READ,
            count: 2, min: 0, max: i64::from(caps.num_steps), step: 0, items: 0,
            tlv: Some(sound::elem::DbScale {
                min_centibel: widget::amp_min_centibel(&caps),
                step_centibel: caps.step_centibel,
                mute: caps.mute,
            }),
            private: elemkey::pack(nid, output, ElemKind::Volume),
            ops: &ELEM_OPS,
        });
    }
    if caps.mute {
        sound::elem::register(owner, sound::elem::ElemDesc {
            id: sound::elem::ElemId::mixer(&control.switch_name, 0),
            etype: sound::uapi::CTL_ELEM_TYPE_BOOLEAN,
            access: sound::uapi::CTL_ELEM_ACCESS_READWRITE,
            count: 2, min: 0, max: 1, step: 0, items: 0, tlv: None,
            private: elemkey::pack(nid, output, ElemKind::Switch),
            ops: &ELEM_OPS,
        });
    }
}

/// Publish the card's mixer and jack controls from its routing plan.
/// # C: O(routes)
pub fn register_controls(owner: sound::SoundOwnerKey) {
    let described = with_device(owner, |device| {
        match (device.hda.codec.as_ref(), device.hda.plan.as_ref()) {
            (Some(codec), Some(plan)) => Some(elemkey::describe(codec, plan)),
            _ => None,
        }
    });
    let Some(Some(controls)) = described else { return; };
    for control in controls.amps.iter() { register_amp(owner, control); }
    for jack in controls.jacks.iter() {
        let id = sound::elem::ElemId::mixer(&jack.name, 0);
        let numid = sound::elem::register(owner, sound::elem::ElemDesc {
            id, etype: sound::uapi::CTL_ELEM_TYPE_BOOLEAN,
            access: sound::uapi::CTL_ELEM_ACCESS_READ | sound::uapi::CTL_ELEM_ACCESS_VOLATILE,
            count: 1, min: 0, max: 1, step: 0, items: 0, tlv: None,
            private: elemkey::pack(jack.pin, true, ElemKind::Jack),
            ops: &ELEM_OPS,
        });
        with_device(owner, |device| device.jack_elems.push((jack.pin, numid, id)));
    }
}
