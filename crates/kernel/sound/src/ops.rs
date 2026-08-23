//! Sound-card driver operations consumed by the ALSA/OSS core.
//!
//! The sound core owns user-visible ALSA/OSS state and device nodes. The
//! concrete card driver installs this table from probe, matching Linux's
//! `snd_pcm_ops` split without creating a crate cycle. Formats crossing this
//! boundary are ALSA `SNDRV_PCM_FORMAT_*` values and rates are Hz; any
//! transport-private encoding stays inside the driver that owns it.

use sync::{Spinlock, TaskList as OpsLockClass};
use alloc::vec::Vec;

use crate::identity::CardIdentity;

/// `(format_mask, rate_mask, ch_min, ch_max)`. `format_mask` bit `f` is set
/// when the card accepts `SNDRV_PCM_FORMAT_f`; `rate_mask` bit `i` selects
/// `crate::format::RATE_HZ[i]`.
pub type Caps = Option<(u64, u64, u8, u8)>;

/// ALSA PCM device number within one sound card.
pub type PcmDevice = u32;

/// Largest period and buffer, in bytes, the card's transfer path accepts.
pub type HwLimits = (u32, u32);

pub struct SoundOps {
    pub identity: fn(crate::SoundOwnerKey) -> CardIdentity,
    pub config: fn(crate::SoundOwnerKey) -> Option<(u32, u32, u32, u32)>,
    pub pcm_caps: fn(crate::SoundOwnerKey) -> Caps,
    pub cap_caps: fn(crate::SoundOwnerKey) -> Caps,
    pub hw_limits: fn(crate::SoundOwnerKey) -> HwLimits,
    /// Card-specific `SNDRV_PCM_INFO_*` bits (PAUSE, MMAP, …) ORed onto the
    /// core's transfer-model bits.
    pub info_flags: fn(crate::SoundOwnerKey) -> u32,
    pub period_bytes: fn(crate::SoundOwnerKey) -> usize,
    pub pcm_hw_params: fn(crate::SoundOwnerKey, u32, u32, u8, u32, u32) -> bool,
    pub pcm_prepare: fn(crate::SoundOwnerKey) -> bool,
    pub pcm_trigger: fn(crate::SoundOwnerKey, bool) -> bool,
    /// Suspend/resume the DMA engine without discarding the ring position.
    /// `None` from the core's perspective is expressed by returning `false`.
    pub pcm_pause: fn(crate::SoundOwnerKey, bool) -> bool,
    /// Play out what is already queued, then stop.
    pub pcm_drain: fn(crate::SoundOwnerKey) -> bool,
    /// Frames the hardware has consumed since prepare, when the card can
    /// report a real position; `None` leaves the core tracking `appl_ptr`.
    pub pcm_pointer: fn(crate::SoundOwnerKey) -> Option<u64>,
    pub pcm_hw_free: fn(crate::SoundOwnerKey) -> bool,
    pub pcm_submit: fn(crate::SoundOwnerKey, &[u8]) -> usize,
    pub cap_hw_params: fn(crate::SoundOwnerKey, u32, u32, u8, u32, u32) -> bool,
    pub cap_prepare: fn(crate::SoundOwnerKey) -> bool,
    pub cap_trigger: fn(crate::SoundOwnerKey, bool) -> bool,
    pub cap_pointer: fn(crate::SoundOwnerKey) -> Option<u64>,
    pub cap_hw_free: fn(crate::SoundOwnerKey) -> bool,
    pub pcm_recv: fn(crate::SoundOwnerKey, &mut [u8]) -> usize,
}

#[derive(Copy, Clone)]
struct OpsBinding {
    owner: crate::SoundOwnerKey,
    ops: &'static SoundOps,
}

static OPS: Spinlock<Vec<OpsBinding>, OpsLockClass> = Spinlock::new(Vec::new());

/// # C: O(cards)
pub fn register(owner: crate::SoundOwnerKey, ops: &'static SoundOps) -> bool {
    if crate::card_number(owner).is_none() {
        return false;
    }
    let mut guard = OPS.lock();
    if let Some(binding) = guard.iter_mut().find(|binding| binding.owner == owner) {
        binding.ops = ops;
    } else {
        guard.push(OpsBinding { owner, ops });
    }
    true
}

/// # C: O(cards)
pub fn clear(owner: crate::SoundOwnerKey) -> bool {
    let mut guard = OPS.lock();
    let before = guard.len();
    guard.retain(|binding| binding.owner != owner);
    DEVICE_OPS.lock().retain(|binding| binding.owner != owner);
    guard.len() != before
}

/// # C: O(cards)
pub fn ops_for(owner: crate::SoundOwnerKey) -> Option<&'static SoundOps> {
    OPS.lock()
        .iter()
        .find(|binding| binding.owner == owner && crate::card_number(owner).is_some())
        .map(|binding| binding.ops)
}

/// # C: O(cards)
pub fn ops() -> Option<&'static SoundOps> {
    ops_for(crate::owner()?)
}

/// # C: O(cards)
pub fn config() -> Option<(u32, u32, u32, u32)> {
    let owner = crate::owner()?;
    ops_for(owner).and_then(|ops| (ops.config)(owner))
}

/// # C: O(cards)
pub fn identity(owner: crate::SoundOwnerKey) -> Option<CardIdentity> {
    ops_for(owner).map(|ops| (ops.identity)(owner))
}

/// # C: O(cards)
pub fn pcm_caps(owner: crate::SoundOwnerKey) -> Caps {
    ops_for(owner).and_then(|ops| (ops.pcm_caps)(owner))
}

/// # C: O(cards)
pub fn cap_caps(owner: crate::SoundOwnerKey) -> Caps {
    ops_for(owner).and_then(|ops| (ops.cap_caps)(owner))
}

/// # C: O(cards)
pub fn hw_limits(owner: crate::SoundOwnerKey) -> Option<HwLimits> {
    ops_for(owner).map(|ops| (ops.hw_limits)(owner)).filter(|(period, buffer)| *period != 0 && *buffer != 0)
}

/// # C: O(cards)
pub fn info_flags(owner: crate::SoundOwnerKey) -> u32 {
    ops_for(owner).map(|ops| (ops.info_flags)(owner)).unwrap_or(0)
}

/// # C: O(cards)
pub fn period_bytes(owner: crate::SoundOwnerKey) -> Option<usize> {
    ops_for(owner).map(|ops| (ops.period_bytes)(owner)).filter(|bytes| *bytes != 0)
}

/// # C: O(cards)
pub fn pcm_hw_params(owner: crate::SoundOwnerKey, format: u32, rate_hz: u32, channels: u8, period_bytes: u32, buffer_bytes: u32) -> bool {
    ops_for(owner).map(|ops| (ops.pcm_hw_params)(owner, format, rate_hz, channels, period_bytes, buffer_bytes)).unwrap_or(false)
}

/// # C: O(cards)
pub fn pcm_prepare(owner: crate::SoundOwnerKey) -> bool {
    ops_for(owner).map(|ops| (ops.pcm_prepare)(owner)).unwrap_or(false)
}

/// # C: O(cards)
pub fn pcm_trigger(owner: crate::SoundOwnerKey, start: bool) -> bool {
    ops_for(owner).map(|ops| (ops.pcm_trigger)(owner, start)).unwrap_or(false)
}

/// # C: O(cards)
pub fn pcm_pause(owner: crate::SoundOwnerKey, pause: bool) -> bool {
    ops_for(owner).map(|ops| (ops.pcm_pause)(owner, pause)).unwrap_or(false)
}

/// # C: O(cards)
pub fn pcm_drain(owner: crate::SoundOwnerKey) -> bool {
    ops_for(owner).map(|ops| (ops.pcm_drain)(owner)).unwrap_or(false)
}

/// # C: O(cards)
pub fn pcm_pointer(owner: crate::SoundOwnerKey) -> Option<u64> {
    ops_for(owner).and_then(|ops| (ops.pcm_pointer)(owner))
}

/// # C: O(cards)
pub fn pcm_hw_free(owner: crate::SoundOwnerKey) -> bool {
    ops_for(owner).map(|ops| (ops.pcm_hw_free)(owner)).unwrap_or(false)
}

/// # C: O(cards)
pub fn pcm_submit(owner: crate::SoundOwnerKey, bytes: &[u8]) -> usize {
    ops_for(owner).map(|ops| (ops.pcm_submit)(owner, bytes)).unwrap_or(0)
}

/// # C: O(cards)
pub fn cap_hw_params(owner: crate::SoundOwnerKey, format: u32, rate_hz: u32, channels: u8, period_bytes: u32, buffer_bytes: u32) -> bool {
    ops_for(owner).map(|ops| (ops.cap_hw_params)(owner, format, rate_hz, channels, period_bytes, buffer_bytes)).unwrap_or(false)
}

/// # C: O(cards)
pub fn cap_prepare(owner: crate::SoundOwnerKey) -> bool {
    ops_for(owner).map(|ops| (ops.cap_prepare)(owner)).unwrap_or(false)
}

/// # C: O(cards)
pub fn cap_trigger(owner: crate::SoundOwnerKey, start: bool) -> bool {
    ops_for(owner).map(|ops| (ops.cap_trigger)(owner, start)).unwrap_or(false)
}

/// # C: O(cards)
pub fn cap_pointer(owner: crate::SoundOwnerKey) -> Option<u64> {
    ops_for(owner).and_then(|ops| (ops.cap_pointer)(owner))
}

/// # C: O(cards)
pub fn cap_hw_free(owner: crate::SoundOwnerKey) -> bool {
    ops_for(owner).map(|ops| (ops.cap_hw_free)(owner)).unwrap_or(false)
}

/// # C: O(cards)
pub fn pcm_recv(owner: crate::SoundOwnerKey, out: &mut [u8]) -> usize {
    ops_for(owner).map(|ops| (ops.pcm_recv)(owner, out)).unwrap_or(0)
}


/// Per-device PCM operations.  Linux keeps one `struct snd_pcm` and one
/// pair of stream callbacks for every device number on a card; this registry
/// carries that identity without changing legacy card-wide OSS callbacks.
pub struct PcmDeviceOps {
    pub pcm_devices: fn(crate::SoundOwnerKey) -> u32,
    pub pcm_caps: fn(crate::SoundOwnerKey, PcmDevice) -> Caps,
    pub cap_caps: fn(crate::SoundOwnerKey, PcmDevice) -> Caps,
    pub hw_limits: fn(crate::SoundOwnerKey, PcmDevice) -> HwLimits,
    pub info_flags: fn(crate::SoundOwnerKey, PcmDevice) -> u32,
    pub period_bytes: fn(crate::SoundOwnerKey, PcmDevice) -> usize,
    pub pcm_hw_params: fn(crate::SoundOwnerKey, PcmDevice, u32, u32, u8, u32, u32) -> bool,
    pub pcm_prepare: fn(crate::SoundOwnerKey, PcmDevice) -> bool,
    pub pcm_trigger: fn(crate::SoundOwnerKey, PcmDevice, bool) -> bool,
    pub pcm_pause: fn(crate::SoundOwnerKey, PcmDevice, bool) -> bool,
    pub pcm_drain: fn(crate::SoundOwnerKey, PcmDevice) -> bool,
    pub pcm_pointer: fn(crate::SoundOwnerKey, PcmDevice) -> Option<u64>,
    pub pcm_hw_free: fn(crate::SoundOwnerKey, PcmDevice) -> bool,
    pub pcm_submit: fn(crate::SoundOwnerKey, PcmDevice, &[u8]) -> usize,
    pub cap_hw_params: fn(crate::SoundOwnerKey, PcmDevice, u32, u32, u8, u32, u32) -> bool,
    pub cap_prepare: fn(crate::SoundOwnerKey, PcmDevice) -> bool,
    pub cap_trigger: fn(crate::SoundOwnerKey, PcmDevice, bool) -> bool,
    pub cap_pointer: fn(crate::SoundOwnerKey, PcmDevice) -> Option<u64>,
    pub cap_hw_free: fn(crate::SoundOwnerKey, PcmDevice) -> bool,
    pub pcm_recv: fn(crate::SoundOwnerKey, PcmDevice, &mut [u8]) -> usize,
}

#[derive(Copy, Clone)]
struct DeviceOpsBinding {
    owner: crate::SoundOwnerKey,
    ops: &'static PcmDeviceOps,
}

static DEVICE_OPS: Spinlock<Vec<DeviceOpsBinding>, OpsLockClass> = Spinlock::new(Vec::new());

/// Register the Linux-shaped per-card PCM device table after the card's
/// ordinary operations are installed. # C: O(cards)
pub fn register_pcm_devices(owner: crate::SoundOwnerKey, ops: &'static PcmDeviceOps) -> bool {
    let mut guard = DEVICE_OPS.lock();
    if let Some(binding) = guard.iter_mut().find(|binding| binding.owner == owner) {
        binding.ops = ops;
    } else {
        guard.push(DeviceOpsBinding { owner, ops });
    }
    true
}

fn device_ops(owner: crate::SoundOwnerKey) -> Option<&'static PcmDeviceOps> {
    DEVICE_OPS.lock().iter().find(|binding| binding.owner == owner).map(|binding| binding.ops)
}

pub fn pcm_devices(owner: crate::SoundOwnerKey) -> u32 {
    device_ops(owner).map(|ops| (ops.pcm_devices)(owner)).unwrap_or_else(|| u32::from(pcm_caps(owner).is_some() || cap_caps(owner).is_some()))
}

pub fn pcm_caps_for(owner: crate::SoundOwnerKey, device: PcmDevice) -> Caps {
    device_ops(owner).map(|ops| (ops.pcm_caps)(owner, device)).unwrap_or_else(|| if device == 0 { pcm_caps(owner) } else { None })
}

pub fn cap_caps_for(owner: crate::SoundOwnerKey, device: PcmDevice) -> Caps {
    device_ops(owner).map(|ops| (ops.cap_caps)(owner, device)).unwrap_or_else(|| if device == 0 { cap_caps(owner) } else { None })
}

pub fn hw_limits_for(owner: crate::SoundOwnerKey, device: PcmDevice) -> Option<HwLimits> {
    device_ops(owner).map(|ops| (ops.hw_limits)(owner, device)).or_else(|| if device == 0 { hw_limits(owner) } else { None })
        .filter(|(period, buffer)| *period != 0 && *buffer != 0)
}

pub fn info_flags_for(owner: crate::SoundOwnerKey, device: PcmDevice) -> u32 {
    device_ops(owner).map(|ops| (ops.info_flags)(owner, device)).unwrap_or_else(|| if device == 0 { info_flags(owner) } else { 0 })
}

pub fn period_bytes_for(owner: crate::SoundOwnerKey, device: PcmDevice) -> Option<usize> {
    device_ops(owner).map(|ops| (ops.period_bytes)(owner, device)).or_else(|| if device == 0 { period_bytes(owner) } else { None })
        .filter(|bytes| *bytes != 0)
}

pub fn pcm_hw_params_for(owner: crate::SoundOwnerKey, device: PcmDevice, format: u32, rate_hz: u32, channels: u8, period_bytes: u32, buffer_bytes: u32) -> bool {
    device_ops(owner).map(|ops| (ops.pcm_hw_params)(owner, device, format, rate_hz, channels, period_bytes, buffer_bytes))
        .unwrap_or_else(|| device == 0 && pcm_hw_params(owner, format, rate_hz, channels, period_bytes, buffer_bytes))
}

pub fn pcm_prepare_for(owner: crate::SoundOwnerKey, device: PcmDevice) -> bool {
    device_ops(owner).map(|ops| (ops.pcm_prepare)(owner, device)).unwrap_or_else(|| device == 0 && pcm_prepare(owner))
}

pub fn pcm_trigger_for(owner: crate::SoundOwnerKey, device: PcmDevice, start: bool) -> bool {
    device_ops(owner).map(|ops| (ops.pcm_trigger)(owner, device, start)).unwrap_or_else(|| device == 0 && pcm_trigger(owner, start))
}

pub fn pcm_pause_for(owner: crate::SoundOwnerKey, device: PcmDevice, pause: bool) -> bool {
    device_ops(owner).map(|ops| (ops.pcm_pause)(owner, device, pause)).unwrap_or_else(|| device == 0 && pcm_pause(owner, pause))
}

pub fn pcm_drain_for(owner: crate::SoundOwnerKey, device: PcmDevice) -> bool {
    device_ops(owner).map(|ops| (ops.pcm_drain)(owner, device)).unwrap_or_else(|| device == 0 && pcm_drain(owner))
}

pub fn pcm_pointer_for(owner: crate::SoundOwnerKey, device: PcmDevice) -> Option<u64> {
    device_ops(owner).and_then(|ops| (ops.pcm_pointer)(owner, device)).or_else(|| if device == 0 { pcm_pointer(owner) } else { None })
}

pub fn pcm_hw_free_for(owner: crate::SoundOwnerKey, device: PcmDevice) -> bool {
    device_ops(owner).map(|ops| (ops.pcm_hw_free)(owner, device)).unwrap_or_else(|| device == 0 && pcm_hw_free(owner))
}

pub fn pcm_submit_for(owner: crate::SoundOwnerKey, device: PcmDevice, bytes: &[u8]) -> usize {
    device_ops(owner).map(|ops| (ops.pcm_submit)(owner, device, bytes)).unwrap_or_else(|| if device == 0 { pcm_submit(owner, bytes) } else { 0 })
}

pub fn cap_hw_params_for(owner: crate::SoundOwnerKey, device: PcmDevice, format: u32, rate_hz: u32, channels: u8, period_bytes: u32, buffer_bytes: u32) -> bool {
    device_ops(owner).map(|ops| (ops.cap_hw_params)(owner, device, format, rate_hz, channels, period_bytes, buffer_bytes))
        .unwrap_or_else(|| device == 0 && cap_hw_params(owner, format, rate_hz, channels, period_bytes, buffer_bytes))
}

pub fn cap_prepare_for(owner: crate::SoundOwnerKey, device: PcmDevice) -> bool {
    device_ops(owner).map(|ops| (ops.cap_prepare)(owner, device)).unwrap_or_else(|| device == 0 && cap_prepare(owner))
}

pub fn cap_trigger_for(owner: crate::SoundOwnerKey, device: PcmDevice, start: bool) -> bool {
    device_ops(owner).map(|ops| (ops.cap_trigger)(owner, device, start)).unwrap_or_else(|| device == 0 && cap_trigger(owner, start))
}

pub fn cap_pointer_for(owner: crate::SoundOwnerKey, device: PcmDevice) -> Option<u64> {
    device_ops(owner).and_then(|ops| (ops.cap_pointer)(owner, device)).or_else(|| if device == 0 { cap_pointer(owner) } else { None })
}

pub fn cap_hw_free_for(owner: crate::SoundOwnerKey, device: PcmDevice) -> bool {
    device_ops(owner).map(|ops| (ops.cap_hw_free)(owner, device)).unwrap_or_else(|| device == 0 && cap_hw_free(owner))
}

pub fn pcm_recv_for(owner: crate::SoundOwnerKey, device: PcmDevice, out: &mut [u8]) -> usize {
    device_ops(owner).map(|ops| (ops.pcm_recv)(owner, device, out)).unwrap_or_else(|| if device == 0 { pcm_recv(owner, out) } else { 0 })
}
