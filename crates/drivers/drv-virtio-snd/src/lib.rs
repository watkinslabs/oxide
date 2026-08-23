// Modern virtio-snd (sound) runtime driver. virtio-snd (PCI modern
// device-id 0x1059, virtio device class 25) exposes four virtqueues:
// CONTROLQ(0), EVENTQ(1), TXQ(2), RXQ(3) per docs/58§2. This module owns
// the CONTROLQ request/response engine and the device-config-driven probe
// (query the PCM stream table via VIRTIO_SND_R_PCM_INFO).
//
// The transport backend performs generic virtio bring-up (reset →
// ACK/DRIVER → feature negotiate → FEATURES_OK → queue PA program +
// DRIVER_OK), then hands persistent queue resources here via `install`.
// This driver reads virtio_snd_config itself and owns
// CONTROLQ/EVENTQ/TXQ/RXQ resource state.
//
// Arch-neutral: every op is MMIO (notify_cap window) + HHDM (ring +
// control scratch frame), mirroring drv-virtio-rng / drv-virtio-blk.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use sync::{Spinlock, TaskList as DriverLockClass};

pub const VIRTIO_ID_SOUND: u16 = 25;

type DeviceKey = virtio::VirtioChildDeviceKey;

fn sound_owner(device_key: DeviceKey) -> Option<sound::SoundOwnerKey> {
    sound::SoundOwnerKey::from_raw(device_key.raw())
}

pub const DRIVER_ID: virtio::VirtioChildDriverId =
    virtio::VirtioChildDriverId::new("virtio-snd", VIRTIO_ID_SOUND);

pub const VIRTIO_SND_R_PCM_INFO: u32 = 0x0100;
pub const VIRTIO_SND_S_OK: u32 = 0x8000;
pub const VIRTIO_SND_D_OUTPUT: u8 = 0;
pub const VIRTIO_SND_D_INPUT: u8 = 1;

const VIRTIO_SND_R_PCM_SET_PARAMS: u32 = 0x0101;
const VIRTIO_SND_R_PCM_PREPARE: u32 = 0x0102;
const VIRTIO_SND_R_PCM_RELEASE: u32 = 0x0103;
const VIRTIO_SND_R_PCM_START: u32 = 0x0104;
const VIRTIO_SND_R_PCM_STOP: u32 = 0x0105;

pub const VIRTIO_SND_PCM_FMT_S16: u8 = 5;
pub const VIRTIO_SND_PCM_FMT_U16: u8 = 6;
pub const VIRTIO_SND_PCM_RATE_44100: u8 = 6;
const PLAYBACK_RATE_HZ: u32 = 44100;

const PCM_INFO_SIZE: usize = 32;
const PCM_INFO_DIR_OFF: usize = 24;
const QUERY_INFO_SIZE: usize = 16;
const SND_HDR_SIZE: usize = 4;

const CTL_POLL_BUDGET: u32 = 2_000_000;
const TX_POLL_BUDGET: u32 = 4_000_000;
const EVENT_SIZE: usize = 8;
const SND_FRAME_BYTES: usize = hal::PAGE_SIZE_BYTES as usize;
/// Largest eventq the driver accepts: `prepost_eventq` writes one descriptor
/// per slot into a one-frame descriptor table AND one buffer per slot into a
/// one-frame event area, so the cap is whichever of the two runs out first.
const MAX_EVENTQ_DESCS: u16 = {
    let by_buffer = SND_FRAME_BYTES / EVENT_SIZE;
    let by_desc = SND_FRAME_BYTES / lifecycle::VIRTQ_DESC_ENTRY_BYTES;
    (if by_desc < by_buffer { by_desc } else { by_buffer }) as u16
};

const REQ_OFF: u64 = 0;
const RESP_OFF: u64 = 0x200;

/// `virtio_snd_pcm_xfer` header (stream_id) that opens a TX/RX chain.
const SND_XFER_HDR_BYTES: usize = 4;
/// `virtio_snd_pcm_status` the device writes back at the end of the chain.
const SND_XFER_STATUS_BYTES: usize = 8;
/// Where that status lands inside the TX/RX scratch frame.
const SND_XFER_STATUS_OFF: u64 = 16;

const WANTED_FEATURES: u64 = virtio::VIRTIO_F_VERSION_1;

pub const fn wanted_features() -> u64 {
    WANTED_FEATURES
}

pub const fn transport_profile() -> virtio::VirtioTransportProfile {
    virtio::VirtioTransportProfile::snd(wanted_features(), None, Some(raise_event)).with_ring_event_idx()
}

mod state;
use state::{
    active_ctx, active_ctx_for, active_ctx_mut, active_ctx_mut_for, free_frame, free_object_frame, Ctx,
    PcmState, SndDeviceConfig, SndProbe, SndProbeFrames, SoundCardReservation, CTX,
    DRAINED_EVENTS, LAST_EVENT,
};

mod control;
use control::{pcm_info_scan, submit_ctl};

mod event;
pub use event::raise_event;
#[cfg(test)]
use event::{event_softirq, record_event};

mod lifecycle;
pub use lifecycle::{
    config, eventq_state, eventq_state_for, event_stats_for, install, present, present_for,
    shutdown, uninstall,
};
pub use state::SndInstall;
#[cfg(test)]
use lifecycle::{remove_ctx_and_release_event_handler, stop_reset_free};
#[cfg(test)]
use state::{clear_freed_frames_for_tests, freed_frames_for_tests, remove_ctx, test_frame_pa};

mod fmt;

/// Identity reported through SNDRV_CTL_IOCTL_CARD_INFO. # C: O(1)
fn identity(_owner: sound::SoundOwnerKey) -> sound::CardIdentity {
    sound::CardIdentity::new(b"virtio-snd", b"virtio_snd", b"virtio-snd",
                             b"virtio sound card at virtio bus", b"virtio-snd", b"",
                             b"virtio-snd PCM")
}

/// The TXQ/RXQ path stages one frame-sized period at a time and double
/// buffers it. # C: O(1)
fn hw_limits(_owner: sound::SoundOwnerKey) -> sound::ops::HwLimits {
    // The persistent TX/RX DMA area is one PMM frame.  Linux's virtio-snd
    // runtime area may span many pages; this driver deliberately advertises
    // the exact area it can retain and map until the transport grows a
    // multi-page message pool.
    (SND_FRAME_BYTES as u32, SND_FRAME_BYTES as u32)
}

/// Blocking submit/receive only: no pause, no mmap. # C: O(1)
fn info_flags(_owner: sound::SoundOwnerKey) -> u32 { 0 }

fn pcm_devices(_owner: sound::SoundOwnerKey) -> u32 { 1 }
fn pcm_caps_for(owner: sound::SoundOwnerKey, _device: sound::ops::PcmDevice) -> sound::ops::Caps { pcm_caps(owner) }
fn cap_caps_for(owner: sound::SoundOwnerKey, _device: sound::ops::PcmDevice) -> sound::ops::Caps { cap_caps(owner) }
fn hw_limits_for(owner: sound::SoundOwnerKey, _device: sound::ops::PcmDevice) -> sound::ops::HwLimits { hw_limits(owner) }
fn info_flags_for(_owner: sound::SoundOwnerKey, _device: sound::ops::PcmDevice) -> u32 {
    sound::uapi::PCM_INFO_MMAP | sound::uapi::PCM_INFO_MMAP_VALID
}
fn period_bytes_for(owner: sound::SoundOwnerKey, _device: sound::ops::PcmDevice) -> usize { period_bytes(owner) }
fn pcm_hw_params_for(owner: sound::SoundOwnerKey, _device: sound::ops::PcmDevice, f: u32, r: u32, c: u8, p: u32, b: u32) -> bool { pcm_hw_params(owner, f, r, c, p, b) }
fn pcm_prepare_for(owner: sound::SoundOwnerKey, _device: sound::ops::PcmDevice) -> bool { pcm_prepare(owner) }
fn pcm_trigger_for(owner: sound::SoundOwnerKey, _device: sound::ops::PcmDevice, start: bool) -> bool { pcm_trigger(owner, start) }
fn pcm_pause_for(_owner: sound::SoundOwnerKey, _device: sound::ops::PcmDevice, _pause: bool) -> bool { false }
fn pcm_drain_for(_owner: sound::SoundOwnerKey, _device: sound::ops::PcmDevice) -> bool { true }
fn pcm_pointer_for(_owner: sound::SoundOwnerKey, _device: sound::ops::PcmDevice) -> Option<u64> { None }
fn pcm_hw_free_for(owner: sound::SoundOwnerKey, _device: sound::ops::PcmDevice) -> bool { pcm_hw_free(owner) }
fn pcm_submit_for(owner: sound::SoundOwnerKey, _device: sound::ops::PcmDevice, bytes: &[u8]) -> usize { pcm_submit(owner, bytes) }
fn cap_hw_params_for(owner: sound::SoundOwnerKey, _device: sound::ops::PcmDevice, f: u32, r: u32, c: u8, p: u32, b: u32) -> bool { cap_hw_params(owner, f, r, c, p, b) }
fn cap_prepare_for(owner: sound::SoundOwnerKey, _device: sound::ops::PcmDevice) -> bool { cap_prepare(owner) }
fn cap_trigger_for(owner: sound::SoundOwnerKey, _device: sound::ops::PcmDevice, start: bool) -> bool { cap_trigger(owner, start) }
fn cap_pointer_for(_owner: sound::SoundOwnerKey, _device: sound::ops::PcmDevice) -> Option<u64> { None }
fn cap_hw_free_for(owner: sound::SoundOwnerKey, _device: sound::ops::PcmDevice) -> bool { cap_hw_free(owner) }
fn pcm_recv_for(owner: sound::SoundOwnerKey, _device: sound::ops::PcmDevice, out: &mut [u8]) -> usize { pcm_recv(owner, out) }

fn pcm_mmap_frame(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice, capture: bool, offset: u64) -> Option<u64> {
    if device != 0 || offset & (hal::PAGE_SIZE_BYTES - 1) != 0 || offset >= SND_FRAME_BYTES as u64 { return None; }
    let g = CTX.lock_bh::<crate::state::SndBh>();
    let ctx = active_ctx_for(&g, owner)?;
    let state = if capture { ctx.cap_state } else { ctx.pcm_state };
    if state == PcmState::Idle { return None; }
    let pa = if capture { ctx.rx_buf_pa } else { ctx.tx_buf_pa };
    (pa != 0).then_some(pa)
}

fn pcm_mmap_commit(owner: sound::SoundOwnerKey, device: sound::ops::PcmDevice, capture: bool,
                   appl: u64, hw: u64, frame_bytes: u32, buffer_frames: u32) -> Option<u64> {
    if device != 0 || frame_bytes == 0 || buffer_frames == 0
        || (frame_bytes as u64).checked_mul(buffer_frames as u64)? > SND_FRAME_BYTES as u64 {
        return None;
    }
    if capture { pcm::mmap_capture_commit(owner, appl, hw, frame_bytes, buffer_frames) }
    else { pcm::mmap_playback_commit(owner, appl, hw, frame_bytes, buffer_frames) }
}

static PCM_DEVICE_OPS: sound::ops::PcmDeviceOps = sound::ops::PcmDeviceOps {
    pcm_devices, pcm_caps: pcm_caps_for, cap_caps: cap_caps_for, hw_limits: hw_limits_for,
    info_flags: info_flags_for, period_bytes: period_bytes_for,
    pcm_hw_params: pcm_hw_params_for, pcm_prepare: pcm_prepare_for, pcm_trigger: pcm_trigger_for,
    pcm_pause: pcm_pause_for, pcm_drain: pcm_drain_for, pcm_pointer: pcm_pointer_for,
    pcm_hw_free: pcm_hw_free_for, pcm_submit: pcm_submit_for,
    cap_hw_params: cap_hw_params_for, cap_prepare: cap_prepare_for, cap_trigger: cap_trigger_for,
    cap_pointer: cap_pointer_for, cap_hw_free: cap_hw_free_for, pcm_recv: pcm_recv_for,
    pcm_mmap_frame, pcm_mmap_commit,
};

fn pcm_pause(_owner: sound::SoundOwnerKey, _pause: bool) -> bool { false }

/// Every submitted period has already been handed to the device and
/// acknowledged, so a drain has nothing left to wait for. # C: O(1)
fn pcm_drain(_owner: sound::SoundOwnerKey) -> bool { true }

/// The device reports no independent DMA position; the core's own accounting
/// over the acknowledged periods is the truthful answer. # C: O(1)
fn no_pointer(_owner: sound::SoundOwnerKey) -> Option<u64> { None }

static SOUND_OPS: sound::ops::SoundOps = sound::ops::SoundOps {
    identity,
    hw_limits,
    info_flags,
    pcm_pause,
    pcm_drain,
    pcm_pointer: no_pointer,
    cap_pointer: no_pointer,
    config,
    pcm_caps,
    cap_caps,
    period_bytes,
    pcm_hw_params,
    pcm_prepare,
    pcm_trigger,
    pcm_hw_free,
    pcm_submit,
    cap_hw_params,
    cap_prepare,
    cap_trigger,
    cap_hw_free,
    pcm_recv,
};

mod pcm;
pub use pcm::{
    beep, beep_diag, cap_caps, cap_frame_size, cap_hw_free, cap_hw_params, cap_prepare,
    cap_state, cap_trigger, capture_ready, configured, frame_size, input_stream, output_stream,
    pcm_caps, pcm_hw_free, pcm_hw_params, pcm_prepare, pcm_recv, pcm_state, pcm_submit,
    pcm_trigger, period_bytes, playback_ready,
};
use pcm::{pcm_ctl, PERIOD_BYTES};

#[cfg(test)]
mod tests;
