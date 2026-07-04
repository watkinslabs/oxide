// Modern virtio-snd (sound) runtime driver. virtio-snd (PCI modern
// device-id 0x1059, virtio device class 25) exposes four virtqueues:
// CONTROLQ(0), EVENTQ(1), TXQ(2), RXQ(3) per docs/58§2. This module owns
// the CONTROLQ request/response engine and the device-config-driven probe
// (query the PCM stream table via VIRTIO_SND_R_PCM_INFO).
//
// The boot probe in `pci_boot::virtio_drv` performs the generic virtio
// bring-up (reset → ACK/DRIVER → feature negotiate → FEATURES_OK → q0
// desc/driver/device PA program + DRIVER_OK), then hands persistent queue
// resources here via `install`. This driver reads virtio_snd_config itself
// and owns CONTROLQ/EVENTQ/TXQ/RXQ resource state.
//
// Arch-neutral: every op is MMIO (notify_cap window) + HHDM (ring +
// control scratch frame), mirroring drv-virtio-rng / drv-virtio-blk.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use sync::{Spinlock, TaskList as DriverLockClass};
use virtio::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};

pub const VIRTIO_ID_SOUND: u16 = 25;

type DeviceKey = virtio::VirtioChildDeviceKey;

fn sound_owner(device_key: DeviceKey) -> u32 {
    device_key.raw()
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
const MAX_EVENTQ_DESCS: u16 = (0x1000 / EVENT_SIZE) as u16;

const REQ_OFF: u64 = 0;
const RESP_OFF: u64 = 0x200;

const WANTED_FEATURES: u64 = virtio::VIRTIO_F_VERSION_1;

pub const fn wanted_features() -> u64 {
    WANTED_FEATURES
}

pub const fn transport_profile() -> virtio::VirtioTransportProfile {
    virtio::VirtioTransportProfile::snd(wanted_features(), None, Some(raise_event))
}

mod state;
use state::{
    active_ctx, active_ctx_for, active_ctx_mut, active_ctx_mut_for, free_frame, Ctx,
    PcmState, SndDeviceConfig, SndInstall, SndProbe, SndProbeFrames, SoundCardReservation, CTX,
    DRAINED_EVENTS, LAST_EVENT,
};

mod control;
use control::{pcm_info_scan, submit_ctl};

mod event;
pub use event::raise_event;
#[cfg(test)]
use event::record_event;

mod lifecycle;
pub use lifecycle::{
    config, eventq_state, eventq_state_for, event_stats_for, install, present, present_for,
    shutdown, uninstall,
};
#[cfg(test)]
use lifecycle::remove_ctx_and_release_event_handler;
#[cfg(test)]
use state::remove_ctx;

static SOUND_OPS: sound::ops::SoundOps = sound::ops::SoundOps {
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
