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

/// Virtio device ID for sound devices.
pub const VIRTIO_ID_SOUND: u16 = 25;

type DeviceKey = virtio::VirtioChildDeviceKey;

fn sound_owner(device_key: DeviceKey) -> u32 {
    device_key.raw()
}

/// Driver-model identity for virtio-snd child binding.
pub const DRIVER_ID: virtio::VirtioChildDriverId =
    virtio::VirtioChildDriverId::new("virtio-snd", VIRTIO_ID_SOUND);

// Wire constants — virtio 1.2 §5.14 / docs/58§4.
/// CONTROLQ request: query the PCM stream table.
pub const VIRTIO_SND_R_PCM_INFO: u32 = 0x0100;
/// Control response status: success.
pub const VIRTIO_SND_S_OK: u32 = 0x8000;
/// PCM stream direction: guest→device (playback).
pub const VIRTIO_SND_D_OUTPUT: u8 = 0;
/// PCM stream direction: device→guest (capture).
pub const VIRTIO_SND_D_INPUT: u8 = 1;

// CONTROLQ PCM-stream lifecycle codes (docs/58§4.1).
const VIRTIO_SND_R_PCM_SET_PARAMS: u32 = 0x0101;
const VIRTIO_SND_R_PCM_PREPARE:    u32 = 0x0102;
const VIRTIO_SND_R_PCM_RELEASE:    u32 = 0x0103;
const VIRTIO_SND_R_PCM_START:      u32 = 0x0104;
const VIRTIO_SND_R_PCM_STOP:       u32 = 0x0105;

/// PCM sample format `VIRTIO_SND_PCM_FMT_S16` (docs/58§4.3).
pub const VIRTIO_SND_PCM_FMT_S16: u8 = 5;
/// PCM rate `VIRTIO_SND_PCM_RATE_44100` (docs/58§4.3).
pub const VIRTIO_SND_PCM_RATE_44100: u8 = 6;
/// Playback sample rate matching VIRTIO_SND_PCM_RATE_44100 (Hz).
const PLAYBACK_RATE_HZ: u32 = 44100;

/// sizeof(virtio_snd_pcm_info) on the wire (docs/58§4): hda_fn_nid(4)
/// features(4) formats(8) rates(8) direction(1) channels_min(1)
/// channels_max(1) padding[5] = 32 bytes. `direction` sits at byte 24.
const PCM_INFO_SIZE: usize = 32;
const PCM_INFO_DIR_OFF: usize = 24;
/// sizeof(virtio_snd_query_info): hdr(4) start_id(4) count(4) size(4).
const QUERY_INFO_SIZE: usize = 16;
/// sizeof(virtio_snd_hdr) — the status prefix in every control response.
const SND_HDR_SIZE: usize = 4;

/// Bounded spin budget for one CONTROLQ completion. QEMU retires control
/// requests near-instantly; generous headroom, matching the rng/blk style.
const CTL_POLL_BUDGET: u32 = 2_000_000;

/// TXQ completion poll budget. Each iteration forces a VM exit (device_status
/// read) so QEMU's audio timer can retire a buffer; the count therefore
/// bounds real wall-clock, not just spins. Generous so a period (≈23 ms at
/// 44.1 kHz / 2 KiB) retires even under TCG.
const TX_POLL_BUDGET: u32 = 4_000_000;
/// virtio_snd_event is 8 bytes: le32 event code + le32 data.
const EVENT_SIZE: usize = 8;
const MAX_EVENTQ_DESCS: u16 = (0x1000 / EVENT_SIZE) as u16;

/// Control scratch-frame layout: request at offset 0, response at 0x200
/// (leaves 0x200 for any request, 0xE00 for the response array).
const REQ_OFF: u64 = 0;
const RESP_OFF: u64 = 0x200;

const WANTED_FEATURES: u64 = virtio::VIRTIO_F_VERSION_1;

/// Feature policy for the virtio-snd child driver. The PCI transport executes
/// common-cfg negotiation; this driver owns the sound feature mask it is
/// prepared to consume.
pub const fn wanted_features() -> u64 {
    WANTED_FEATURES
}

/// Transport contract for the virtio-snd child driver. The virtio bus
/// consumes this profile; the PCI transport only executes it.
/// # C: O(1)
pub const fn transport_profile() -> virtio::VirtioTransportProfile {
    virtio::VirtioTransportProfile::snd(wanted_features(), None, Some(raise_event))
}

/// Persistent per-device CONTROLQ engine. PAs/VA reference the q0 ring the
/// boot probe already programmed. One in-flight control request at a time,
/// serialised by the `Spinlock` around the whole request body.
struct Ctx {
    /// Owning virtio child identity supplied by the transport bus.
    device_key: DeviceKey,
    controlq: virtio::VirtQueueResource,
    hhdm:     u64,
    /// virtio common-cfg MMIO window. A harmless read of device_status
    /// (@0x14) forces a VM exit so QEMU's audio-backend timer can retire
    /// TXQ buffers while we poll (TCG holds the BQL during tight spins).
    cfg_va:       u64,
    /// One 4 KiB frame split into request + response windows for control
    /// requests. Allocated once at install.
    scratch_pa:   u64,
    /// Driver-side avail.idx shadow (next ring slot to publish).
    avail_idx:    u16,
    /// EVENTQ(1) ring the transport programmed. Event draining lands in a
    /// later sound-event worker, but the queue resource is part of the
    /// installed virtio-snd device state rather than being ignored by the
    /// transport.
    eventq: Option<virtio::VirtQueueResource>,
    /// Driver-owned EVENTQ buffer frame, split into 8-byte event records.
    event_buf_pa: u64,
    /// EVENTQ driver-side last used.idx drained.
    event_last_used: u16,
    /// EVENTQ driver-side avail.idx shadow.
    event_avail_idx: u16,
    /// Number of EVENTQ records drained for this device.
    event_drained: u64,
    /// Last raw 8-byte virtio_snd_event drained for this device.
    event_last_raw: u64,
    /// virtio_snd_config (docs/58§4): jacks/streams/chmaps/controls.
    jacks:    u32,
    streams:  u32,
    chmaps:   u32,
    controls: u32,
    /// First OUTPUT stream id discovered by PCM_INFO (None if no playback
    /// stream). The default playback target for `beep`/`pcm_write`.
    out_stream: Option<u32>,
    /// OUTPUT stream capabilities harvested from PCM_INFO: supported
    /// `formats`/`rates` bitmasks (VIRTIO_SND_PCM_FMT_*/RATE_* bit indices)
    /// + channel range. Drive the ALSA `hw_params` refinement.
    out_formats: u64,
    out_rates:   u64,
    out_ch_min:  u8,
    out_ch_max:  u8,
    /// TXQ(2) ring the transport programmed.
    txq: Option<virtio::VirtQueueResource>,
    /// TXQ driver-side avail.idx shadow.
    tx_avail_idx: u16,
    /// Period payload frame (one 4 KiB page) the TXQ payload descriptor
    /// points at; refilled each `tx_period`.
    tx_buf_pa: u64,
    /// TXQ scratch: virtio_snd_pcm_xfer header (@0) + virtio_snd_pcm_status
    /// (@16). One 4 KiB page.
    tx_scratch_pa: u64,
    /// OUTPUT substream lifecycle state (the snd_pcm_ops state machine the
    /// ALSA core drives via hw_params/prepare/trigger).
    pcm_state: PcmState,
    /// Applied geometry (set by `pcm_hw_params`): rate/format are
    /// VIRTIO_SND_PCM_RATE_*/FMT_* enum values; bytes-per-frame derives from
    /// format×channels. `period_bytes` is the TXQ transfer unit.
    cfg_rate:     u8,
    cfg_format:   u8,
    cfg_channels: u8,
    cfg_period_bytes: u32,
    // ── capture (INPUT stream, RXQ) — mirrors the OUTPUT fields above ──
    /// First INPUT stream id from PCM_INFO (None if no capture stream).
    in_stream:  Option<u32>,
    in_formats: u64,
    in_rates:   u64,
    in_ch_min:  u8,
    in_ch_max:  u8,
    /// RXQ(3) ring the transport programmed.
    rxq: Option<virtio::VirtQueueResource>,
    rx_avail_idx: u16,
    /// RXQ payload frame (device writes captured PCM here) + scratch (xfer
    /// hdr @0 + status @16). One 4 KiB page each.
    rx_buf_pa:     u64,
    rx_scratch_pa: u64,
    cap_state: PcmState,
    cap_rate:     u8,
    cap_format:   u8,
    cap_channels: u8,
    cap_period_bytes: u32,
}

/// OUTPUT substream state (mirrors SNDRV_PCM_STATE_* the core exposes).
#[derive(PartialEq, Clone, Copy)]
pub enum PcmState { Idle, Configured, Prepared, Running }

// SAFETY justification: Ctx holds raw PAs/VAs into HHDM/MMIO stable for
// the device lifetime; all access is funneled through the CONTROLQ
// Spinlock, so cross-CPU sharing is sound.
static CTX: Spinlock<Vec<Ctx>, DriverLockClass> = Spinlock::new(Vec::new());

/// Aggregate EVENTQ records drained across installed virtio-snd devices.
/// Per-device accounting lives in each `Ctx`; this is a compatibility
/// diagnostic for old debug readers.
pub static DRAINED_EVENTS: AtomicU64 = AtomicU64::new(0);
/// Last raw 8-byte virtio_snd_event seen across all devices. Per-device last
/// event is exposed by `event_stats_for`.
pub static LAST_EVENT: AtomicU64 = AtomicU64::new(0);

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

/// Transport → driver handoff: the CONTROLQ/EVENTQ rings and optional PCM
/// rings the transport programmed.
pub struct SndInstall {
    pub device_key: DeviceKey,
    pub resources: virtio::VirtioResources,
}

#[derive(Clone, Copy)]
struct SndDeviceConfig {
    jacks: u32,
    streams: u32,
    chmaps: u32,
    controls: u32,
}

fn read_device_config(resources: virtio::VirtioResources) -> Option<SndDeviceConfig> {
    let cfg = resources.device_cfg_va;
    if cfg == 0 {
        return None;
    }
    // SAFETY: `device_cfg_va` is the transport-owned, Device-attr mapped
    // virtio-snd config window kept alive for this device lifetime. The config
    // layout is four little-endian u32 fields at offsets 0, 4, 8, and 12.
    let (jacks, streams, chmaps, controls) = unsafe {
        (
            core::ptr::read_volatile(cfg as *const u32),
            core::ptr::read_volatile((cfg + 4) as *const u32),
            core::ptr::read_volatile((cfg + 8) as *const u32),
            core::ptr::read_volatile((cfg + 12) as *const u32),
        )
    };
    Some(SndDeviceConfig { jacks, streams, chmaps, controls })
}

/// Probe result handed back for the boot line: total streams + the
/// OUTPUT/INPUT split discovered via VIRTIO_SND_R_PCM_INFO.
pub struct SndProbe {
    pub streams: u32,
    pub out:     u32,
    pub input:   u32,
}

struct SndProbeFrames {
    scratch_pa:    u64,
    event_buf_pa:  u64,
    tx_buf_pa:     u64,
    tx_scratch_pa: u64,
    rx_buf_pa:     u64,
    rx_scratch_pa: u64,
    owned:         bool,
}

impl SndProbeFrames {
    fn alloc(need_tx: bool, need_rx: bool) -> Option<Self> {
        let mut frames = Self {
            scratch_pa: 0,
            event_buf_pa: 0,
            tx_buf_pa: 0,
            tx_scratch_pa: 0,
            rx_buf_pa: 0,
            rx_scratch_pa: 0,
            owned: true,
        };
        frames.scratch_pa = pmm::setup::alloc_one_frame()?;
        frames.event_buf_pa = pmm::setup::alloc_one_frame()?;
        if need_tx {
            frames.tx_buf_pa = pmm::setup::alloc_one_frame()?;
            frames.tx_scratch_pa = pmm::setup::alloc_one_frame()?;
        }
        if need_rx {
            frames.rx_buf_pa = pmm::setup::alloc_one_frame()?;
            frames.rx_scratch_pa = pmm::setup::alloc_one_frame()?;
        }
        Some(frames)
    }

    fn all(&self) -> [u64; 6] {
        [
            self.scratch_pa,
            self.event_buf_pa,
            self.tx_buf_pa,
            self.tx_scratch_pa,
            self.rx_buf_pa,
            self.rx_scratch_pa,
        ]
    }

    fn disarm(&mut self) {
        self.owned = false;
    }
}

impl Drop for SndProbeFrames {
    fn drop(&mut self) {
        if self.owned {
            for pa in self.all() {
                free_frame(pa);
            }
        }
    }
}

/// True once a virtio-snd device has been brought up + installed.
/// # C: O(1)
pub fn present() -> bool { !CTX.lock().is_empty() }

/// True iff the named virtio-snd transport is installed.
/// # C: O(installed transports)
pub fn present_for(device_key: DeviceKey) -> bool {
    CTX.lock()
        .iter()
        .any(|ctx| ctx.device_key == device_key)
}

/// Snapshot of the harvested virtio_snd_config: `(jacks, streams, chmaps,
/// controls)`. None until a device is installed. Backs the ALSA card /
/// jack / control-element sizing under `/dev/snd/*`.
/// # C: O(1)
pub fn config(owner: u32) -> Option<(u32, u32, u32, u32)> {
    active_ctx_for(&CTX.lock(), owner).map(|c| (c.jacks, c.streams, c.chmaps, c.controls))
}

/// Snapshot of the installed EVENTQ resource:
/// `(queue_size, last_used_idx, next_avail_idx)`.
/// # C: O(1)
pub fn eventq_state() -> Option<(u16, u16, u16)> {
    active_ctx(&CTX.lock()).and_then(|ctx| {
        ctx.eventq
            .map(|eventq| (eventq.size, ctx.event_last_used, ctx.event_avail_idx))
    })
}

/// Snapshot of the named device's EVENTQ resource:
/// `(queue_size, last_used_idx, next_avail_idx)`.
/// # C: O(installed transports)
pub fn eventq_state_for(device_key: DeviceKey) -> Option<(u16, u16, u16)> {
    CTX.lock()
        .iter()
        .find(|ctx| ctx.device_key == device_key)
        .and_then(|ctx| {
            ctx.eventq
                .map(|eventq| (eventq.size, ctx.event_last_used, ctx.event_avail_idx))
        })
}

/// Per-device EVENTQ diagnostics: `(drained_count, last_raw_event)`.
/// # C: O(installed transports)
pub fn event_stats_for(device_key: DeviceKey) -> Option<(u64, u64)> {
    CTX.lock()
        .iter()
        .find(|ctx| ctx.device_key == device_key)
        .map(|ctx| (ctx.event_drained, ctx.event_last_raw))
}

struct SoundCardReservation {
    owner: u32,
    active: bool,
}

impl SoundCardReservation {
    fn reserve(owner: u32) -> Option<Self> {
        if !sound::reserve_card(owner) {
            return None;
        }
        Some(Self { owner, active: true })
    }

    fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for SoundCardReservation {
    fn drop(&mut self) {
        if self.active {
            let _ = sound::cancel_card_reservation(self.owner);
        }
    }
}

/// Install the virtio-snd queue state for one device. Called once after
/// DRIVER_OK + queue setup. Reads the device config, requires CONTROLQ and
/// EVENTQ, allocates the control scratch frame, then queries the PCM stream
/// table and returns the OUTPUT/INPUT stream split. Returns None if a required
/// ring PA / notify VA / config / HHDM is missing or no scratch frame is
/// available.
/// # C: O(streams) — one CONTROLQ round-trip
pub fn install(p: SndInstall) -> Option<SndProbe> {
    let controlq = p.resources.require_queue(0)?;
    let eventq = p.resources.require_queue(1)?;
    if !p.resources.common_cfg_valid() {
        return None;
    }
    let device_cfg = read_device_config(p.resources)?;
    let txq = p.resources.require_queue(2);
    let rxq = p.resources.require_queue(3);
    if CTX.lock().iter().any(|ctx| ctx.device_key == p.device_key) {
        return None;
    }
    let owner = sound_owner(p.device_key);
    let mut card_reservation = SoundCardReservation::reserve(owner)?;
    if eventq.size == 0 || eventq.size > MAX_EVENTQ_DESCS {
        return None;
    }
    let mut frames = SndProbeFrames::alloc(txq.is_some(), rxq.is_some())?;
    // Zero every freshly-allocated frame for deterministic state.
    for pa in frames.all() {
        if pa == 0 { continue; }
        let va = p.resources.hhdm.wrapping_add(pa) as *mut u8;
        // SAFETY: HHDM covers all RAM the PMM hands out; each frame is
        // freshly allocated and owned by this driver; aligned u8 stores span
        // only the 4 KiB page.
        unsafe { for i in 0..0x1000usize { core::ptr::write_volatile(va.add(i), 0); } }
    }
    // Seed avail.idx from the live used.idx so the first request waits for a
    // fresh completion rather than mistaking a stale idx for its own.
    let used = p.resources.hhdm.wrapping_add(controlq.device_pa) as *const u16;
    // SAFETY: HHDM-mapped queue-0 used ring programmed by the boot probe;
    // aligned u16 load of used.idx at u16 offset 1 in the device-owned frame.
    let used_seen = unsafe { core::ptr::read_volatile(used.add(1)) };
    let event_used = p.resources.hhdm.wrapping_add(eventq.device_pa) as *const u16;
    // SAFETY: HHDM-mapped EVENTQ used ring programmed by the boot probe;
    // aligned u16 load of used.idx at u16 offset 1.
    let event_used_seen = unsafe { core::ptr::read_volatile(event_used.add(1)) };
    let event_avail_idx = event_used_seen.wrapping_add(eventq.size);
    prepost_eventq(p.resources.hhdm, eventq, frames.event_buf_pa, event_avail_idx);
    // TXQ avail.idx seeds from its own used.idx likewise (0 if unprogrammed).
    let tx_used_seen = if let Some(txq) = txq {
        let txu = p.resources.hhdm.wrapping_add(txq.device_pa) as *const u16;
        // SAFETY: HHDM-mapped TXQ used ring programmed by the boot probe;
        // aligned u16 load of used.idx at u16 offset 1.
        unsafe { core::ptr::read_volatile(txu.add(1)) }
    } else { 0 };
    let rx_used_seen = if let Some(rxq) = rxq {
        let rxu = p.resources.hhdm.wrapping_add(rxq.device_pa) as *const u16;
        // SAFETY: HHDM-mapped RXQ used ring programmed by the boot probe;
        // aligned u16 load of used.idx at u16 offset 1.
        unsafe { core::ptr::read_volatile(rxu.add(1)) }
    } else { 0 };
    let mut g = CTX.lock();
    if g.iter().any(|ctx| ctx.device_key == p.device_key) {
        drop(g);
        return None;
    }
    g.push(Ctx {
        device_key: p.device_key,
        controlq,
        hhdm: p.resources.hhdm,
        cfg_va: p.resources.cfg_va,
        scratch_pa: frames.scratch_pa,
        avail_idx: used_seen,
        eventq: Some(eventq),
        event_buf_pa: frames.event_buf_pa,
        event_last_used: event_used_seen,
        event_avail_idx,
        event_drained: 0,
        event_last_raw: 0,
        jacks: device_cfg.jacks,
        streams: device_cfg.streams,
        chmaps: device_cfg.chmaps,
        controls: device_cfg.controls,
        out_stream: None,
        out_formats: 0, out_rates: 0, out_ch_min: 1, out_ch_max: 2,
        txq, tx_avail_idx: tx_used_seen,
        tx_buf_pa: frames.tx_buf_pa, tx_scratch_pa: frames.tx_scratch_pa,
        pcm_state: PcmState::Idle,
        cfg_rate: VIRTIO_SND_PCM_RATE_44100,
        cfg_format: VIRTIO_SND_PCM_FMT_S16,
        cfg_channels: 2,
        cfg_period_bytes: PERIOD_BYTES as u32,
        in_stream: None,
        in_formats: 0, in_rates: 0, in_ch_min: 1, in_ch_max: 2,
        rxq, rx_avail_idx: rx_used_seen,
        rx_buf_pa: frames.rx_buf_pa, rx_scratch_pa: frames.rx_scratch_pa,
        cap_state: PcmState::Idle,
        cap_rate: VIRTIO_SND_PCM_RATE_44100,
        cap_format: VIRTIO_SND_PCM_FMT_S16,
        cap_channels: 2,
        cap_period_bytes: PERIOD_BYTES as u32,
    });
    frames.disarm();
    drop(g);
    softirq::set_handler(softirq::Slot::SndEvent, event_softirq);
    let (out, input) = match pcm_info_scan(p.device_key) {
        Some(split) => split,
        None => {
            if let Some(ctx) = remove_ctx_and_release_event_handler(p.device_key) {
                stop_reset_free(ctx);
            }
            return None;
        }
    };
    if !sound::ops::register(owner, &SOUND_OPS) {
        let _ = uninstall(p.device_key);
        return None;
    }
    if !sound::register_card(owner) {
        let _ = uninstall(p.device_key);
        return None;
    }
    card_reservation.disarm();
    Some(SndProbe { streams: device_cfg.streams, out, input })
}

/// Stop streams, reset the virtio device, and release all queue/scratch frames
/// owned by the matching installed transport. # C: O(CONTROLQ)
pub fn uninstall(device_key: DeviceKey) -> bool {
    let Some(ctx) = remove_ctx_and_release_event_handler(device_key) else {
        return false;
    };
    let owner = sound_owner(device_key);
    if sound::unregister_card(owner) {
        let _ = sound::ops::clear(owner);
    }
    stop_reset_free(ctx);
    true
}

fn remove_ctx(device_key: DeviceKey) -> Option<(Ctx, bool)> {
    let mut guard = CTX.lock();
    let idx = guard.iter().position(|ctx| ctx.device_key == device_key)?;
    let ctx = guard.remove(idx);
    let empty_after = guard.is_empty();
    Some((ctx, empty_after))
}

fn active_ctx_mut(ctxs: &mut [Ctx]) -> Option<&mut Ctx> {
    let owner = sound::owner()?;
    active_ctx_mut_for(ctxs, owner)
}

fn active_ctx(ctxs: &[Ctx]) -> Option<&Ctx> {
    let owner = sound::owner()?;
    active_ctx_for(ctxs, owner)
}

fn active_ctx_mut_for(ctxs: &mut [Ctx], owner: u32) -> Option<&mut Ctx> {
    ctxs.iter_mut().find(|ctx| sound_owner(ctx.device_key) == owner)
}

fn active_ctx_for(ctxs: &[Ctx], owner: u32) -> Option<&Ctx> {
    ctxs.iter().find(|ctx| sound_owner(ctx.device_key) == owner)
}

/// Quiesce the installed virtio-snd transport for reboot/poweroff without
/// unregistering the sound card or clearing sound ops. Publication remains
/// visible for the terminal transition; subsequent ops see no live transport.
/// # C: O(CONTROLQ)
pub fn shutdown(device_key: DeviceKey) -> bool {
    let Some(ctx) = remove_ctx_and_release_event_handler(device_key) else {
        return false;
    };
    stop_reset_free(ctx);
    true
}

fn remove_ctx_and_release_event_handler(device_key: DeviceKey) -> Option<Ctx> {
    let (ctx, empty_after) = remove_ctx(device_key)?;
    if empty_after {
        let _ = softirq::clear_handler(softirq::Slot::SndEvent);
    }
    Some(ctx)
}

fn stop_reset_free(mut ctx: Ctx) {
    if let Some(stream) = ctx.out_stream {
        if ctx.pcm_state == PcmState::Running {
            let _ = pcm_ctl(&mut ctx, VIRTIO_SND_R_PCM_STOP, stream);
        }
        if ctx.pcm_state != PcmState::Idle {
            let _ = pcm_ctl(&mut ctx, VIRTIO_SND_R_PCM_RELEASE, stream);
        }
    }
    if let Some(stream) = ctx.in_stream {
        if ctx.cap_state == PcmState::Running {
            let _ = pcm_ctl(&mut ctx, VIRTIO_SND_R_PCM_STOP, stream);
        }
        if ctx.cap_state != PcmState::Idle {
            let _ = pcm_ctl(&mut ctx, VIRTIO_SND_R_PCM_RELEASE, stream);
        }
    }
    if ctx.cfg_va != 0 {
        // SAFETY: cfg_va is the mapped virtio common-cfg window captured at
        // probe; device_status is an 8-bit register at offset 0x14.
        unsafe { core::ptr::write_volatile((ctx.cfg_va + 0x14) as *mut u8, 0u8); }
    }
    free_frame(ctx.event_buf_pa);
    free_frame(ctx.rx_buf_pa);
    free_frame(ctx.rx_scratch_pa);
    free_frame(ctx.tx_buf_pa);
    free_frame(ctx.tx_scratch_pa);
    free_frame(ctx.scratch_pa);
}

fn prepost_eventq(
    hhdm: u64,
    eventq: virtio::VirtQueueResource,
    event_buf_pa: u64,
    avail_idx: u16,
) {
    let qsize = eventq.size as usize;
    let desc_va = hhdm.wrapping_add(eventq.desc_pa) as *mut u8;
    // SAFETY: HHDM-mapped EVENTQ descriptor table and driver ring were
    // programmed by the transport. qsize is bounded by MAX_EVENTQ_DESCS so the
    // event buffer frame and split ring frame writes stay in-bounds.
    unsafe {
        for i in 0..qsize {
            let entry_pa = event_buf_pa.wrapping_add((i as u64) * EVENT_SIZE as u64);
            let off = i * 16;
            core::ptr::write_volatile(desc_va.add(off) as *mut u64, entry_pa);
            core::ptr::write_volatile(desc_va.add(off + 8) as *mut u32, EVENT_SIZE as u32);
            core::ptr::write_volatile(
                desc_va.add(off + 12) as *mut u16,
                VRING_DESC_F_WRITE,
            );
            core::ptr::write_volatile(desc_va.add(off + 14) as *mut u16, 0u16);
        }
        let avail_va = hhdm.wrapping_add(eventq.driver_pa) as *mut u8;
        core::ptr::write_volatile(avail_va as *mut u16, 0u16);
        for i in 0..qsize {
            core::ptr::write_volatile(avail_va.add(4 + i * 2) as *mut u16, i as u16);
        }
        core::sync::atomic::fence(Ordering::Release);
        core::ptr::write_volatile(avail_va.add(2) as *mut u16, avail_idx);
        core::ptr::write_volatile(eventq.notify_va as *mut u16, eventq.index);
    }
}

/// Raise the sound EVENTQ bottom half from queue-1 MSI context.
/// # C: O(1)
pub fn raise_event() {
    softirq::raise(softirq::Slot::SndEvent);
}

fn event_softirq() {
    let mut g = CTX.lock();
    for ctx in g.iter_mut() {
        drain_eventq(ctx);
    }
}

fn drain_eventq(ctx: &mut Ctx) {
    let Some(eventq) = ctx.eventq else { return };
    let used_va = ctx.hhdm.wrapping_add(eventq.device_pa) as *mut u8;
    // SAFETY: HHDM-mapped EVENTQ used ring; aligned u16 load of used.idx.
    let dev_idx = unsafe { core::ptr::read_volatile(used_va.add(2) as *const u16) };
    if dev_idx == ctx.event_last_used {
        return;
    }

    while ctx.event_last_used != dev_idx {
        let i = (ctx.event_last_used as usize) % eventq.size as usize;
        let used_off = 4 + i * 8;
        // SAFETY: bounded used-ring read. EVENTQ size was validated at install.
        let desc_id = unsafe { core::ptr::read_volatile(used_va.add(used_off) as *const u32) }
            as u16;
        if desc_id < eventq.size {
            let event_pa = ctx
                .event_buf_pa
                .wrapping_add((desc_id as u64) * EVENT_SIZE as u64);
            let event_va = ctx.hhdm.wrapping_add(event_pa) as *const u64;
            // SAFETY: desc_id was range-checked and addresses one 8-byte
            // event record in the driver-owned EVENTQ buffer frame.
            let raw = unsafe { core::ptr::read_volatile(event_va) };
            record_event(ctx, raw);

            let avail_va = ctx.hhdm.wrapping_add(eventq.driver_pa) as *mut u8;
            let slot = (ctx.event_avail_idx as usize) % eventq.size as usize;
            // SAFETY: bounded write inside the EVENTQ avail ring.
            unsafe {
                core::ptr::write_volatile(avail_va.add(4 + slot * 2) as *mut u16, desc_id);
            }
            ctx.event_avail_idx = ctx.event_avail_idx.wrapping_add(1);
        }
        ctx.event_last_used = ctx.event_last_used.wrapping_add(1);
    }

    let avail_va = ctx.hhdm.wrapping_add(eventq.driver_pa) as *mut u8;
    // SAFETY: aligned avail.idx write and queue notify for the transport-owned
    // EVENTQ notify window.
    unsafe {
        core::sync::atomic::fence(Ordering::Release);
        core::ptr::write_volatile(avail_va.add(2) as *mut u16, ctx.event_avail_idx);
        core::ptr::write_volatile(eventq.notify_va as *mut u16, eventq.index);
    }
}

fn record_event(ctx: &mut Ctx, raw: u64) {
    ctx.event_last_raw = raw;
    ctx.event_drained = ctx.event_drained.wrapping_add(1);
    LAST_EVENT.store(raw, Ordering::Relaxed);
    DRAINED_EVENTS.fetch_add(1, Ordering::Relaxed);
}

fn free_frame(pa: u64) {
    if pa != 0 {
        // SAFETY: all callers pass child-owned buffer pages returned by
        // pmm::setup::alloc_one_frame and ensure each page is freed at most
        // once. Vring frames are transport-owned after successful probe and are
        // freed when the transport is unpublished.
        unsafe { pmm::setup::free_one_frame(pa); }
    }
}

/// Query the PCM stream table (VIRTIO_SND_R_PCM_INFO, start_id=0,
/// count=streams) and tally the OUTPUT/INPUT split by each entry's
/// `direction` byte. Returns None on transport/status error so probe can
/// reset the device and free child-owned DMA pages before publication.
/// # C: O(streams)
fn pcm_info_scan(device_key: DeviceKey) -> Option<(u32, u32)> {
    let mut g = CTX.lock();
    let ctx = g.iter_mut().find(|ctx| ctx.device_key == device_key)?;
    let count = ctx.streams;
    if count == 0 { return Some((0, 0)); }
    let h = ctx.hhdm;

    // Build virtio_snd_query_info at REQ_OFF.
    let req = h.wrapping_add(ctx.scratch_pa + REQ_OFF) as *mut u32;
    // SAFETY: HHDM-mapped scratch frame owned by this driver; four aligned
    // u32 stores within the request window build the query header.
    unsafe {
        core::ptr::write_volatile(req.add(0), VIRTIO_SND_R_PCM_INFO);
        core::ptr::write_volatile(req.add(1), 0);                     // start_id
        core::ptr::write_volatile(req.add(2), count);                 // count
        core::ptr::write_volatile(req.add(3), PCM_INFO_SIZE as u32);  // size
    }

    // Response = virtio_snd_hdr status + count × virtio_snd_pcm_info, capped
    // to the scratch frame.
    let want = SND_HDR_SIZE + count as usize * PCM_INFO_SIZE;
    let resp_len = want.min(0x1000 - RESP_OFF as usize);
    let status = match submit_ctl(ctx, QUERY_INFO_SIZE, resp_len) {
        Some(s) => s, None => return None,
    };
    if status != VIRTIO_SND_S_OK { return None; }

    // Tally direction across the entries that fit in the response window.
    let entries = ((resp_len - SND_HDR_SIZE) / PCM_INFO_SIZE).min(count as usize);
    let base = h.wrapping_add(ctx.scratch_pa + RESP_OFF + SND_HDR_SIZE as u64) as *const u8;
    let (mut out, mut input) = (0u32, 0u32);
    let mut first_out: Option<u32> = None;
    let mut first_in: Option<u32> = None;
    for i in 0..entries {
        let e = base.wrapping_add(i * PCM_INFO_SIZE);
        // u8 read of byte `off` within entry `e` of the device-filled
        // response window (bounded by entries < resp_len).
        let rd8 = |off: usize| -> u8 {
            // SAFETY: `e` is the HHDM-mapped response window the device just
            // filled; off < PCM_INFO_SIZE keeps the read inside this entry.
            unsafe { core::ptr::read_volatile(e.add(off)) }
        };
        let rd64 = |off: usize| -> u64 {
            let mut v = 0u64;
            for b in 0..8 { v |= (rd8(off + b) as u64) << (b * 8); }
            v
        };
        // formats@8 / rates@16 (le64), channels_min@25 / channels_max@26.
        if rd8(PCM_INFO_DIR_OFF) == VIRTIO_SND_D_INPUT {
            input += 1;
            if first_in.is_none() {
                first_in = Some(i as u32);
                ctx.in_formats = rd64(8);
                ctx.in_rates = rd64(16);
                ctx.in_ch_min = rd8(25).max(1);
                ctx.in_ch_max = rd8(26).max(ctx.in_ch_min);
            }
        } else {
            out += 1;
            if first_out.is_none() {
                first_out = Some(i as u32);
                ctx.out_formats = rd64(8);
                ctx.out_rates = rd64(16);
                ctx.out_ch_min = rd8(25).max(1);
                ctx.out_ch_max = rd8(26).max(ctx.out_ch_min);
            }
        }
    }
    ctx.out_stream = first_out;
    ctx.in_stream = first_in;
    Some((out, input))
}

/// Submit one CONTROLQ request/response pair: a 2-descriptor chain (req RO
/// + resp WO) onto q0, kick the device, poll the used ring for completion,
/// and return the response's leading virtio_snd_hdr status le32. The
/// request is read from scratch+REQ_OFF (`req_len` bytes); the device
/// writes `resp_len` bytes into scratch+RESP_OFF. None on poll timeout.
/// # C: O(CTL_POLL_BUDGET) per call
fn submit_ctl(ctx: &mut Ctx, req_len: usize, resp_len: usize) -> Option<u32> {
    let h = ctx.hhdm;
    let controlq = ctx.controlq;

    // Descriptor chain head at index 0: [0]=req (RO, NEXT→1), [1]=resp (WO).
    // Each virtq desc = 16 bytes = 2 u64: addr; then len|flags<<32|next<<48.
    let desc = h.wrapping_add(controlq.desc_pa) as *mut u64;
    // SAFETY: HHDM-mapped queue-0 descriptor table programmed by the boot
    // probe; four aligned u64 stores into the driver-owned ring frame build
    // a 2-descriptor chain over our owned scratch request/response windows.
    unsafe {
        core::ptr::write_volatile(desc.add(0), ctx.scratch_pa + REQ_OFF);
        let d0 = (req_len as u64)
               | ((VRING_DESC_F_NEXT as u64) << 32)
               | (1u64 << 48);
        core::ptr::write_volatile(desc.add(1), d0);
        core::ptr::write_volatile(desc.add(2), ctx.scratch_pa + RESP_OFF);
        let d1 = (resp_len as u64) | ((VRING_DESC_F_WRITE as u64) << 32);
        core::ptr::write_volatile(desc.add(3), d1);
    }

    // Publish to the avail ring: ring[slot]=0 (head desc index), bump idx.
    let slot = (ctx.avail_idx % controlq.size) as usize;
    let avail = h.wrapping_add(controlq.driver_pa) as *mut u16;
    // SAFETY: HHDM-mapped queue-0 avail ring; u16 stores at ring(2+slot)/
    // idx(1) within the driver-owned frame; slot bounded by controlq.size; the
    // Release fence publishes the descriptor writes before the idx bump.
    let target = unsafe {
        core::ptr::write_volatile(avail.add(2 + slot), 0u16);
        core::sync::atomic::fence(Ordering::Release);
        ctx.avail_idx = ctx.avail_idx.wrapping_add(1);
        core::ptr::write_volatile(avail.add(1), ctx.avail_idx);
        ctx.avail_idx
    };
    core::sync::atomic::fence(Ordering::Release);

    // Kick the device via the CONTROLQ notify register (queue index 0).
    // SAFETY: notify VA is the Device-attr MMIO window mapped by the boot
    // probe; an aligned u16 store of queue index 0 is the spec-defined kick.
    unsafe { core::ptr::write_volatile(controlq.notify_va as *mut u16, controlq.index); }

    // Poll the used ring until used.idx reaches our target (or budget).
    let used = h.wrapping_add(controlq.device_pa) as *const u16;
    let mut polls = 0u32;
    loop {
        // SAFETY: HHDM-mapped queue-0 used ring; aligned u16 load of used.idx
        // at u16 offset 1 within the device-owned frame.
        let uidx = unsafe { core::ptr::read_volatile(used.add(1)) };
        if uidx == target { break; }
        if polls >= CTL_POLL_BUDGET { return None; }
        polls += 1;
        core::hint::spin_loop();
    }
    // virtio 1.2 §2.7.13.2: acquire barrier after observing used.idx so the
    // device-written response status is not read ahead of the idx load.
    core::sync::atomic::fence(Ordering::Acquire);

    // Leading virtio_snd_hdr status (le32) of the response window.
    let st = h.wrapping_add(ctx.scratch_pa + RESP_OFF) as *const u32;
    // SAFETY: HHDM-mapped response window the device just wrote; aligned u32
    // load of the status header at RESP_OFF.
    Some(unsafe { core::ptr::read_volatile(st) })
}

// ── PCM playback (TXQ) ──────────────────────────────────────────────────
// docs/58§4 control reqs + §8 TXQ device operation. PR-C: enough to drive a
// tone end-to-end; ALSA/OSS substream plumbing (PR-D/PR-E) layers on top.

/// The default OUTPUT stream id, or None if no playback stream / not
/// installed. # C: O(1)
pub fn output_stream() -> Option<u32> { active_ctx(&CTX.lock()).and_then(|c| c.out_stream) }

/// Issue a simple `virtio_snd_pcm_hdr` control request (code + stream_id) on
/// the CONTROLQ — PREPARE / START / STOP / RELEASE. Returns the status le32.
/// # C: O(CONTROLQ round-trip)
fn pcm_ctl(ctx: &mut Ctx, code: u32, stream_id: u32) -> Option<u32> {
    let req = ctx.hhdm.wrapping_add(ctx.scratch_pa + REQ_OFF) as *mut u32;
    // SAFETY: HHDM-mapped scratch request window owned by this driver; two
    // aligned u32 stores build the 8-byte virtio_snd_pcm_hdr.
    unsafe {
        core::ptr::write_volatile(req.add(0), code);
        core::ptr::write_volatile(req.add(1), stream_id);
    }
    submit_ctl(ctx, 8, SND_HDR_SIZE)
}

/// `VIRTIO_SND_R_PCM_SET_PARAMS` on `stream_id`: 24-byte
/// virtio_snd_pcm_set_params (docs/58§4). Returns the status le32.
/// # C: O(CONTROLQ round-trip)
fn pcm_set_params(
    ctx: &mut Ctx, stream_id: u32, buffer_bytes: u32, period_bytes: u32,
    channels: u8, format: u8, rate: u8,
) -> Option<u32> {
    let base = ctx.hhdm.wrapping_add(ctx.scratch_pa + REQ_OFF);
    let w = base as *mut u32;
    let b = base as *mut u8;
    // SAFETY: HHDM-mapped scratch request window owned by this driver; the
    // u32 and u8 stores stay within the 24-byte set_params struct.
    unsafe {
        core::ptr::write_volatile(w.add(0), VIRTIO_SND_R_PCM_SET_PARAMS); // hdr.code
        core::ptr::write_volatile(w.add(1), stream_id);                   // hdr.stream_id
        core::ptr::write_volatile(w.add(2), buffer_bytes);
        core::ptr::write_volatile(w.add(3), period_bytes);
        core::ptr::write_volatile(w.add(4), 0u32);                        // features
        core::ptr::write_volatile(b.add(20), channels);
        core::ptr::write_volatile(b.add(21), format);
        core::ptr::write_volatile(b.add(22), rate);
        core::ptr::write_volatile(b.add(23), 0u8);                        // padding
    }
    submit_ctl(ctx, 24, SND_HDR_SIZE)
}

/// Push one PCM period (≤4 KiB) to the TXQ: a 3-descriptor chain
/// (virtio_snd_pcm_xfer hdr RO + payload RO + virtio_snd_pcm_status WO),
/// kick, poll the used ring. Returns true once the device retires it.
/// # C: O(TX_POLL_BUDGET)
fn tx_period(ctx: &mut Ctx, stream_id: u32, pcm: &[u8]) -> bool {
    let Some(txq) = ctx.txq else { return false };
    if ctx.tx_buf_pa == 0 || ctx.tx_scratch_pa == 0 { return false; }
    let h = ctx.hhdm;
    let n = pcm.len().min(0x1000);
    // xfer hdr (stream_id) at tx_scratch+0; copy payload into tx_buf.
    let xfer = h.wrapping_add(ctx.tx_scratch_pa) as *mut u32;
    let buf = h.wrapping_add(ctx.tx_buf_pa) as *mut u8;
    // SAFETY: HHDM-mapped driver-owned scratch + payload frames; the xfer u32
    // store and the n≤4 KiB payload copy stay within their 4 KiB pages.
    unsafe {
        core::ptr::write_volatile(xfer, stream_id);
        for i in 0..n { core::ptr::write_volatile(buf.add(i), pcm[i]); }
    }
    // 3-descriptor chain at TXQ desc index 0.
    let desc = h.wrapping_add(txq.desc_pa) as *mut u64;
    // SAFETY: HHDM-mapped TXQ descriptor table programmed by the boot probe;
    // six aligned u64 stores build a 3-descriptor chain over driver-owned
    // buffers (xfer hdr RO → payload RO → status WO).
    unsafe {
        core::ptr::write_volatile(desc.add(0), ctx.tx_scratch_pa);          // xfer hdr
        core::ptr::write_volatile(desc.add(1),
            4u64 | ((VRING_DESC_F_NEXT as u64) << 32) | (1u64 << 48));
        core::ptr::write_volatile(desc.add(2), ctx.tx_buf_pa);              // payload
        core::ptr::write_volatile(desc.add(3),
            (n as u64) | ((VRING_DESC_F_NEXT as u64) << 32) | (2u64 << 48));
        core::ptr::write_volatile(desc.add(4), ctx.tx_scratch_pa + 16);     // status
        core::ptr::write_volatile(desc.add(5),
            8u64 | ((VRING_DESC_F_WRITE as u64) << 32));
    }
    // Publish to TXQ avail + kick + poll used.
    let slot = (ctx.tx_avail_idx % txq.size) as usize;
    let avail = h.wrapping_add(txq.driver_pa) as *mut u16;
    // SAFETY: HHDM-mapped TXQ avail ring; u16 stores at ring(2+slot)/idx(1)
    // within the driver-owned frame; slot bounded by txq.size; Release fences
    // publish the descriptor chain before the idx bump.
    let target = unsafe {
        core::ptr::write_volatile(avail.add(2 + slot), 0u16);
        core::sync::atomic::fence(Ordering::Release);
        ctx.tx_avail_idx = ctx.tx_avail_idx.wrapping_add(1);
        core::ptr::write_volatile(avail.add(1), ctx.tx_avail_idx);
        ctx.tx_avail_idx
    };
    core::sync::atomic::fence(Ordering::Release);
    // Kick the device via the TXQ notify register (queue index 2).
    // SAFETY: notify VA is the Device-attr MMIO window mapped by the boot
    // probe; an aligned u16 store of queue index 2 is the spec-defined kick.
    unsafe { core::ptr::write_volatile(txq.notify_va as *mut u16, txq.index); }
    let used = h.wrapping_add(txq.device_pa) as *const u16;
    let mut polls = 0u32;
    loop {
        // SAFETY: HHDM-mapped TXQ used ring; aligned u16 load of used.idx.
        let uidx = unsafe { core::ptr::read_volatile(used.add(1)) };
        if uidx == target { return true; }
        if polls >= TX_POLL_BUDGET { return false; }
        // Unlike the synchronous CONTROLQ, virtio-sound retires a TXQ buffer
        // only when the audio backend consumes it (a QEMU timer). Under TCG
        // the vCPU holds the BQL during a tight spin, starving that timer —
        // so every iteration we read device_status (@0x14, read-only) to
        // force a VM exit, releasing the BQL so the backend can make progress.
        if ctx.cfg_va != 0 {
            // SAFETY: cfg_va is the Device-attr-mapped common-cfg window;
            // device_status is a u32 at +0x14; the read has no side effect.
            let _ = unsafe { core::ptr::read_volatile((ctx.cfg_va + 0x14) as *const u32) };
        }
        polls += 1;
        core::hint::spin_loop();
    }
}

/// Play a square-wave tone of `hz` Hz for `ms` ms on the default OUTPUT
/// stream: SET_PARAMS(S16 mono 44.1 kHz) → PREPARE → START → push period
/// buffers on the TXQ → STOP. Returns true on success. Backs the VT
/// `KIOCSOUND`/`KDMKTONE` beep (50§16) and a boot self-test under debug-boot.
/// # C: O((ms/period) × TXQ round-trip)
pub fn beep(hz: u32, ms: u32) -> bool { beep_diag(hz, ms) == 0 }

/// `beep` with a diagnostic step code: 0=ok, 1=not installed, 2=no OUTPUT
/// stream, 3=no TXQ, 4=SET_PARAMS rejected, 5=PREPARE rejected, 6=START
/// rejected, 7=TXQ transfer timeout. The code is the failing stage so the
/// boot self-test can pinpoint a lockstep gap.
/// # C: O((ms/period) × TXQ round-trip)
pub fn beep_diag(hz: u32, ms: u32) -> u8 {
    let mut g = CTX.lock();
    let ctx = match active_ctx_mut(&mut g) { Some(c) => c, None => return 1 };
    let stream = match ctx.out_stream { Some(s) => s, None => return 2 };
    if ctx.txq.is_none() { return 3; }

    // S16 mono @44.1 kHz; 2 KiB period, 4 KiB (2-period) buffer.
    if pcm_set_params(ctx, stream, (PERIOD_BYTES * 2) as u32, PERIOD_BYTES as u32,
        1, VIRTIO_SND_PCM_FMT_S16, VIRTIO_SND_PCM_RATE_44100) != Some(VIRTIO_SND_S_OK)
    {
        return 4;
    }
    if pcm_ctl(ctx, VIRTIO_SND_R_PCM_PREPARE, stream) != Some(VIRTIO_SND_S_OK) { return 5; }
    if pcm_ctl(ctx, VIRTIO_SND_R_PCM_START, stream) != Some(VIRTIO_SND_S_OK) { return 6; }

    // Synthesise the square wave into 2 KiB periods (1024 mono S16 samples)
    // and stream them. half = samples per half-cycle.
    let total = (PLAYBACK_RATE_HZ as u64 * ms as u64 / 1000) as usize;
    let half = if hz == 0 { 1 } else { (PLAYBACK_RATE_HZ / (2 * hz)).max(1) as usize };
    let mut buf = [0u8; PERIOD_BYTES];
    let mut s = 0usize;
    let mut ok = true;
    while s < total && ok {
        for k in 0..(PERIOD_BYTES / 2) {
            let amp: i16 = if ((s + k) / half) % 2 == 0 { 8000 } else { -8000 };
            let le = (amp as u16).to_le_bytes();
            buf[k * 2] = le[0];
            buf[k * 2 + 1] = le[1];
        }
        ok = tx_period(ctx, stream, &buf);
        s += PERIOD_BYTES / 2;
    }
    let _ = pcm_ctl(ctx, VIRTIO_SND_R_PCM_STOP, stream);
    let _ = pcm_ctl(ctx, VIRTIO_SND_R_PCM_RELEASE, stream);
    if ok { 0 } else { 7 }
}

// ── OUTPUT substream ops (the snd_pcm_ops the ALSA core drives) ─────────
//
// The `sound` crate (ALSA PCM core) owns the substream state machine +
// ring accounting + the SNDRV_PCM_IOCTL ABI; it calls these ops to apply
// hw params, prepare/free the device buffer, trigger start/stop, and
// transfer frames — exactly the snd_pcm_ops split in Linux ALSA. The OSS
// /dev/dsp emulation drives the same ops via the core.

const PERIOD_BYTES: usize = 2048;

/// Bytes per frame for a virtio_snd format enum × channel count. The
/// supported formats are 1-byte (µ-law/A-law/S8/U8) or 2-byte (S16/U16).
/// # C: O(1)
fn frame_bytes(format: u8, channels: u8) -> usize {
    let bps = match format {
        VIRTIO_SND_PCM_FMT_S16 | 6 /*U16*/ => 2,
        _ => 1,
    };
    bps * channels.max(1) as usize
}

/// OUTPUT-stream hw capabilities `(formats, rates, ch_min, ch_max)` harvested
/// from PCM_INFO — `formats`/`rates` are VIRTIO_SND_PCM_FMT_*/RATE_* bit
/// masks. Drive the ALSA `hw_params` refinement. None until installed.
/// # C: O(1)
pub fn pcm_caps(owner: u32) -> Option<(u64, u64, u8, u8)> {
    active_ctx_for(&CTX.lock(), owner).map(|c| (c.out_formats, c.out_rates, c.out_ch_min, c.out_ch_max))
}

/// Default period (fragment) size in bytes the TXQ transfers. # C: O(1)
pub fn period_bytes(_owner: u32) -> usize { PERIOD_BYTES }

/// `(installed, has_output_stream, has_txq)` — playback-readiness probe for
/// the core/self-test. # C: O(1)
pub fn playback_ready() -> (bool, bool, bool) {
    let g = CTX.lock();
    match active_ctx(&g) {
        Some(c) => (true, c.out_stream.is_some(), c.txq.is_some()),
        None => (false, false, false),
    }
}

/// Current OUTPUT substream state. # C: O(1)
pub fn pcm_state() -> PcmState {
    active_ctx(&CTX.lock()).map(|c| c.pcm_state).unwrap_or(PcmState::Idle)
}

/// Applied geometry `(rate, format, channels, period_bytes)` (enums), or
/// None if not installed. # C: O(1)
pub fn configured() -> Option<(u8, u8, u8, u32)> {
    active_ctx(&CTX.lock()).map(|c| (c.cfg_rate, c.cfg_format, c.cfg_channels, c.cfg_period_bytes))
}

/// Bytes per frame of the configured format × channels (frames↔bytes for
/// the core's appl_ptr/hw_ptr accounting). # C: O(1)
pub fn frame_size() -> usize {
    active_ctx(&CTX.lock()).map(|c| frame_bytes(c.cfg_format, c.cfg_channels)).unwrap_or(4)
}

/// snd_pcm_ops::hw_params — apply rate/format/channels + the period/buffer
/// geometry to the device (VIRTIO_SND_R_PCM_SET_PARAMS). rate/format are
/// VIRTIO_SND_PCM_RATE_*/FMT_* enums. → state Configured. # C: O(CONTROLQ)
pub fn pcm_hw_params(owner: u32, rate: u8, format: u8, channels: u8,
                     period_bytes: u32, buffer_bytes: u32) -> bool {
    let mut g = CTX.lock();
    let ctx = match active_ctx_mut_for(&mut g, owner) { Some(c) => c, None => return false };
    let stream = match ctx.out_stream { Some(s) => s, None => return false };
    let ch = channels.clamp(1, 2);
    // SET_PARAMS requires a released stream (spec §5.14): if a prior session
    // left it PREPARED/RUNNING, STOP+RELEASE first so re-config is robust.
    if ctx.pcm_state == PcmState::Prepared || ctx.pcm_state == PcmState::Running {
        let _ = pcm_ctl(ctx, VIRTIO_SND_R_PCM_STOP, stream);
        let _ = pcm_ctl(ctx, VIRTIO_SND_R_PCM_RELEASE, stream);
    }
    if pcm_set_params(ctx, stream, buffer_bytes, period_bytes, ch, format, rate)
        != Some(VIRTIO_SND_S_OK) { return false; }
    ctx.cfg_rate = rate;
    ctx.cfg_format = format;
    ctx.cfg_channels = ch;
    ctx.cfg_period_bytes = period_bytes.max(1).min(0x1000);
    ctx.pcm_state = PcmState::Configured;
    true
}

/// snd_pcm_ops::prepare — allocate the device buffer + ready the stream
/// (VIRTIO_SND_R_PCM_PREPARE). → state Prepared. # C: O(CONTROLQ)
pub fn pcm_prepare(owner: u32) -> bool {
    let mut g = CTX.lock();
    let ctx = match active_ctx_mut_for(&mut g, owner) { Some(c) => c, None => return false };
    if ctx.pcm_state == PcmState::Idle { return false; }
    let stream = match ctx.out_stream { Some(s) => s, None => return false };
    if pcm_ctl(ctx, VIRTIO_SND_R_PCM_PREPARE, stream) != Some(VIRTIO_SND_S_OK) { return false; }
    ctx.pcm_state = PcmState::Prepared;
    true
}

/// snd_pcm_ops::trigger — START (`start=true`) / STOP (`start=false`)
/// streaming. → state Running / Prepared. # C: O(CONTROLQ)
pub fn pcm_trigger(owner: u32, start: bool) -> bool {
    let mut g = CTX.lock();
    let ctx = match active_ctx_mut_for(&mut g, owner) { Some(c) => c, None => return false };
    let stream = match ctx.out_stream { Some(s) => s, None => return false };
    let code = if start { VIRTIO_SND_R_PCM_START } else { VIRTIO_SND_R_PCM_STOP };
    if pcm_ctl(ctx, code, stream) != Some(VIRTIO_SND_S_OK) { return false; }
    ctx.pcm_state = if start { PcmState::Running } else { PcmState::Prepared };
    true
}

/// snd_pcm_ops::hw_free — release the device buffer
/// (VIRTIO_SND_R_PCM_RELEASE). → state Idle. # C: O(CONTROLQ)
pub fn pcm_hw_free(owner: u32) -> bool {
    let mut g = CTX.lock();
    let ctx = match active_ctx_mut_for(&mut g, owner) { Some(c) => c, None => return false };
    if ctx.pcm_state == PcmState::Idle { return true; }
    let stream = match ctx.out_stream { Some(s) => s, None => return false };
    let _ = pcm_ctl(ctx, VIRTIO_SND_R_PCM_RELEASE, stream);
    ctx.pcm_state = PcmState::Idle;
    true
}

/// Transfer interleaved PCM frames to a Running OUTPUT stream — the
/// snd_pcm_ops transfer/ack: push the bytes as period-sized TXQ chains,
/// blocking until each is consumed. Returns bytes accepted (0 if not
/// Running / no device / TX timeout). # C: O(bytes/period × TXQ round-trip)
pub fn pcm_submit(owner: u32, bytes: &[u8]) -> usize {
    let mut g = CTX.lock();
    let ctx = match active_ctx_mut_for(&mut g, owner) { Some(c) => c, None => return 0 };
    if ctx.pcm_state != PcmState::Running { return 0; }
    let stream = match ctx.out_stream { Some(s) => s, None => return 0 };
    let chunk = (ctx.cfg_period_bytes as usize).max(1).min(0x1000);
    let mut off = 0usize;
    while off < bytes.len() {
        let n = (bytes.len() - off).min(chunk);
        if !tx_period(ctx, stream, &bytes[off..off + n]) { break; }
        off += n;
    }
    off
}

// ── INPUT substream ops (RXQ capture) — mirror of the OUTPUT ops ────────

/// Post one capture buffer to the RXQ: a 3-descriptor chain (virtio_snd_
/// pcm_xfer hdr RO + payload WO + virtio_snd_pcm_status WO), kick, poll the
/// used ring, then copy the captured PCM into `out`. Returns bytes captured
/// (the used-ring length minus the 8-byte status trailer). # C: O(TX_POLL_BUDGET)
fn rx_period(ctx: &mut Ctx, stream_id: u32, out: &mut [u8]) -> usize {
    let Some(rxq) = ctx.rxq else { return 0 };
    if ctx.rx_buf_pa == 0 || ctx.rx_scratch_pa == 0 { return 0; }
    let h = ctx.hhdm;
    let n = out.len().min(0x1000);
    let xfer = h.wrapping_add(ctx.rx_scratch_pa) as *mut u32;
    // SAFETY: HHDM-mapped driver-owned scratch frame; one aligned u32 store
    // writes the virtio_snd_pcm_xfer stream_id header.
    unsafe { core::ptr::write_volatile(xfer, stream_id); }
    let desc = h.wrapping_add(rxq.desc_pa) as *mut u64;
    // SAFETY: HHDM-mapped RXQ descriptor table programmed by the boot probe;
    // six aligned u64 stores build a 3-descriptor chain: xfer hdr RO →
    // payload WO (device fills) → status WO, over driver-owned frames.
    unsafe {
        core::ptr::write_volatile(desc.add(0), ctx.rx_scratch_pa);            // xfer hdr (RO)
        core::ptr::write_volatile(desc.add(1),
            4u64 | ((VRING_DESC_F_NEXT as u64) << 32) | (1u64 << 48));
        core::ptr::write_volatile(desc.add(2), ctx.rx_buf_pa);               // payload (WO)
        core::ptr::write_volatile(desc.add(3),
            (n as u64) | (((VRING_DESC_F_NEXT | VRING_DESC_F_WRITE) as u64) << 32) | (2u64 << 48));
        core::ptr::write_volatile(desc.add(4), ctx.rx_scratch_pa + 16);      // status (WO)
        core::ptr::write_volatile(desc.add(5),
            8u64 | ((VRING_DESC_F_WRITE as u64) << 32));
    }
    let slot = (ctx.rx_avail_idx % rxq.size) as usize;
    let avail = h.wrapping_add(rxq.driver_pa) as *mut u16;
    // SAFETY: HHDM-mapped RXQ avail ring; u16 stores at ring(2+slot)/idx(1)
    // within the driver-owned frame; slot bounded by rxq.size; Release fences
    // publish the descriptor chain before the idx bump.
    let target = unsafe {
        core::ptr::write_volatile(avail.add(2 + slot), 0u16);
        core::sync::atomic::fence(Ordering::Release);
        ctx.rx_avail_idx = ctx.rx_avail_idx.wrapping_add(1);
        core::ptr::write_volatile(avail.add(1), ctx.rx_avail_idx);
        ctx.rx_avail_idx
    };
    core::sync::atomic::fence(Ordering::Release);
    // Kick the device via the RXQ notify register (queue index 3).
    // SAFETY: notify VA is the Device-attr MMIO window mapped by the boot
    // probe; an aligned u16 store of queue index 3 is the spec-defined kick.
    unsafe { core::ptr::write_volatile(rxq.notify_va as *mut u16, rxq.index); }
    let used16 = h.wrapping_add(rxq.device_pa) as *const u16;
    let mut polls = 0u32;
    loop {
        // SAFETY: HHDM-mapped RXQ used ring; aligned u16 load of used.idx.
        let uidx = unsafe { core::ptr::read_volatile(used16.add(1)) };
        if uidx == target { break; }
        if polls >= TX_POLL_BUDGET { return 0; }
        // Same BQL-yield as TXQ: the device fills the RX buffer on its audio
        // timer; force a VM exit each spin so QEMU makes progress under TCG.
        if ctx.cfg_va != 0 {
            // SAFETY: cfg_va Device-attr common-cfg window; device_status @0x14
            // is a side-effect-free u32 read.
            let _ = unsafe { core::ptr::read_volatile((ctx.cfg_va + 0x14) as *const u32) };
        }
        polls += 1;
        core::hint::spin_loop();
    }
    // used ring elem: {id:u32, len:u32} at byte 4 + elem*8; len = bytes the
    // device wrote (payload + 8-byte status). Payload = len - 8.
    let elem = ((target.wrapping_sub(1)) % rxq.size) as usize;
    let used32 = h.wrapping_add(rxq.device_pa) as *const u32;
    // SAFETY: HHDM-mapped used ring; aligned u32 load of the completed elem's
    // len at u32 index 1 + elem*2 + 1; elem bounded by rxq.size.
    let used_len = unsafe { core::ptr::read_volatile(used32.add(1 + elem * 2 + 1)) } as usize;
    let payload = used_len.saturating_sub(8).min(n);
    let src = h.wrapping_add(ctx.rx_buf_pa) as *const u8;
    // SAFETY: HHDM-mapped RX payload frame the device just filled; bounded
    // read of `payload` ≤ n ≤ 4 KiB bytes.
    for i in 0..payload { out[i] = unsafe { core::ptr::read_volatile(src.add(i)) }; }
    payload
}

/// INPUT-stream hw capabilities `(formats, rates, ch_min, ch_max)`. None
/// until installed. # C: O(1)
pub fn cap_caps(owner: u32) -> Option<(u64, u64, u8, u8)> {
    active_ctx_for(&CTX.lock(), owner).map(|c| (c.in_formats, c.in_rates, c.in_ch_min, c.in_ch_max))
}

/// The default INPUT (capture) stream id, or None. # C: O(1)
pub fn input_stream() -> Option<u32> { active_ctx(&CTX.lock()).and_then(|c| c.in_stream) }

/// Current INPUT substream state. # C: O(1)
pub fn cap_state() -> PcmState {
    active_ctx(&CTX.lock()).map(|c| c.cap_state).unwrap_or(PcmState::Idle)
}

/// `(installed, has_input_stream, has_rxq)` capture-readiness probe. # C: O(1)
pub fn capture_ready() -> (bool, bool, bool) {
    let g = CTX.lock();
    match active_ctx(&g) {
        Some(c) => (true, c.in_stream.is_some(), c.rxq.is_some()),
        None => (false, false, false),
    }
}

/// Bytes per frame of the configured capture format × channels. # C: O(1)
pub fn cap_frame_size() -> usize {
    active_ctx(&CTX.lock()).map(|c| frame_bytes(c.cap_format, c.cap_channels)).unwrap_or(4)
}

/// snd_pcm_ops::hw_params for the INPUT stream (RELEASE-if-armed then
/// SET_PARAMS). → cap state Configured. # C: O(CONTROLQ)
pub fn cap_hw_params(owner: u32, rate: u8, format: u8, channels: u8,
                     period_bytes: u32, buffer_bytes: u32) -> bool {
    let mut g = CTX.lock();
    let ctx = match active_ctx_mut_for(&mut g, owner) { Some(c) => c, None => return false };
    let stream = match ctx.in_stream { Some(s) => s, None => return false };
    let ch = channels.clamp(1, 2);
    if ctx.cap_state == PcmState::Prepared || ctx.cap_state == PcmState::Running {
        let _ = pcm_ctl(ctx, VIRTIO_SND_R_PCM_STOP, stream);
        let _ = pcm_ctl(ctx, VIRTIO_SND_R_PCM_RELEASE, stream);
    }
    if pcm_set_params(ctx, stream, buffer_bytes, period_bytes, ch, format, rate)
        != Some(VIRTIO_SND_S_OK) { return false; }
    ctx.cap_rate = rate; ctx.cap_format = format; ctx.cap_channels = ch;
    ctx.cap_period_bytes = period_bytes.max(1).min(0x1000);
    ctx.cap_state = PcmState::Configured;
    true
}

/// snd_pcm_ops::prepare for the INPUT stream. → cap state Prepared. # C: O(CONTROLQ)
pub fn cap_prepare(owner: u32) -> bool {
    let mut g = CTX.lock();
    let ctx = match active_ctx_mut_for(&mut g, owner) { Some(c) => c, None => return false };
    if ctx.cap_state == PcmState::Idle { return false; }
    let stream = match ctx.in_stream { Some(s) => s, None => return false };
    if pcm_ctl(ctx, VIRTIO_SND_R_PCM_PREPARE, stream) != Some(VIRTIO_SND_S_OK) { return false; }
    ctx.cap_state = PcmState::Prepared;
    true
}

/// snd_pcm_ops::trigger for the INPUT stream. → Running / Prepared. # C: O(CONTROLQ)
pub fn cap_trigger(owner: u32, start: bool) -> bool {
    let mut g = CTX.lock();
    let ctx = match active_ctx_mut_for(&mut g, owner) { Some(c) => c, None => return false };
    let stream = match ctx.in_stream { Some(s) => s, None => return false };
    let code = if start { VIRTIO_SND_R_PCM_START } else { VIRTIO_SND_R_PCM_STOP };
    if pcm_ctl(ctx, code, stream) != Some(VIRTIO_SND_S_OK) { return false; }
    ctx.cap_state = if start { PcmState::Running } else { PcmState::Prepared };
    true
}

/// snd_pcm_ops::hw_free for the INPUT stream. → cap state Idle. # C: O(CONTROLQ)
pub fn cap_hw_free(owner: u32) -> bool {
    let mut g = CTX.lock();
    let ctx = match active_ctx_mut_for(&mut g, owner) { Some(c) => c, None => return false };
    if ctx.cap_state == PcmState::Idle { return true; }
    let stream = match ctx.in_stream { Some(s) => s, None => return false };
    let _ = pcm_ctl(ctx, VIRTIO_SND_R_PCM_RELEASE, stream);
    ctx.cap_state = PcmState::Idle;
    true
}

/// Capture interleaved PCM from a Running INPUT stream into `out` — the
/// snd_pcm_ops transfer for READI: post period-sized RXQ buffers, blocking
/// until each is filled. Returns bytes captured (0 if not Running / no
/// device / RX timeout). # C: O(bytes/period × RXQ round-trip)
pub fn pcm_recv(owner: u32, out: &mut [u8]) -> usize {
    let mut g = CTX.lock();
    let ctx = match active_ctx_mut_for(&mut g, owner) { Some(c) => c, None => return 0 };
    if ctx.cap_state != PcmState::Running { return 0; }
    let stream = match ctx.in_stream { Some(s) => s, None => return 0 };
    let chunk = (ctx.cap_period_bytes as usize).max(1).min(0x1000);
    let mut off = 0usize;
    while off < out.len() {
        let end = (off + chunk).min(out.len());
        let got = rx_period(ctx, stream, &mut out[off..end]);
        if got == 0 { break; }
        off += got;
    }
    off
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicU64;

    static TEST_LOCK: Spinlock<(), DriverLockClass> = Spinlock::new(());
    static TEST_EVENT_CALLS: AtomicU64 = AtomicU64::new(0);

    const fn key(raw: u32) -> DeviceKey {
        DeviceKey::from_raw(raw)
    }

    fn test_event_handler() {
        TEST_EVENT_CALLS.fetch_add(1, Ordering::Relaxed);
    }

    fn queue(index: u16) -> virtio::VirtQueueResource {
        virtio::VirtQueueResource {
            index,
            size: 8,
            desc_pa: 0,
            driver_pa: 0,
            device_pa: 0,
            notify_va: 0,
            notify_off: 0,
        }
    }

    fn ctx(device_key: DeviceKey) -> Ctx {
        Ctx {
            device_key,
            controlq: queue(0),
            hhdm: 0,
            cfg_va: 0,
            scratch_pa: 0,
            avail_idx: 0,
            eventq: Some(queue(1)),
            event_buf_pa: 0,
            event_last_used: 0,
            event_avail_idx: 0,
            event_drained: 0,
            event_last_raw: 0,
            jacks: 0,
            streams: 0,
            chmaps: 0,
            controls: 0,
            out_stream: None,
            out_formats: 0,
            out_rates: 0,
            out_ch_min: 1,
            out_ch_max: 2,
            txq: None,
            tx_avail_idx: 0,
            tx_buf_pa: 0,
            tx_scratch_pa: 0,
            pcm_state: PcmState::Idle,
            cfg_rate: VIRTIO_SND_PCM_RATE_44100,
            cfg_format: VIRTIO_SND_PCM_FMT_S16,
            cfg_channels: 2,
            cfg_period_bytes: PERIOD_BYTES as u32,
            in_stream: None,
            in_formats: 0,
            in_rates: 0,
            in_ch_min: 1,
            in_ch_max: 2,
            rxq: None,
            rx_avail_idx: 0,
            rx_buf_pa: 0,
            rx_scratch_pa: 0,
            cap_state: PcmState::Idle,
            cap_rate: VIRTIO_SND_PCM_RATE_44100,
            cap_format: VIRTIO_SND_PCM_FMT_S16,
            cap_channels: 2,
            cap_period_bytes: PERIOD_BYTES as u32,
        }
    }

    fn reset_test_state() {
        CTX.lock().clear();
        TEST_EVENT_CALLS.store(0, Ordering::Relaxed);
        DRAINED_EVENTS.store(0, Ordering::Relaxed);
        LAST_EVENT.store(0, Ordering::Relaxed);
        let _ = softirq::clear_handler(softirq::Slot::SndEvent);
    }

    #[test]
    fn event_stats_are_keyed_by_snd_context() {
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        {
            let mut ctxs = CTX.lock();
            ctxs.push(ctx(key(0x0010_0000)));
            ctxs.push(ctx(key(0x0020_0000)));
            record_event(&mut ctxs[0], 0xaaaa_0000_0000_0001);
            record_event(&mut ctxs[1], 0xbbbb_0000_0000_0002);
            record_event(&mut ctxs[1], 0xbbbb_0000_0000_0003);
        }

        assert_eq!(event_stats_for(key(0x0010_0000)), Some((1, 0xaaaa_0000_0000_0001)));
        assert_eq!(event_stats_for(key(0x0020_0000)), Some((2, 0xbbbb_0000_0000_0003)));
        assert_eq!(event_stats_for(key(0x0030_0000)), None);
        assert_eq!(DRAINED_EVENTS.load(Ordering::Relaxed), 3);
        assert_eq!(LAST_EVENT.load(Ordering::Relaxed), 0xbbbb_0000_0000_0003);
        assert_eq!(eventq_state_for(key(0x0010_0000)), Some((8, 0, 0)));
        assert_eq!(eventq_state_for(key(0x0020_0000)), Some((8, 0, 0)));
        reset_test_state();
    }

    #[test]
    fn removing_one_snd_context_keeps_event_softirq_installed() {
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        {
            let mut ctxs = CTX.lock();
            ctxs.push(ctx(key(0x0010_0000)));
            ctxs.push(ctx(key(0x0020_0000)));
        }
        softirq::set_handler(softirq::Slot::SndEvent, test_event_handler);

        let removed = remove_ctx_and_release_event_handler(key(0x0010_0000))
            .expect("expected first context removal");
        assert_eq!(removed.device_key, key(0x0010_0000));
        softirq::raise(softirq::Slot::SndEvent);
        // SAFETY: hosted unit test owns the SndEvent slot under TEST_LOCK.
        unsafe { softirq::run_pending(); }
        assert_eq!(TEST_EVENT_CALLS.load(Ordering::Relaxed), 1);
        assert!(present_for(key(0x0020_0000)));
        reset_test_state();
    }

    #[test]
    fn removing_last_snd_context_clears_event_softirq() {
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        CTX.lock().push(ctx(key(0x0010_0000)));
        softirq::set_handler(softirq::Slot::SndEvent, test_event_handler);

        let removed = remove_ctx_and_release_event_handler(key(0x0010_0000))
            .expect("expected last context removal");
        assert_eq!(removed.device_key, key(0x0010_0000));
        softirq::raise(softirq::Slot::SndEvent);
        // SAFETY: hosted unit test owns the SndEvent slot under TEST_LOCK.
        unsafe { softirq::run_pending(); }
        assert_eq!(TEST_EVENT_CALLS.load(Ordering::Relaxed), 0);
        assert!(!present());
        reset_test_state();
    }
}
