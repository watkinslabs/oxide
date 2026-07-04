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
/// PCM sample format `VIRTIO_SND_PCM_FMT_U16` (docs/58§4.3).
pub const VIRTIO_SND_PCM_FMT_U16: u8 = 6;
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
/// # C: O(1)
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
    let owner = sound_owner(device_key);
    let card_removed = sound::unregister_card(owner);
    let ops_removed = sound::ops::clear(owner);
    let Some(ctx) = remove_ctx_and_release_event_handler(device_key) else {
        return card_removed || ops_removed;
    };
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
