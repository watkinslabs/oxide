use super::*;
use super::event::event_softirq;
use super::state::remove_ctx;

const SND_CFG_JACKS_OFF: u64 = 0;
const SND_CFG_STREAMS_OFF: u64 = 4;
const SND_CFG_CHMAPS_OFF: u64 = 8;
const SND_CFG_CONTROLS_OFF: u64 = 12;
pub(super) const VIRTQ_DESC_ENTRY_BYTES: usize = 16;

pub(super) fn read_device_config(resources: virtio::VirtioResources) -> Option<SndDeviceConfig> {
    let cfg = resources.device_cfg_va;
    if cfg == 0 {
        return None;
    }
    // SAFETY: `device_cfg_va` is the Device-attr virtio_snd_config window the
    // transport mapped for this child (rejected as 0 above); the four counts
    // are aligned u32 fields at the head of that window.
    let (jacks, streams, chmaps, controls) = unsafe {
        (
            core::ptr::read_volatile((cfg + SND_CFG_JACKS_OFF) as *const u32),
            core::ptr::read_volatile((cfg + SND_CFG_STREAMS_OFF) as *const u32),
            core::ptr::read_volatile((cfg + SND_CFG_CHMAPS_OFF) as *const u32),
            core::ptr::read_volatile((cfg + SND_CFG_CONTROLS_OFF) as *const u32),
        )
    };
    Some(SndDeviceConfig { jacks, streams, chmaps, controls })
}

pub fn present() -> bool { !CTX.lock_bh::<crate::state::SndBh>().is_empty() }

pub fn present_for(device_key: DeviceKey) -> bool {
    CTX.lock_bh::<crate::state::SndBh>().iter().any(|ctx| ctx.device_key == device_key)
}

pub fn config(owner: sound::SoundOwnerKey) -> Option<(u32, u32, u32, u32)> {
    active_ctx_for(&CTX.lock_bh::<crate::state::SndBh>(), owner).map(|c| (c.jacks, c.streams, c.chmaps, c.controls))
}

pub fn eventq_state() -> Option<(u16, u16, u16)> {
    active_ctx(&CTX.lock_bh::<crate::state::SndBh>()).and_then(|ctx| {
        ctx.eventq.as_ref().map(|eventq| (eventq.resource().size, eventq.used_seen(), eventq.avail_idx()))
    })
}

pub fn eventq_state_for(device_key: DeviceKey) -> Option<(u16, u16, u16)> {
    CTX.lock_bh::<crate::state::SndBh>()
        .iter()
        .find(|ctx| ctx.device_key == device_key)
        .and_then(|ctx| ctx.eventq.as_ref().map(|eventq| (eventq.resource().size, eventq.used_seen(), eventq.avail_idx())))
}

pub fn event_stats_for(device_key: DeviceKey) -> Option<(u64, u64)> {
    CTX.lock_bh::<crate::state::SndBh>()
        .iter()
        .find(|ctx| ctx.device_key == device_key)
        .map(|ctx| (ctx.event_drained, ctx.event_last_raw))
}

pub fn install(p: SndInstall) -> Option<SndProbe> {
    let controlq = p.resources.require_queue_at_least(0, 2)?;
    let eventq = p.resources.require_queue(1)?;
    if !p.resources.common_cfg_valid() {
        return None;
    }
    let device_cfg = read_device_config(p.resources)?;
    let txq = p.resources.require_queue_at_least(2, 3);
    let rxq = p.resources.require_queue_at_least(3, 3);
    if CTX.lock_bh::<crate::state::SndBh>().iter().any(|ctx| ctx.device_key == p.device_key) {
        return None;
    }
    let owner = sound_owner(p.device_key)?;
    let mut card_reservation = SoundCardReservation::reserve(owner)?;
    if eventq.size == 0 || eventq.size > MAX_EVENTQ_DESCS {
        return None;
    }
    let mut frames = SndProbeFrames::alloc(txq.is_some(), rxq.is_some())?;
    for pa in frames.all() {
        if pa == 0 {
            continue;
        }
        let va = p.resources.hhdm.wrapping_add(pa) as *mut u8;
        // SAFETY: HHDM view of a frame `SndProbeFrames::alloc` just took from
        // the PMM, still owned solely by this probe and named by no descriptor
        // yet; the loop clears exactly the one frame that was allocated.
        unsafe { for i in 0..SND_FRAME_BYTES { core::ptr::write_volatile(va.add(i), 0); } }
    }
    let controlq = virtio::VirtioSplitQueue::new_with_features(
        controlq, p.resources.hhdm, p.resources.drv_features,
    ).ok()?;
    let mut eventq = virtio::VirtioSplitQueue::new_with_features(
        eventq, p.resources.hhdm, p.resources.drv_features,
    ).ok()?;
    let txq = txq.map(|queue| virtio::VirtioSplitQueue::new_with_features(
        queue, p.resources.hhdm, p.resources.drv_features,
    )).transpose().ok()?;
    let rxq = rxq.map(|queue| virtio::VirtioSplitQueue::new_with_features(
        queue, p.resources.hhdm, p.resources.drv_features,
    )).transpose().ok()?;
    let mut g = CTX.lock_bh::<crate::state::SndBh>();
    if g.iter().any(|ctx| ctx.device_key == p.device_key) {
        drop(g);
        return None;
    }
    g.push(Ctx {
        device_key: p.device_key,
        controlq: Some(controlq),
        hhdm: p.resources.hhdm,
        cfg_va: p.resources.cfg_va,
        scratch_pa: frames.scratch_pa,
        eventq: None,
        event_buf_pa: frames.event_buf_pa,
        event_drained: 0,
        event_last_raw: 0,
        jacks: device_cfg.jacks,
        streams: device_cfg.streams,
        chmaps: device_cfg.chmaps,
        controls: device_cfg.controls,
        out_stream: None,
        out_formats: 0, out_rates: 0, out_ch_min: 1, out_ch_max: 2,
        txq,
        tx_buf_pa: frames.tx_buf_pa, tx_scratch_pa: frames.tx_scratch_pa,
        pcm_state: PcmState::Idle,
        cfg_rate: VIRTIO_SND_PCM_RATE_44100,
        cfg_format: VIRTIO_SND_PCM_FMT_S16,
        cfg_channels: 2,
        cfg_period_bytes: PERIOD_BYTES as u32,
        in_stream: None,
        in_formats: 0, in_rates: 0, in_ch_min: 1, in_ch_max: 2,
        rxq,
        rx_buf_pa: frames.rx_buf_pa, rx_scratch_pa: frames.rx_scratch_pa,
        cap_state: PcmState::Idle,
        cap_rate: VIRTIO_SND_PCM_RATE_44100,
        cap_format: VIRTIO_SND_PCM_FMT_S16,
        cap_channels: 2,
        cap_period_bytes: PERIOD_BYTES as u32,
    });
    frames.disarm();
    drop(g);
    // Pre-post the eventq only once the Ctx owns the frames. Publishing WRITE
    // descriptors over `event_buf_pa` and kicking the device earlier would let
    // the losing side of a same-key install race drop its probe — returning a
    // frame the device already holds descriptors for straight to the PMM.
    if !prepost_eventq(&mut eventq, frames.event_buf_pa) {
        if let Some(ctx) = remove_ctx_and_release_event_handler(p.device_key) {
            stop_reset_free(ctx);
        }
        return None;
    }
    if let Some(ctx) = CTX.lock_bh::<crate::state::SndBh>().iter_mut()
        .find(|ctx| ctx.device_key == p.device_key) {
        ctx.eventq = Some(eventq);
    } else { return None; }
    softirq::set_handler(softirq::Slot::SndEvent, event_softirq);
    // Linux fills EVENTQ with notifications disabled, then enables its
    // callback only after every event buffer is visible to the driver.  The
    // context and softirq handler must likewise exist before this first doorbell:
    // an immediate completion otherwise has nowhere to be drained.
    if let Some(eventq) = CTX.lock_bh::<crate::state::SndBh>()
        .iter_mut()
        .find(|ctx| ctx.device_key == p.device_key)
        .and_then(|ctx| ctx.eventq.as_mut()) {
        eventq.kick();
    } else {
        if let Some(ctx) = remove_ctx_and_release_event_handler(p.device_key) {
            stop_reset_free(ctx);
        }
        return None;
    }
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

pub fn uninstall(device_key: DeviceKey) -> bool {
    let (card_removed, ops_removed) = match sound_owner(device_key) {
        Some(owner) => (sound::unregister_card(owner), sound::ops::clear(owner)),
        None => (false, false),
    };
    let Some(ctx) = remove_ctx_and_release_event_handler(device_key) else {
        return card_removed || ops_removed;
    };
    stop_reset_free(ctx);
    true
}

pub fn shutdown(device_key: DeviceKey) -> bool {
    let Some(ctx) = remove_ctx_and_release_event_handler(device_key) else {
        return false;
    };
    stop_reset_free(ctx);
    true
}

pub(super) fn remove_ctx_and_release_event_handler(device_key: DeviceKey) -> Option<Ctx> {
    let (ctx, empty_after) = remove_ctx(device_key)?;
    if empty_after {
        let _ = softirq::clear_handler(softirq::Slot::SndEvent);
    }
    Some(ctx)
}

pub(super) fn stop_reset_free(mut ctx: Ctx) {
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
    let _ = virtio::reset_device(ctx.cfg_va);
    free_frame(ctx.event_buf_pa);
    free_frame(ctx.rx_buf_pa);
    free_frame(ctx.rx_scratch_pa);
    free_frame(ctx.tx_buf_pa);
    free_frame(ctx.tx_scratch_pa);
    free_frame(ctx.scratch_pa);
}

pub(super) fn prepost_eventq(eventq: &mut virtio::VirtioSplitQueue, event_buf_pa: u64) -> bool {
    let qsize = eventq.resource().size as usize;
    // Every slot i gets { addr=event_buf_pa + i*EVENT_SIZE, len=EVENT_SIZE,
    // WRITE }: the device fills the driver's own event frame, nothing else.
    // `install` capped eventq.size at MAX_EVENTQ_DESCS — the smaller of what
    // one event frame and one descriptor frame hold — so slot i and buffer i
    // both stay in-frame.  Do not notify here: install first makes the queue
    // reachable from its completion handler, then rings once for the batch.
    for i in 0..qsize {
        let entry_pa = event_buf_pa.wrapping_add((i as u64) * EVENT_SIZE as u64);
        if eventq.submit_no_kick(&[virtio::SplitQueueSeg {
            dma: entry_pa, len: EVENT_SIZE as u32, device_writes: true,
        }]).is_err() { return false; }
    }
    true
}
