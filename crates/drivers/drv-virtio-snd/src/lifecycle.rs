use super::*;
use super::event::event_softirq;
use super::state::remove_ctx;

pub(super) fn read_device_config(resources: virtio::VirtioResources) -> Option<SndDeviceConfig> {
    let cfg = resources.device_cfg_va;
    if cfg == 0 {
        return None;
    }
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

pub fn present() -> bool { !CTX.lock().is_empty() }

pub fn present_for(device_key: DeviceKey) -> bool {
    CTX.lock().iter().any(|ctx| ctx.device_key == device_key)
}

pub fn config(owner: u32) -> Option<(u32, u32, u32, u32)> {
    active_ctx_for(&CTX.lock(), owner).map(|c| (c.jacks, c.streams, c.chmaps, c.controls))
}

pub fn eventq_state() -> Option<(u16, u16, u16)> {
    active_ctx(&CTX.lock()).and_then(|ctx| {
        ctx.eventq.map(|eventq| (eventq.size, ctx.event_last_used, ctx.event_avail_idx))
    })
}

pub fn eventq_state_for(device_key: DeviceKey) -> Option<(u16, u16, u16)> {
    CTX.lock()
        .iter()
        .find(|ctx| ctx.device_key == device_key)
        .and_then(|ctx| ctx.eventq.map(|eventq| (eventq.size, ctx.event_last_used, ctx.event_avail_idx)))
}

pub fn event_stats_for(device_key: DeviceKey) -> Option<(u64, u64)> {
    CTX.lock()
        .iter()
        .find(|ctx| ctx.device_key == device_key)
        .map(|ctx| (ctx.event_drained, ctx.event_last_raw))
}

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
    for pa in frames.all() {
        if pa == 0 {
            continue;
        }
        let va = p.resources.hhdm.wrapping_add(pa) as *mut u8;
        unsafe { for i in 0..0x1000usize { core::ptr::write_volatile(va.add(i), 0); } }
    }
    let used = p.resources.hhdm.wrapping_add(controlq.device_pa) as *const u16;
    let used_seen = unsafe { core::ptr::read_volatile(used.add(1)) };
    let event_used = p.resources.hhdm.wrapping_add(eventq.device_pa) as *const u16;
    let event_used_seen = unsafe { core::ptr::read_volatile(event_used.add(1)) };
    let event_avail_idx = event_used_seen.wrapping_add(eventq.size);
    prepost_eventq(p.resources.hhdm, eventq, frames.event_buf_pa, event_avail_idx);
    let tx_used_seen = if let Some(txq) = txq {
        let txu = p.resources.hhdm.wrapping_add(txq.device_pa) as *const u16;
        unsafe { core::ptr::read_volatile(txu.add(1)) }
    } else { 0 };
    let rx_used_seen = if let Some(rxq) = rxq {
        let rxu = p.resources.hhdm.wrapping_add(rxq.device_pa) as *const u16;
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
    if ctx.cfg_va != 0 {
        unsafe { core::ptr::write_volatile((ctx.cfg_va + 0x14) as *mut u8, 0u8); }
    }
    free_frame(ctx.event_buf_pa);
    free_frame(ctx.rx_buf_pa);
    free_frame(ctx.rx_scratch_pa);
    free_frame(ctx.tx_buf_pa);
    free_frame(ctx.tx_scratch_pa);
    free_frame(ctx.scratch_pa);
}

pub(super) fn prepost_eventq(
    hhdm: u64,
    eventq: virtio::VirtQueueResource,
    event_buf_pa: u64,
    avail_idx: u16,
) {
    let qsize = eventq.size as usize;
    let desc_va = hhdm.wrapping_add(eventq.desc_pa) as *mut u8;
    unsafe {
        for i in 0..qsize {
            let entry_pa = event_buf_pa.wrapping_add((i as u64) * EVENT_SIZE as u64);
            let off = i * 16;
            core::ptr::write_volatile(desc_va.add(off) as *mut u64, entry_pa);
            core::ptr::write_volatile(desc_va.add(off + 8) as *mut u32, EVENT_SIZE as u32);
            core::ptr::write_volatile(desc_va.add(off + 12) as *mut u16, VRING_DESC_F_WRITE);
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
