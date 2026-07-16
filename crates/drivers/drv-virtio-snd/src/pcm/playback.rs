use super::*;

pub(crate) const PERIOD_BYTES: usize = 2048;

pub(crate) fn pcm_ctl(ctx: &mut Ctx, code: u32, stream_id: u32) -> Option<u32> {
    let req = ctx.hhdm.wrapping_add(ctx.scratch_pa + REQ_OFF) as *mut u32;
    unsafe {
        core::ptr::write_volatile(req.add(0), code);
        core::ptr::write_volatile(req.add(1), stream_id);
    }
    submit_ctl(ctx, 8, SND_HDR_SIZE)
}

pub(crate) fn pcm_set_params(
    ctx: &mut Ctx, stream_id: u32, buffer_bytes: u32, period_bytes: u32, channels: u8,
    format: u8, rate: u8,
) -> Option<u32> {
    let base = ctx.hhdm.wrapping_add(ctx.scratch_pa + REQ_OFF);
    let w = base as *mut u32;
    let b = base as *mut u8;
    unsafe {
        core::ptr::write_volatile(w.add(0), VIRTIO_SND_R_PCM_SET_PARAMS);
        core::ptr::write_volatile(w.add(1), stream_id);
        core::ptr::write_volatile(w.add(2), buffer_bytes);
        core::ptr::write_volatile(w.add(3), period_bytes);
        core::ptr::write_volatile(w.add(4), 0u32);
        core::ptr::write_volatile(b.add(20), channels);
        core::ptr::write_volatile(b.add(21), format);
        core::ptr::write_volatile(b.add(22), rate);
        core::ptr::write_volatile(b.add(23), 0u8);
    }
    submit_ctl(ctx, 24, SND_HDR_SIZE)
}

fn tx_period(ctx: &mut Ctx, stream_id: u32, pcm: &[u8]) -> bool {
    let Some(txq) = ctx.txq else { return false };
    if ctx.tx_buf_pa == 0 || ctx.tx_scratch_pa == 0 { return false; }
    let h = ctx.hhdm;
    let n = pcm.len().min(SND_FRAME_BYTES);
    let xfer = h.wrapping_add(ctx.tx_scratch_pa) as *mut u32;
    let buf = h.wrapping_add(ctx.tx_buf_pa) as *mut u8;
    unsafe {
        core::ptr::write_volatile(xfer, stream_id);
        for i in 0..n { core::ptr::write_volatile(buf.add(i), pcm[i]); }
    }
    let desc = h.wrapping_add(txq.desc_pa) as *mut u64;
    unsafe {
        core::ptr::write_volatile(desc.add(0), ctx.tx_scratch_pa);
        core::ptr::write_volatile(
            desc.add(1),
            4u64 | ((VRING_DESC_F_NEXT as u64) << 32) | (1u64 << 48),
        );
        core::ptr::write_volatile(desc.add(2), ctx.tx_buf_pa);
        core::ptr::write_volatile(
            desc.add(3),
            (n as u64) | ((VRING_DESC_F_NEXT as u64) << 32) | (2u64 << 48),
        );
        core::ptr::write_volatile(desc.add(4), ctx.tx_scratch_pa + 16);
        core::ptr::write_volatile(desc.add(5), 8u64 | ((VRING_DESC_F_WRITE as u64) << 32));
    }
    let slot = (ctx.tx_avail_idx % txq.size) as usize;
    let avail = h.wrapping_add(txq.driver_pa) as *mut u16;
    let target = unsafe {
        core::ptr::write_volatile(avail.add(2 + slot), 0u16);
        core::sync::atomic::fence(Ordering::Release);
        ctx.tx_avail_idx = ctx.tx_avail_idx.wrapping_add(1);
        core::ptr::write_volatile(avail.add(1), ctx.tx_avail_idx);
        ctx.tx_avail_idx
    };
    core::sync::atomic::fence(Ordering::Release);
    unsafe { core::ptr::write_volatile(txq.notify_va as *mut u16, txq.index); }
    let used = h.wrapping_add(txq.device_pa) as *const u16;
    let mut polls = 0u32;
    loop {
        let uidx = unsafe { core::ptr::read_volatile(used.add(1)) };
        if uidx == target { return true; }
        if polls >= TX_POLL_BUDGET { return false; }
        if ctx.cfg_va != 0 {
            let _ = virtio::read_status(ctx.cfg_va);
        }
        polls += 1;
        core::hint::spin_loop();
    }
}

pub fn beep(hz: u32, ms: u32) -> bool { beep_diag(hz, ms) == 0 }

pub fn beep_diag(hz: u32, ms: u32) -> u8 {
    let mut g = CTX.lock();
    let ctx = match active_ctx_mut(&mut g) { Some(c) => c, None => return 1 };
    let stream = match ctx.out_stream { Some(s) => s, None => return 2 };
    if ctx.txq.is_none() { return 3; }

    if pcm_set_params(
        ctx,
        stream,
        (PERIOD_BYTES * 2) as u32,
        PERIOD_BYTES as u32,
        1,
        VIRTIO_SND_PCM_FMT_S16,
        VIRTIO_SND_PCM_RATE_44100,
    ) != Some(VIRTIO_SND_S_OK)
    {
        return 4;
    }
    if pcm_ctl(ctx, VIRTIO_SND_R_PCM_PREPARE, stream) != Some(VIRTIO_SND_S_OK) { return 5; }
    if pcm_ctl(ctx, VIRTIO_SND_R_PCM_START, stream) != Some(VIRTIO_SND_S_OK) { return 6; }

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

pub fn pcm_hw_params(
    owner: sound::SoundOwnerKey, rate: u8, format: u8, channels: u8, period_bytes: u32, buffer_bytes: u32,
) -> bool {
    let mut g = CTX.lock();
    let ctx = match active_ctx_mut_for(&mut g, owner) { Some(c) => c, None => return false };
    let stream = match ctx.out_stream { Some(s) => s, None => return false };
    let ch = channels.clamp(1, 2);
    if ctx.pcm_state == PcmState::Prepared || ctx.pcm_state == PcmState::Running {
        if pcm_ctl(ctx, VIRTIO_SND_R_PCM_STOP, stream) != Some(VIRTIO_SND_S_OK) { return false; }
        if pcm_ctl(ctx, VIRTIO_SND_R_PCM_RELEASE, stream) != Some(VIRTIO_SND_S_OK) { return false; }
        ctx.pcm_state = PcmState::Idle;
    }
    if pcm_set_params(ctx, stream, buffer_bytes, period_bytes, ch, format, rate)
        != Some(VIRTIO_SND_S_OK) { return false; }
    ctx.cfg_rate = rate;
    ctx.cfg_format = format;
    ctx.cfg_channels = ch;
    ctx.cfg_period_bytes = period_bytes.max(1).min(SND_FRAME_BYTES as u32);
    ctx.pcm_state = PcmState::Configured;
    true
}

pub fn pcm_prepare(owner: sound::SoundOwnerKey) -> bool {
    let mut g = CTX.lock();
    let ctx = match active_ctx_mut_for(&mut g, owner) { Some(c) => c, None => return false };
    if ctx.pcm_state == PcmState::Idle { return false; }
    let stream = match ctx.out_stream { Some(s) => s, None => return false };
    if pcm_ctl(ctx, VIRTIO_SND_R_PCM_PREPARE, stream) != Some(VIRTIO_SND_S_OK) { return false; }
    ctx.pcm_state = PcmState::Prepared;
    true
}

pub fn pcm_trigger(owner: sound::SoundOwnerKey, start: bool) -> bool {
    let mut g = CTX.lock();
    let ctx = match active_ctx_mut_for(&mut g, owner) { Some(c) => c, None => return false };
    let stream = match ctx.out_stream { Some(s) => s, None => return false };
    let code = if start { VIRTIO_SND_R_PCM_START } else { VIRTIO_SND_R_PCM_STOP };
    if pcm_ctl(ctx, code, stream) != Some(VIRTIO_SND_S_OK) { return false; }
    ctx.pcm_state = if start { PcmState::Running } else { PcmState::Prepared };
    true
}

pub fn pcm_hw_free(owner: sound::SoundOwnerKey) -> bool {
    let mut g = CTX.lock();
    let ctx = match active_ctx_mut_for(&mut g, owner) { Some(c) => c, None => return false };
    if ctx.pcm_state == PcmState::Idle { return true; }
    let stream = match ctx.out_stream { Some(s) => s, None => return false };
    if pcm_ctl(ctx, VIRTIO_SND_R_PCM_RELEASE, stream) != Some(VIRTIO_SND_S_OK) {
        return false;
    }
    ctx.pcm_state = PcmState::Idle;
    true
}

pub fn pcm_submit(owner: sound::SoundOwnerKey, bytes: &[u8]) -> usize {
    let mut g = CTX.lock();
    let ctx = match active_ctx_mut_for(&mut g, owner) { Some(c) => c, None => return 0 };
    if ctx.pcm_state != PcmState::Running { return 0; }
    let stream = match ctx.out_stream { Some(s) => s, None => return 0 };
    let chunk = (ctx.cfg_period_bytes as usize).max(1).min(SND_FRAME_BYTES);
    let mut off = 0usize;
    while off < bytes.len() {
        let n = (bytes.len() - off).min(chunk);
        if !tx_period(ctx, stream, &bytes[off..off + n]) { break; }
        off += n;
    }
    off
}
