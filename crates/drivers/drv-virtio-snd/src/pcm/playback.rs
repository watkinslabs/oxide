use super::*;

pub(crate) const PERIOD_BYTES: usize = 2048;

pub(crate) fn pcm_ctl(ctx: &mut Ctx, code: u32, stream_id: u32) -> Option<u32> {
    let req = ctx.hhdm.wrapping_add(ctx.scratch_pa + REQ_OFF) as *mut u32;
    // SAFETY: HHDM view of the control scratch frame this Ctx owns, written
    // under the CTX lock; the two u32 stores build an 8-byte pcm header at
    // REQ_OFF, far below RESP_OFF, so they cannot touch the response half.
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
    // SAFETY: same control scratch frame under the CTX lock; the stores lay out
    // the 24-byte set_params request at REQ_OFF (five aligned u32 at 0..20,
    // then four bytes at 20..24), which stays well below RESP_OFF.
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
    let Some(mut txq) = ctx.txq.take() else { return false };
    let result = tx_period_on_queue(ctx, &mut txq, stream_id, pcm);
    ctx.txq = Some(txq);
    result
}

fn tx_period_on_queue(
    ctx: &mut Ctx, txq: &mut virtio::VirtioSplitQueue, stream_id: u32, pcm: &[u8],
) -> bool {
    if ctx.tx_buf_pa == 0 || ctx.tx_scratch_pa == 0 { return false; }
    let h = ctx.hhdm;
    let n = pcm.len().min(SND_FRAME_BYTES);
    let xfer = h.wrapping_add(ctx.tx_scratch_pa) as *mut u32;
    let buf = h.wrapping_add(ctx.tx_buf_pa) as *mut u8;
    // SAFETY: HHDM views of the TX scratch and TX audio frames this Ctx owns
    // (both nonzero, checked above) under the CTX lock; the header is one
    // aligned u32 at offset 0, and `n <= SND_FRAME_BYTES` bounds the payload
    // copy to the audio frame, with `pcm[i]` bounds-checked by the slice.
    unsafe {
        core::ptr::write_volatile(xfer, stream_id);
        for i in 0..n { core::ptr::write_volatile(buf.add(i), pcm[i]); }
    }
    // Linux submits the xfer header, audio payload, and status as one SG
    // request.  The shared queue owns the descriptor chain and ring state.
    let head = txq.submit(&[
        virtio::SplitQueueSeg { dma: ctx.tx_scratch_pa, len: SND_XFER_HDR_BYTES as u32, device_writes: false },
        virtio::SplitQueueSeg { dma: ctx.tx_buf_pa, len: n as u32, device_writes: false },
        virtio::SplitQueueSeg { dma: ctx.tx_scratch_pa + SND_XFER_STATUS_OFF, len: SND_XFER_STATUS_BYTES as u32, device_writes: true },
    ]).ok();
    head.and_then(|head| super::wait_for_period_completion(txq, head, ctx.cfg_va)).is_some()
}

/// Submit one bounded portion of the userspace-owned mmap ring without a
/// staging copy.  The queue owns the DMA frame only until completion, so the
/// synchronous wait preserves the same lifetime rule as the legacy path.
pub(crate) fn mmap_commit(
    owner: sound::SoundOwnerKey, appl: u64, hw: u64, frame_bytes: u32, buffer_frames: u32,
) -> Option<u64> {
    let mut g = CTX.lock_bh::<crate::state::SndBh>();
    let ctx = active_ctx_mut_for(&mut g, owner)?;
    if ctx.pcm_state != PcmState::Running || ctx.tx_buf_pa == 0 || ctx.tx_scratch_pa == 0 {
        return None;
    }
    let available = appl.wrapping_sub(hw).min(buffer_frames as u64);
    if available == 0 { return Some(hw); }
    let frames = available.min((ctx.cfg_period_bytes as u64 / frame_bytes as u64).max(1));
    let bytes = (frames * frame_bytes as u64) as usize;
    let ring_bytes = (buffer_frames * frame_bytes) as u64;
    let start = (hw % buffer_frames as u64) * frame_bytes as u64;
    let first = bytes.min((ring_bytes - start) as usize);
    let second = bytes - first;
    let xfer = ctx.hhdm.wrapping_add(ctx.tx_scratch_pa) as *mut u32;
    // SAFETY: the scratch frame is private to this Ctx while CTX is held.
    unsafe { core::ptr::write_volatile(xfer, ctx.out_stream?); }
    let mut segs = [
        virtio::SplitQueueSeg { dma: ctx.tx_scratch_pa, len: SND_XFER_HDR_BYTES as u32, device_writes: false },
        virtio::SplitQueueSeg { dma: ctx.tx_buf_pa + start, len: first as u32, device_writes: false },
        virtio::SplitQueueSeg { dma: ctx.tx_buf_pa + ring_bytes, len: 0, device_writes: false },
        virtio::SplitQueueSeg { dma: ctx.tx_scratch_pa + SND_XFER_STATUS_OFF, len: SND_XFER_STATUS_BYTES as u32, device_writes: true },
    ];
    if second != 0 { segs[2] = virtio::SplitQueueSeg { dma: ctx.tx_buf_pa, len: second as u32, device_writes: false }; }
    let mut txq = ctx.txq.take()?;
    let result = if second == 0 {
        let short = [segs[0], segs[1], segs[3]];
        txq.submit(&short)
    } else {
        txq.submit(&segs)
    }.ok().and_then(|head| super::wait_for_period_completion(&mut txq, head, ctx.cfg_va));
    ctx.txq = Some(txq);
    result.map(|_| hw + frames)
}

pub fn beep(hz: u32, ms: u32) -> bool { beep_diag(hz, ms) == 0 }

pub fn beep_diag(hz: u32, ms: u32) -> u8 {
    let mut g = CTX.lock_bh::<crate::state::SndBh>();
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
    owner: sound::SoundOwnerKey, alsa_format: u32, rate_hz: u32, channels: u8, period_bytes: u32, buffer_bytes: u32,
) -> bool {
    let Some(format) = crate::fmt::alsa_to_virtio(alsa_format) else { return false; };
    let rate = crate::fmt::hz_to_virtio_rate(rate_hz);
    let mut g = CTX.lock_bh::<crate::state::SndBh>();
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
    let mut g = CTX.lock_bh::<crate::state::SndBh>();
    let ctx = match active_ctx_mut_for(&mut g, owner) { Some(c) => c, None => return false };
    if ctx.pcm_state == PcmState::Idle { return false; }
    let stream = match ctx.out_stream { Some(s) => s, None => return false };
    if pcm_ctl(ctx, VIRTIO_SND_R_PCM_PREPARE, stream) != Some(VIRTIO_SND_S_OK) { return false; }
    ctx.pcm_state = PcmState::Prepared;
    true
}

pub fn pcm_trigger(owner: sound::SoundOwnerKey, start: bool) -> bool {
    let mut g = CTX.lock_bh::<crate::state::SndBh>();
    let ctx = match active_ctx_mut_for(&mut g, owner) { Some(c) => c, None => return false };
    let stream = match ctx.out_stream { Some(s) => s, None => return false };
    let code = if start { VIRTIO_SND_R_PCM_START } else { VIRTIO_SND_R_PCM_STOP };
    if pcm_ctl(ctx, code, stream) != Some(VIRTIO_SND_S_OK) { return false; }
    ctx.pcm_state = if start { PcmState::Running } else { PcmState::Prepared };
    true
}

pub fn pcm_hw_free(owner: sound::SoundOwnerKey) -> bool {
    let mut g = CTX.lock_bh::<crate::state::SndBh>();
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
    let mut g = CTX.lock_bh::<crate::state::SndBh>();
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
