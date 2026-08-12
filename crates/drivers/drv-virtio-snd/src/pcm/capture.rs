use super::*;

fn rx_period(ctx: &mut Ctx, stream_id: u32, out: &mut [u8]) -> usize {
    let Some(mut rxq) = ctx.rxq.take() else { return 0 };
    let result = rx_period_on_queue(ctx, &mut rxq, stream_id, out);
    ctx.rxq = Some(rxq);
    result
}

fn rx_period_on_queue(
    ctx: &mut Ctx, rxq: &mut virtio::VirtioSplitQueue, stream_id: u32, out: &mut [u8],
) -> usize {
    if ctx.rx_buf_pa == 0 || ctx.rx_scratch_pa == 0 { return 0; }
    let h = ctx.hhdm;
    let n = out.len().min(SND_FRAME_BYTES);
    let xfer = h.wrapping_add(ctx.rx_scratch_pa) as *mut u32;
    // SAFETY: HHDM view of the RX scratch frame this Ctx owns (nonzero,
    // checked above) under the CTX lock; the request header is one aligned
    // u32 at offset 0 of that frame.
    unsafe { core::ptr::write_volatile(xfer, stream_id); }
    // The RX request has one driver-readable header and two device-writable
    // segments, matching Linux's `virtqueue_add_sgs(vq, ..., 1, 2, ...)`.
    let used_len = match rxq.submit(&[
        virtio::SplitQueueSeg { dma: ctx.rx_scratch_pa, len: SND_XFER_HDR_BYTES as u32, device_writes: false },
        virtio::SplitQueueSeg { dma: ctx.rx_buf_pa, len: n as u32, device_writes: true },
        virtio::SplitQueueSeg { dma: ctx.rx_scratch_pa + SND_XFER_STATUS_OFF, len: SND_XFER_STATUS_BYTES as u32, device_writes: true },
    ]).ok().and_then(|head| super::wait_for_period_completion(rxq, head, ctx.cfg_va)) {
        Some(len) => len as usize,
        None => return 0,
    };
    // `used_len` is DEVICE-supplied: it bounds nothing until clamped to `n`,
    // which is both the capture buffer's own size and `out`'s length.
    let payload = used_len.saturating_sub(SND_XFER_STATUS_BYTES).min(n);
    let src = h.wrapping_add(ctx.rx_buf_pa) as *const u8;
    // SAFETY: HHDM view of this Ctx's capture frame after the device signalled
    // completion; `payload <= n <= SND_FRAME_BYTES` keeps each read in that
    // frame, and `out[i]` is bounds-checked because `payload <= out.len()`.
    for i in 0..payload { out[i] = unsafe { core::ptr::read_volatile(src.add(i)) }; }
    payload
}

pub fn cap_hw_params(
    owner: sound::SoundOwnerKey, rate: u8, format: u8, channels: u8, period_bytes: u32, buffer_bytes: u32,
) -> bool {
    let mut g = CTX.lock_bh::<crate::state::SndBh>();
    let ctx = match active_ctx_mut_for(&mut g, owner) { Some(c) => c, None => return false };
    let stream = match ctx.in_stream { Some(s) => s, None => return false };
    let ch = channels.clamp(1, 2);
    if ctx.cap_state == PcmState::Prepared || ctx.cap_state == PcmState::Running {
        if pcm_ctl(ctx, VIRTIO_SND_R_PCM_STOP, stream) != Some(VIRTIO_SND_S_OK) { return false; }
        if pcm_ctl(ctx, VIRTIO_SND_R_PCM_RELEASE, stream) != Some(VIRTIO_SND_S_OK) { return false; }
        ctx.cap_state = PcmState::Idle;
    }
    if super::playback::pcm_set_params(ctx, stream, buffer_bytes, period_bytes, ch, format, rate)
        != Some(VIRTIO_SND_S_OK) { return false; }
    ctx.cap_rate = rate;
    ctx.cap_format = format;
    ctx.cap_channels = ch;
    ctx.cap_period_bytes = period_bytes.max(1).min(SND_FRAME_BYTES as u32);
    ctx.cap_state = PcmState::Configured;
    true
}

pub fn cap_prepare(owner: sound::SoundOwnerKey) -> bool {
    let mut g = CTX.lock_bh::<crate::state::SndBh>();
    let ctx = match active_ctx_mut_for(&mut g, owner) { Some(c) => c, None => return false };
    if ctx.cap_state == PcmState::Idle { return false; }
    let stream = match ctx.in_stream { Some(s) => s, None => return false };
    if pcm_ctl(ctx, VIRTIO_SND_R_PCM_PREPARE, stream) != Some(VIRTIO_SND_S_OK) { return false; }
    ctx.cap_state = PcmState::Prepared;
    true
}

pub fn cap_trigger(owner: sound::SoundOwnerKey, start: bool) -> bool {
    let mut g = CTX.lock_bh::<crate::state::SndBh>();
    let ctx = match active_ctx_mut_for(&mut g, owner) { Some(c) => c, None => return false };
    let stream = match ctx.in_stream { Some(s) => s, None => return false };
    let code = if start { VIRTIO_SND_R_PCM_START } else { VIRTIO_SND_R_PCM_STOP };
    if pcm_ctl(ctx, code, stream) != Some(VIRTIO_SND_S_OK) { return false; }
    ctx.cap_state = if start { PcmState::Running } else { PcmState::Prepared };
    true
}

pub fn cap_hw_free(owner: sound::SoundOwnerKey) -> bool {
    let mut g = CTX.lock_bh::<crate::state::SndBh>();
    let ctx = match active_ctx_mut_for(&mut g, owner) { Some(c) => c, None => return false };
    if ctx.cap_state == PcmState::Idle { return true; }
    let stream = match ctx.in_stream { Some(s) => s, None => return false };
    if pcm_ctl(ctx, VIRTIO_SND_R_PCM_RELEASE, stream) != Some(VIRTIO_SND_S_OK) {
        return false;
    }
    ctx.cap_state = PcmState::Idle;
    true
}

pub fn pcm_recv(owner: sound::SoundOwnerKey, out: &mut [u8]) -> usize {
    let mut g = CTX.lock_bh::<crate::state::SndBh>();
    let ctx = match active_ctx_mut_for(&mut g, owner) { Some(c) => c, None => return 0 };
    if ctx.cap_state != PcmState::Running { return 0; }
    let stream = match ctx.in_stream { Some(s) => s, None => return 0 };
    let chunk = (ctx.cap_period_bytes as usize).max(1).min(SND_FRAME_BYTES);
    let mut off = 0usize;
    while off < out.len() {
        let end = (off + chunk).min(out.len());
        let got = rx_period(ctx, stream, &mut out[off..end]);
        if got == 0 { break; }
        off += got;
    }
    off
}
