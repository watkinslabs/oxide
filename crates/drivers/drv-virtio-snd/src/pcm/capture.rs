use super::*;

fn rx_period(ctx: &mut Ctx, stream_id: u32, out: &mut [u8]) -> usize {
    let Some(rxq) = ctx.rxq else { return 0 };
    if ctx.rx_buf_pa == 0 || ctx.rx_scratch_pa == 0 { return 0; }
    let h = ctx.hhdm;
    let n = out.len().min(SND_FRAME_BYTES);
    let xfer = h.wrapping_add(ctx.rx_scratch_pa) as *mut u32;
    // SAFETY: HHDM view of the RX scratch frame this Ctx owns (nonzero,
    // checked above) under the CTX lock; the request header is one aligned
    // u32 at offset 0 of that frame.
    unsafe { core::ptr::write_volatile(xfer, stream_id); }
    let desc = h.wrapping_add(rxq.desc_pa) as *mut u64;
    // Chain 0 -> 1 -> 2: 4-byte header (read), n-byte capture buffer (WRITE),
    // 8-byte status at rx_scratch_pa+16 (WRITE). The two device-written spans
    // are the driver's own frames and do not overlap the header.
    // SAFETY: HHDM-mapped rxq descriptor table; six aligned u64 stores cover
    // slots 0..2, inside the one-frame (256-entry) descriptor table.
    unsafe {
        core::ptr::write_volatile(desc.add(0), ctx.rx_scratch_pa);
        core::ptr::write_volatile(
            desc.add(1),
            (SND_XFER_HDR_BYTES as u64) | ((VRING_DESC_F_NEXT as u64) << 32) | (1u64 << 48),
        );
        core::ptr::write_volatile(desc.add(2), ctx.rx_buf_pa);
        core::ptr::write_volatile(
            desc.add(3),
            (n as u64)
                | (((VRING_DESC_F_NEXT | VRING_DESC_F_WRITE) as u64) << 32)
                | (2u64 << 48),
        );
        core::ptr::write_volatile(desc.add(4), ctx.rx_scratch_pa + SND_XFER_STATUS_OFF);
        core::ptr::write_volatile(desc.add(5),
            (SND_XFER_STATUS_BYTES as u64) | ((VRING_DESC_F_WRITE as u64) << 32));
    }
    let slot = (ctx.rx_avail_idx % rxq.size) as usize;
    let avail = h.wrapping_add(rxq.driver_pa) as *mut u16;
    // SAFETY: HHDM-mapped rxq avail ring; ring[slot] is u16 index 2+slot with
    // slot < rxq.size (nonzero per require_queue, capped at one ring frame),
    // idx is index 1, and the release fence publishes the descriptor chain and
    // ring entry before the idx store the device polls.
    let target = unsafe {
        core::ptr::write_volatile(avail.add(2 + slot), 0u16);
        core::sync::atomic::fence(Ordering::Release);
        ctx.rx_avail_idx = ctx.rx_avail_idx.wrapping_add(1);
        core::ptr::write_volatile(avail.add(1), ctx.rx_avail_idx);
        ctx.rx_avail_idx
    };
    core::sync::atomic::fence(Ordering::Release);
    // SAFETY: rxq notify VA is the Device-attr MMIO window the transport
    // mapped for this child; the kick is one aligned u16 store of the index.
    unsafe { core::ptr::write_volatile(rxq.notify_va as *mut u16, rxq.index); }
    let used16 = h.wrapping_add(rxq.device_pa) as *const u16;
    let mut polls = 0u32;
    loop {
        // SAFETY: HHDM-mapped rxq used ring; aligned u16 load of used.idx at
        // index 1, volatile because the device is what advances it.
        let uidx = unsafe { core::ptr::read_volatile(used16.add(1)) };
        if uidx == target { break; }
        if polls >= TX_POLL_BUDGET { return 0; }
        if ctx.cfg_va != 0 {
            let _ = virtio::read_status(ctx.cfg_va);
        }
        polls += 1;
        core::hint::spin_loop();
    }
    let elem = ((target.wrapping_sub(1)) % rxq.size) as usize;
    let used32 = h.wrapping_add(rxq.device_pa) as *const u32;
    // SAFETY: HHDM-mapped rxq used ring; ring[] starts at u32 index 1 with
    // {id,len} elements, so element `elem`'s len is at 1+elem*2+1 and elem is
    // reduced modulo rxq.size, keeping the load inside the ring frame.
    let used_len = unsafe { core::ptr::read_volatile(used32.add(1 + elem * 2 + 1)) } as usize;
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
    let mut g = CTX.lock();
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
    let mut g = CTX.lock();
    let ctx = match active_ctx_mut_for(&mut g, owner) { Some(c) => c, None => return false };
    if ctx.cap_state == PcmState::Idle { return false; }
    let stream = match ctx.in_stream { Some(s) => s, None => return false };
    if pcm_ctl(ctx, VIRTIO_SND_R_PCM_PREPARE, stream) != Some(VIRTIO_SND_S_OK) { return false; }
    ctx.cap_state = PcmState::Prepared;
    true
}

pub fn cap_trigger(owner: sound::SoundOwnerKey, start: bool) -> bool {
    let mut g = CTX.lock();
    let ctx = match active_ctx_mut_for(&mut g, owner) { Some(c) => c, None => return false };
    let stream = match ctx.in_stream { Some(s) => s, None => return false };
    let code = if start { VIRTIO_SND_R_PCM_START } else { VIRTIO_SND_R_PCM_STOP };
    if pcm_ctl(ctx, code, stream) != Some(VIRTIO_SND_S_OK) { return false; }
    ctx.cap_state = if start { PcmState::Running } else { PcmState::Prepared };
    true
}

pub fn cap_hw_free(owner: sound::SoundOwnerKey) -> bool {
    let mut g = CTX.lock();
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
    let mut g = CTX.lock();
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
