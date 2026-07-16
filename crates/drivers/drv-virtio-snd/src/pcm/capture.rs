use super::*;

fn rx_period(ctx: &mut Ctx, stream_id: u32, out: &mut [u8]) -> usize {
    let Some(rxq) = ctx.rxq else { return 0 };
    if ctx.rx_buf_pa == 0 || ctx.rx_scratch_pa == 0 { return 0; }
    let h = ctx.hhdm;
    let n = out.len().min(SND_FRAME_BYTES);
    let xfer = h.wrapping_add(ctx.rx_scratch_pa) as *mut u32;
    unsafe { core::ptr::write_volatile(xfer, stream_id); }
    let desc = h.wrapping_add(rxq.desc_pa) as *mut u64;
    unsafe {
        core::ptr::write_volatile(desc.add(0), ctx.rx_scratch_pa);
        core::ptr::write_volatile(
            desc.add(1),
            4u64 | ((VRING_DESC_F_NEXT as u64) << 32) | (1u64 << 48),
        );
        core::ptr::write_volatile(desc.add(2), ctx.rx_buf_pa);
        core::ptr::write_volatile(
            desc.add(3),
            (n as u64)
                | (((VRING_DESC_F_NEXT | VRING_DESC_F_WRITE) as u64) << 32)
                | (2u64 << 48),
        );
        core::ptr::write_volatile(desc.add(4), ctx.rx_scratch_pa + 16);
        core::ptr::write_volatile(desc.add(5), 8u64 | ((VRING_DESC_F_WRITE as u64) << 32));
    }
    let slot = (ctx.rx_avail_idx % rxq.size) as usize;
    let avail = h.wrapping_add(rxq.driver_pa) as *mut u16;
    let target = unsafe {
        core::ptr::write_volatile(avail.add(2 + slot), 0u16);
        core::sync::atomic::fence(Ordering::Release);
        ctx.rx_avail_idx = ctx.rx_avail_idx.wrapping_add(1);
        core::ptr::write_volatile(avail.add(1), ctx.rx_avail_idx);
        ctx.rx_avail_idx
    };
    core::sync::atomic::fence(Ordering::Release);
    unsafe { core::ptr::write_volatile(rxq.notify_va as *mut u16, rxq.index); }
    let used16 = h.wrapping_add(rxq.device_pa) as *const u16;
    let mut polls = 0u32;
    loop {
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
    let used_len = unsafe { core::ptr::read_volatile(used32.add(1 + elem * 2 + 1)) } as usize;
    let payload = used_len.saturating_sub(8).min(n);
    let src = h.wrapping_add(ctx.rx_buf_pa) as *const u8;
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
