use core::sync::atomic::Ordering;

use virtio::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};

use crate::{
    active_ctx, active_ctx_for, active_ctx_mut, active_ctx_mut_for, submit_ctl, Ctx, PcmState,
    CTX, PLAYBACK_RATE_HZ, REQ_OFF, SND_HDR_SIZE, TX_POLL_BUDGET,
    VIRTIO_SND_PCM_FMT_S16, VIRTIO_SND_PCM_FMT_U16, VIRTIO_SND_PCM_RATE_44100,
    VIRTIO_SND_R_PCM_PREPARE, VIRTIO_SND_R_PCM_RELEASE, VIRTIO_SND_R_PCM_SET_PARAMS,
    VIRTIO_SND_R_PCM_START, VIRTIO_SND_R_PCM_STOP, VIRTIO_SND_S_OK,
};

// ── PCM playback (TXQ) ──────────────────────────────────────────────────
// docs/58§4 control reqs + §8 TXQ device operation. PR-C: enough to drive a
// tone end-to-end; ALSA/OSS substream plumbing (PR-D/PR-E) layers on top.

/// The default OUTPUT stream id, or None if no playback stream / not
/// installed. # C: O(1)
pub fn output_stream() -> Option<u32> { active_ctx(&CTX.lock()).and_then(|c| c.out_stream) }

/// Issue a simple `virtio_snd_pcm_hdr` control request (code + stream_id) on
/// the CONTROLQ — PREPARE / START / STOP / RELEASE. Returns the status le32.
/// # C: O(CONTROLQ round-trip)
pub(super) fn pcm_ctl(ctx: &mut Ctx, code: u32, stream_id: u32) -> Option<u32> {
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

pub(super) const PERIOD_BYTES: usize = 2048;

/// Bytes per frame for a virtio_snd format enum × channel count. The
/// supported formats are 1-byte (µ-law/A-law/S8/U8) or 2-byte (S16/U16).
/// # C: O(1)
fn frame_bytes(format: u8, channels: u8) -> usize {
    let bps = match format {
        VIRTIO_SND_PCM_FMT_S16 | VIRTIO_SND_PCM_FMT_U16 => 2,
        _ => 1,
    };
    bps * channels.max(1) as usize
}

/// OUTPUT-stream hw capabilities `(formats, rates, ch_min, ch_max)` harvested
/// from PCM_INFO — `formats`/`rates` are VIRTIO_SND_PCM_FMT_*/RATE_* bit
/// masks. Drive the ALSA `hw_params` refinement. None until installed.
/// # C: O(1)
pub fn pcm_caps(owner: u32) -> Option<(u64, u64, u8, u8)> {
    active_ctx_for(&CTX.lock(), owner).and_then(|c| {
        c.out_stream?;
        Some((c.out_formats, c.out_rates, c.out_ch_min, c.out_ch_max))
    })
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
        if pcm_ctl(ctx, VIRTIO_SND_R_PCM_STOP, stream) != Some(VIRTIO_SND_S_OK) {
            return false;
        }
        if pcm_ctl(ctx, VIRTIO_SND_R_PCM_RELEASE, stream) != Some(VIRTIO_SND_S_OK) {
            return false;
        }
        ctx.pcm_state = PcmState::Idle;
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
    if pcm_ctl(ctx, VIRTIO_SND_R_PCM_RELEASE, stream) != Some(VIRTIO_SND_S_OK) {
        return false;
    }
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
    active_ctx_for(&CTX.lock(), owner).and_then(|c| {
        c.in_stream?;
        Some((c.in_formats, c.in_rates, c.in_ch_min, c.in_ch_max))
    })
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
        if pcm_ctl(ctx, VIRTIO_SND_R_PCM_STOP, stream) != Some(VIRTIO_SND_S_OK) {
            return false;
        }
        if pcm_ctl(ctx, VIRTIO_SND_R_PCM_RELEASE, stream) != Some(VIRTIO_SND_S_OK) {
            return false;
        }
        ctx.cap_state = PcmState::Idle;
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
    if pcm_ctl(ctx, VIRTIO_SND_R_PCM_RELEASE, stream) != Some(VIRTIO_SND_S_OK) {
        return false;
    }
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
