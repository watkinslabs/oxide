// ALSA PCM core for virtio-snd OUTPUT substreams (card N, dev 0).
// Owns the substream state machine + hw_params refinement against the
// device caps + sw_params + appl_ptr/hw_ptr ring accounting + the
// SNDRV_PCM_IOCTL_* ABI. Calls the card driver's registered snd_pcm_ops
// table (pcm_hw_params/pcm_prepare/pcm_trigger/pcm_hw_free/pcm_submit).
//
// Transfer model: blocking interleaved writei. pcm_submit blocks until the
// device consumes each period, so after a write hw_ptr == appl_ptr and the
// whole buffer is available again — the canonical snd_pcm_writei blocking
// mode (mmap/async streaming is a follow-up; INFO advertises no MMAP).

use alloc::vec::Vec;
use sync::{Spinlock, TaskList as L};
use syscall::errno::Errno;

use crate::uapi::*;

/// SNDRV_PCM_INFO_INTERLEAVED | BLOCK_TRANSFER (no MMAP — blocking writei).
const PCM_INFO_FLAGS: u32 = 0x100 | 0x10000;
/// Default period / periods when the app doesn't pin them.
const DEF_PERIOD_BYTES: u32 = 2048;
const DEF_PERIODS: u32 = 2;
/// appl_ptr/hw_ptr wrap point reported to userspace.
const BOUNDARY: u64 = 0x4000_0000_0000;

/// The OUTPUT substream state owned by one registered sound card.
struct Pcm {
    owner: u32,
    state: u32,
    format: u32,      // ALSA SNDRV_PCM_FORMAT_*
    rate: u32,        // Hz
    channels: u32,
    frame_bytes: u32,
    period_frames: u32,
    buffer_frames: u32,
    start_threshold: u64, // frames
    appl_ptr: u64,        // frames
    hw_ptr: u64,          // frames
}

static PCM: Spinlock<Vec<Pcm>, L> = Spinlock::new(Vec::new());

fn initial(owner: u32) -> Pcm {
    Pcm {
        owner,
        state: STATE_OPEN,
        format: FMT_S16_LE,
        rate: 44100,
        channels: 2,
        frame_bytes: 4,
        period_frames: 512,
        buffer_frames: 1024,
        start_threshold: 1,
        appl_ptr: 0,
        hw_ptr: 0,
    }
}

pub(crate) fn register_card(owner: u32) {
    let mut guard = PCM.lock();
    if !guard.iter().any(|p| p.owner == owner) {
        guard.push(initial(owner));
    }
}

pub(crate) fn unregister_card(owner: u32) {
    let mut guard = PCM.lock();
    guard.retain(|p| p.owner != owner);
}

#[cfg(test)]
pub(crate) fn registered_count() -> usize {
    PCM.lock().len()
}

fn is_registered(owner: u32) -> bool {
    PCM.lock().iter().any(|p| p.owner == owner)
}

#[cfg(test)]
pub(crate) fn has_card(owner: u32) -> bool { is_registered(owner) }

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

// ── format / rate enum mapping (ALSA ↔ virtio_snd) ─────────────────────

/// ALSA format → virtio_snd FMT enum, or None if unmappable. # C: O(1)
fn alsa_fmt_to_virtio(f: u32) -> Option<u8> {
    Some(match f {
        FMT_S8 => 3, FMT_U8 => 4, FMT_S16_LE => 5, FMT_U16_LE => 6,
        FMT_MU_LAW => 1, FMT_A_LAW => 2, _ => return None,
    })
}
/// Sample bits for an ALSA format. # C: O(1)
fn fmt_bits(f: u32) -> u32 { if f == FMT_S16_LE || f == FMT_U16_LE { 16 } else { 8 } }

/// virtio RATE enum → Hz. # C: O(1)
fn rate_enum_hz(e: u8) -> u32 {
    const HZ: [u32; 14] = [5512, 8000, 11025, 16000, 22050, 32000, 44100,
                           48000, 64000, 88200, 96000, 176400, 192000, 384000];
    HZ[(e as usize).min(13)]
}
/// Hz → virtio RATE enum (nearest standard). # C: O(1)
fn hz_rate_enum(hz: u32) -> u8 {
    const HZ: [u32; 14] = [5512, 8000, 11025, 16000, 22050, 32000, 44100,
                           48000, 64000, 88200, 96000, 176400, 192000, 384000];
    let mut best = 6u8; let mut bd = u32::MAX;
    for (i, &h) in HZ.iter().enumerate() {
        let d = if h > hz { h - hz } else { hz - h };
        if d < bd { bd = d; best = i as u8; }
    }
    best
}

/// Device OUTPUT caps `(virtio_formats, virtio_rates, ch_min, ch_max)`.
/// # C: O(1)
fn caps(owner: u32) -> Option<(u64, u64, u8, u8)> { crate::ops::pcm_caps(owner) }

// ── hw_params mask / interval accessors ────────────────────────────────

fn mask_test(b: &UserBuf, param: usize, val: u32) -> bool {
    let word = HWP_MASKS + param * HWP_MASK_STRIDE + (val as usize / 32) * 4;
    (b.r32(word) >> (val % 32)) & 1 != 0
}
fn mask_set_single(b: &UserBuf, param: usize, val: u32) {
    let base = HWP_MASKS + param * HWP_MASK_STRIDE;
    for w in 0..8 { b.w32(base + w * 4, 0); }
    b.w32(base + (val as usize / 32) * 4, 1u32 << (val % 32));
}
fn iv_off(param: usize) -> usize { HWP_INTERVALS + (param - P_SAMPLE_BITS) * HWP_INTERVAL_STRIDE }
fn iv_min(b: &UserBuf, param: usize) -> u32 { b.r32(iv_off(param)) }
fn iv_max(b: &UserBuf, param: usize) -> u32 { b.r32(iv_off(param) + 4) }
/// Pin an interval to a single integer value.
fn iv_set(b: &UserBuf, param: usize, v: u32) {
    let o = iv_off(param);
    b.w32(o, v);
    b.w32(o + 4, v);
    b.w32(o + 8, 0b100); // integer=1, not open, not empty
}

// ── refinement ─────────────────────────────────────────────────────────

/// Concrete geometry chosen by the refinement (ALSA enums + frame math).
pub(crate) struct Resolved {
    pub format: u32, pub rate: u32, pub channels: u32, pub frame_bytes: u32,
    pub period_frames: u32, pub buffer_frames: u32,
    pub period_bytes: u32, pub buffer_bytes: u32,
}

/// ALSA format → virtio_snd FMT enum (re-exported for the capture path).
/// # C: O(1)
pub(crate) fn fmt_alsa_to_virtio(f: u32) -> u8 { alsa_fmt_to_virtio(f).unwrap_or(5) }
/// Hz → virtio RATE enum (re-exported for the capture path). # C: O(1)
pub(crate) fn rate_hz_to_enum(hz: u32) -> u8 { hz_rate_enum(hz) }

/// Refine the app's snd_pcm_hw_params against `(virtio_formats, virtio_rates,
/// ch_min, ch_max)`, pin each parameter to a concrete supported value,
/// write it back, and return the resolved geometry. Direction-agnostic and
/// device-free — both the playback and capture handlers call this, then
/// apply via their own ops. Returns Err(-errno) on an unsatisfiable request.
/// # C: O(1)
pub(crate) fn refine_params(b: &UserBuf, vf: u64, vr: u64, ch_min: u8, ch_max: u8)
    -> Result<Resolved, i64>
{
    // ACCESS — only RW_INTERLEAVED.
    if !mask_test(b, P_ACCESS, ACCESS_RW_INTERLEAVED) { return Err(err(Errno::Einval)); }
    mask_set_single(b, P_ACCESS, ACCESS_RW_INTERLEAVED);

    // FORMAT — first device-supported format the app permits, by preference.
    const PREF: [u32; 6] = [FMT_S16_LE, FMT_U8, FMT_S8, FMT_U16_LE, FMT_MU_LAW, FMT_A_LAW];
    let mut format = None;
    for &f in &PREF {
        if let Some(ve) = alsa_fmt_to_virtio(f) {
            if (vf >> ve) & 1 != 0 && mask_test(b, P_FORMAT, f) { format = Some(f); break; }
        }
    }
    let format = match format { Some(f) => f, None => return Err(err(Errno::Einval)) };
    mask_set_single(b, P_FORMAT, format);
    mask_set_single(b, P_SUBFORMAT, 0); // STD

    // CHANNELS — clamp the app's requested min into the device range.
    let want_ch = iv_min(b, P_CHANNELS).max(1);
    if iv_max(b, P_CHANNELS).max(1) < ch_min as u32 || want_ch > ch_max as u32 {
        return Err(err(Errno::Einval));
    }
    let channels = want_ch.clamp(ch_min as u32, ch_max as u32);
    iv_set(b, P_CHANNELS, channels);

    // RATE — a device-supported rate within the app's [min,max], preferring
    // common rates.
    let (rmin, rmax) = (iv_min(b, P_RATE), iv_max(b, P_RATE).max(iv_min(b, P_RATE)));
    const RPREF: [u32; 8] = [44100, 48000, 22050, 32000, 16000, 11025, 8000, 96000];
    let mut rate = None;
    for &hz in &RPREF {
        let ve = hz_rate_enum(hz);
        if (vr >> ve) & 1 != 0 && hz >= rmin && hz <= rmax { rate = Some(hz); break; }
    }
    // Fallback: any supported rate inside the window.
    let rate = rate.or_else(|| {
        (0u8..14).map(rate_enum_hz)
            .find(|&hz| { let ve = hz_rate_enum(hz); (vr >> ve) & 1 != 0 && hz >= rmin && hz <= rmax })
    });
    let rate = match rate { Some(r) => r, None => return Err(err(Errno::Einval)) };
    iv_set(b, P_RATE, rate);

    // Derived bit/byte/period/buffer geometry.
    let sbits = fmt_bits(format);
    let frame_bytes = (sbits / 8) * channels;
    iv_set(b, P_SAMPLE_BITS, sbits);
    iv_set(b, P_FRAME_BITS, sbits * channels);

    // PERIOD: honour the app's period_bytes/period_size if pinned, else default.
    let pb = iv_min(b, P_PERIOD_BYTES);
    let ps = iv_min(b, P_PERIOD_SIZE);
    let period_bytes = if pb != 0 { pb }
        else if ps != 0 { ps * frame_bytes }
        else { DEF_PERIOD_BYTES };
    let period_bytes = period_bytes.clamp(frame_bytes.max(1), 0x1000);
    let period_frames = (period_bytes / frame_bytes.max(1)).max(1);
    let period_bytes = period_frames * frame_bytes;

    let periods = {
        let p = iv_min(b, P_PERIODS);
        if p >= 2 { p } else { DEF_PERIODS }
    };
    let buffer_frames = period_frames * periods;
    let buffer_bytes = buffer_frames * frame_bytes;

    iv_set(b, P_PERIOD_SIZE, period_frames);
    iv_set(b, P_PERIOD_BYTES, period_bytes);
    iv_set(b, P_PERIODS, periods);
    iv_set(b, P_BUFFER_SIZE, buffer_frames);
    iv_set(b, P_BUFFER_BYTES, buffer_bytes);
    iv_set(b, P_PERIOD_TIME, ((period_frames as u64 * 1_000_000) / rate as u64) as u32);
    iv_set(b, P_BUFFER_TIME, ((buffer_frames as u64 * 1_000_000) / rate as u64) as u32);

    // Result fields.
    b.w32(HWP_CMASK, 0xFFFF_FFFF);
    b.w32(HWP_INFO, PCM_INFO_FLAGS);
    b.w32(HWP_MSBITS, sbits);
    b.w32(HWP_RATE_NUM, rate);
    b.w32(HWP_RATE_DEN, 1);
    b.w64(HWP_FIFO_SIZE, 0);

    Ok(Resolved {
        format, rate, channels, frame_bytes: frame_bytes.max(1),
        period_frames, buffer_frames, period_bytes, buffer_bytes,
    })
}

/// Playback HW_REFINE/HW_PARAMS: refine against the OUTPUT caps; on commit
/// apply via the playback ops + record the substream geometry. # C: O(CONTROLQ)
fn refine(owner: u32, b: &UserBuf, commit: bool) -> i64 {
    let Some((vf, vr, ch_min, ch_max)) = caps(owner) else {
        return err(Errno::Enodev);
    };
    let r = match refine_params(b, vf, vr, ch_min, ch_max) { Ok(r) => r, Err(e) => return e };
    if commit {
        if !crate::ops::pcm_hw_params(owner, rate_hz_to_enum(r.rate), fmt_alsa_to_virtio(r.format),
                                      r.channels as u8, r.period_bytes, r.buffer_bytes) {
            return err(Errno::Eio);
        }
        let mut guard = PCM.lock();
        let Some(p) = guard.iter_mut().find(|p| p.owner == owner) else {
            return err(Errno::Enodev);
        };
        p.format = r.format; p.rate = r.rate; p.channels = r.channels;
        p.frame_bytes = r.frame_bytes;
        p.period_frames = r.period_frames; p.buffer_frames = r.buffer_frames;
        p.state = STATE_SETUP;
        p.appl_ptr = 0; p.hw_ptr = 0;
    }
    0
}

// ── ioctl dispatch ─────────────────────────────────────────────────────

/// Handle one `SNDRV_PCM_IOCTL_*` on the playback substream. The caller has
/// already matched the node; `nr` is the ioctl nr (magic 'A' stripped).
/// # C: O(1) excluding the blocking transfer in WRITEI
pub fn handle(owner: u32, nr: u64, arg: u64) -> i64 {
    match nr {
        PCM_PVERSION => write_int(arg, SNDRV_PCM_VERSION),
        PCM_INFO => pcm_info(owner, arg),
        PCM_TSTAMP | PCM_TTSTAMP => 0,
        PCM_HW_REFINE => match UserBuf::new(arg, HW_PARAMS_SIZE) {
            Some(b) => refine(owner, &b, false), None => err(Errno::Efault),
        },
        PCM_HW_PARAMS => match UserBuf::new(arg, HW_PARAMS_SIZE) {
            Some(b) => refine(owner, &b, true), None => err(Errno::Efault),
        },
        PCM_HW_FREE => {
            if !crate::ops::pcm_hw_free(owner) {
                return err(Errno::Eio);
            }
            let mut guard = PCM.lock();
            let Some(p) = guard.iter_mut().find(|p| p.owner == owner) else {
                return err(Errno::Enodev);
            };
            p.state = STATE_OPEN;
            0
        }
        PCM_SW_PARAMS => sw_params(owner, arg),
        PCM_PREPARE => {
            if !crate::ops::pcm_prepare(owner) { return err(Errno::Eio); }
            let mut guard = PCM.lock();
            let Some(p) = guard.iter_mut().find(|p| p.owner == owner) else {
                return err(Errno::Enodev);
            };
            p.state = STATE_PREPARED; p.appl_ptr = 0; p.hw_ptr = 0; 0
        }
        PCM_START => {
            if !crate::ops::pcm_trigger(owner, true) { return err(Errno::Eio); }
            let mut guard = PCM.lock();
            let Some(p) = guard.iter_mut().find(|p| p.owner == owner) else {
                return err(Errno::Enodev);
            };
            p.state = STATE_RUNNING; 0
        }
        PCM_DROP | PCM_DRAIN => {
            if !crate::ops::pcm_trigger(owner, false) {
                return err(Errno::Eio);
            }
            let mut guard = PCM.lock();
            let Some(p) = guard.iter_mut().find(|p| p.owner == owner) else {
                return err(Errno::Enodev);
            };
            p.state = STATE_SETUP; p.appl_ptr = 0; p.hw_ptr = 0; 0
        }
        PCM_PAUSE => err(Errno::Enotty),
        PCM_HWSYNC => 0,
        PCM_DELAY => write_long(arg, 0),
        PCM_STATUS => pcm_status(owner, arg),
        PCM_SYNC_PTR => sync_ptr(owner, arg),
        PCM_WRITEI => writei(owner, arg),
        PCM_READI => err(Errno::Ebadf), // capture is a follow-up (RXQ)
        _ => err(Errno::Enotty),
    }
}

/// Raw `write(2)` on the pcm fd — the byte-stream equivalent of WRITEI on
/// the configured geometry (snd_pcm_write). Auto-starts a PREPARED stream,
/// transfers (blocking), advances appl_ptr/hw_ptr. Returns bytes accepted.
/// # C: O(bytes/period × TXQ round-trip)
pub fn write_bytes(owner: u32, buf: &[u8]) -> usize {
    let (fb, state) = {
        let guard = PCM.lock();
        let Some(p) = guard.iter().find(|p| p.owner == owner) else {
            return 0;
        };
        (p.frame_bytes as u64, p.state)
    };
    if state == STATE_OPEN || state == STATE_SETUP { return 0; }
    if state == STATE_PREPARED {
        if !crate::ops::pcm_trigger(owner, true) { return 0; }
        let mut guard = PCM.lock();
        let Some(p) = guard.iter_mut().find(|p| p.owner == owner) else {
            return 0;
        };
        p.state = STATE_RUNNING;
    }
    let n = crate::ops::pcm_submit(owner, buf);
    if n > 0 {
        let frames = n as u64 / fb.max(1);
        let mut guard = PCM.lock();
        let Some(p) = guard.iter_mut().find(|p| p.owner == owner) else {
            return n;
        };
        p.appl_ptr = p.appl_ptr.wrapping_add(frames) % BOUNDARY;
        p.hw_ptr = p.appl_ptr;
    }
    n
}

fn write_int(arg: u64, v: u32) -> i64 {
    match UserBuf::new(arg, 4) { Some(b) => { b.w32(0, v); 0 } None => err(Errno::Efault) }
}
fn write_long(arg: u64, v: u64) -> i64 {
    match UserBuf::new(arg, 8) { Some(b) => { b.w64(0, v); 0 } None => err(Errno::Efault) }
}

fn pcm_info(owner: u32, arg: u64) -> i64 {
    if caps(owner).is_none() || !is_registered(owner) {
        return err(Errno::Enodev);
    }
    let b = match UserBuf::new(arg, PCM_INFO_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    b.zero(0, PCM_INFO_SIZE);
    b.w32(PI_DEVICE, 0);
    b.w32(PI_SUBDEVICE, 0);
    b.w32(PI_STREAM, STREAM_PLAYBACK as u32);
    b.w32(PI_CARD, 0);
    b.wstr(PI_ID, b"virtio-snd", 64);
    b.wstr(PI_NAME, b"virtio-snd PCM", 80);
    b.wstr(PI_SUBNAME, b"subdevice #0", 32);
    b.w32(PI_SUBDEVICES_COUNT, 1);
    b.w32(PI_SUBDEVICES_AVAIL, 1);
    0
}

fn sw_params(owner: u32, arg: u64) -> i64 {
    let b = match UserBuf::new(arg, SW_PARAMS_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let st = b.r64(SWP_START_THRESHOLD);
    let mut guard = PCM.lock();
    let Some(p) = guard.iter_mut().find(|p| p.owner == owner) else {
        return err(Errno::Enodev);
    };
    p.start_threshold = if st == 0 { 1 } else { st };
    b.w64(SWP_BOUNDARY, BOUNDARY); // echo the wrap point back
    0
}

fn pcm_status(owner: u32, arg: u64) -> i64 {
    let b = match UserBuf::new(arg, STATUS_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let guard = PCM.lock();
    let Some(p) = guard.iter().find(|p| p.owner == owner) else {
        return err(Errno::Enodev);
    };
    let avail = p.buffer_frames as u64; // synchronous transfer → buffer always free
    b.zero(0, STATUS_SIZE);
    b.w32(ST_STATE, p.state);
    b.w64(ST_APPL_PTR, p.appl_ptr);
    b.w64(ST_HW_PTR, p.hw_ptr);
    b.w64(ST_AVAIL, avail);
    b.w64(ST_AVAIL_MAX, avail);
    0
}

fn sync_ptr(owner: u32, arg: u64) -> i64 {
    let b = match UserBuf::new(arg, SYNC_PTR_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let flags = b.r32(SP_FLAGS);
    let mut guard = PCM.lock();
    let Some(p) = guard.iter_mut().find(|p| p.owner == owner) else {
        return err(Errno::Enodev);
    };
    if flags & SYNC_PTR_APPL == 0 {
        p.appl_ptr = b.r64(SP_CONTROL_APPL_PTR);
    }
    b.w32(SP_STATUS_STATE, p.state);
    b.w64(SP_STATUS_HW_PTR, p.hw_ptr);
    b.w64(SP_CONTROL_APPL_PTR, p.appl_ptr);
    0
}

/// SNDRV_PCM_IOCTL_WRITEI_FRAMES — interleaved blocking playback. Copies the
/// app frames out of `buf`, auto-starts at the start_threshold, transfers
/// via the driver, and advances appl_ptr/hw_ptr. Returns frames written.
fn writei(owner: u32, arg: u64) -> i64 {
    let xf = match UserBuf::new(arg, XFERI_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let ubuf = xf.r64(XFERI_BUF);
    let frames = xf.r64(XFERI_FRAMES);
    let (fb, mut state, start_thr) = {
        let guard = PCM.lock();
        let Some(p) = guard.iter().find(|p| p.owner == owner) else {
            return err(Errno::Enodev);
        };
        (p.frame_bytes as u64, p.state, p.start_threshold)
    };
    if fb == 0 || frames == 0 { return 0; }
    let bytes = frames * fb;
    let src = match UserBuf::new(ubuf, bytes as usize) { Some(b) => b, None => return err(Errno::Efault) };

    if state == STATE_OPEN || state == STATE_SETUP { return err(Errno::Ebadf); }

    // Auto-start once enough has been queued (snd_pcm start_threshold).
    if state == STATE_PREPARED {
        let appl = {
            let guard = PCM.lock();
            let Some(p) = guard.iter().find(|p| p.owner == owner) else {
                return err(Errno::Enodev);
            };
            p.appl_ptr
        };
        if appl + frames >= start_thr {
            if !crate::ops::pcm_trigger(owner, true) { return err(Errno::Eio); }
            let mut guard = PCM.lock();
            let Some(p) = guard.iter_mut().find(|p| p.owner == owner) else {
                return err(Errno::Enodev);
            };
            p.state = STATE_RUNNING;
            state = STATE_RUNNING;
        }
    }
    if state != STATE_RUNNING { /* still buffering before threshold */ }

    // Copy the interleaved frames into a kernel staging buffer one period at
    // a time and submit; pcm_submit blocks until the device consumes it.
    let mut staged = [0u8; 0x1000];
    let mut done: u64 = 0;
    while done < bytes {
        let chunk = ((bytes - done) as usize).min(staged.len());
        for i in 0..chunk { staged[i] = src.r8(done as usize + i); }
        let n = crate::ops::pcm_submit(owner, &staged[..chunk]);
        if n == 0 { break; }
        done += n as u64;
        if n < chunk { break; }
    }
    let wrote_frames = done / fb;
    {
        let mut guard = PCM.lock();
        let Some(p) = guard.iter_mut().find(|p| p.owner == owner) else {
            return err(Errno::Enodev);
        };
        p.appl_ptr = p.appl_ptr.wrapping_add(wrote_frames) % BOUNDARY;
        p.hw_ptr = p.appl_ptr;
    }
    // snd_xferi.result is also set by libasound from the return value; echo it.
    xf.w64(XFERI_RESULT, wrote_frames);
    if wrote_frames == 0 { err(Errno::Eio) } else { wrote_frames as i64 }
}
