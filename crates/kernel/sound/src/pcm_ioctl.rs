use syscall::errno::Errno;

use crate::pcm::pcm_refine::{fmt_alsa_to_virtio, rate_hz_to_enum, refine_params};
use crate::pcm::pcm_state::{is_registered, PCM};
use crate::uapi::*;

const BOUNDARY: u64 = 0x4000_0000_0000;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn caps(owner: crate::SoundOwnerKey) -> Option<(u64, u64, u8, u8)> { crate::ops::pcm_caps(owner) }

fn refine(owner: crate::SoundOwnerKey, b: &UserBuf, commit: bool) -> i64 {
    let Some((vf, vr, ch_min, ch_max)) = caps(owner) else { return err(Errno::Enodev); };
    let r = match refine_params(b, vf, vr, ch_min, ch_max) { Ok(r) => r, Err(e) => return e };
    if commit {
        let Some(format) = fmt_alsa_to_virtio(r.format) else { return err(Errno::Einval); };
        if !crate::ops::pcm_hw_params(owner, rate_hz_to_enum(r.rate), format, r.channels as u8, r.period_bytes, r.buffer_bytes) {
            return err(Errno::Eio);
        }
        let mut guard = PCM.lock();
        let Some(p) = guard.iter_mut().find(|p| p.owner == owner) else { return err(Errno::Enodev); };
        p.format = r.format;
        p.rate = r.rate;
        p.channels = r.channels;
        p.frame_bytes = r.frame_bytes;
        p.period_frames = r.period_frames;
        p.buffer_frames = r.buffer_frames;
        p.state = STATE_SETUP;
        p.appl_ptr = 0;
        p.hw_ptr = 0;
    }
    0
}

/// Handle one `SNDRV_PCM_IOCTL_*` on the playback substream.
/// # C: O(1) excluding the blocking transfer in WRITEI
pub fn handle(owner: crate::SoundOwnerKey, card: u32, nr: u64, arg: u64) -> i64 {
    match nr {
        PCM_PVERSION => write_int(arg, SNDRV_PCM_VERSION),
        PCM_INFO => pcm_info(owner, card, arg),
        PCM_TSTAMP | PCM_TTSTAMP => err(Errno::Enotty),
        PCM_HW_REFINE => match UserBuf::new(arg, HW_PARAMS_SIZE) { Some(b) => refine(owner, &b, false), None => err(Errno::Efault) },
        PCM_HW_PARAMS => match UserBuf::new(arg, HW_PARAMS_SIZE) { Some(b) => refine(owner, &b, true), None => err(Errno::Efault) },
        PCM_HW_FREE => hw_free(owner),
        PCM_SW_PARAMS => sw_params(owner, arg),
        PCM_PREPARE => prepare(owner),
        PCM_START => start(owner),
        PCM_DROP | PCM_DRAIN => drop_stream(owner),
        PCM_PAUSE => err(Errno::Enotty),
        PCM_HWSYNC => 0,
        PCM_DELAY => write_long(arg, 0),
        PCM_STATUS => pcm_status(owner, arg),
        PCM_SYNC_PTR => sync_ptr(owner, arg),
        PCM_WRITEI => writei(owner, arg),
        PCM_READI => err(Errno::Ebadf),
        _ => err(Errno::Enotty),
    }
}

/// Raw `write(2)` on the pcm fd.
/// # C: O(bytes/period × TXQ round-trip)
pub fn write_bytes(owner: crate::SoundOwnerKey, buf: &[u8]) -> usize {
    let (fb, state) = {
        let guard = PCM.lock();
        let Some(p) = guard.iter().find(|p| p.owner == owner) else { return 0; };
        (p.frame_bytes as u64, p.state)
    };
    if state == STATE_OPEN || state == STATE_SETUP { return 0; }
    if state == STATE_PREPARED {
        if !crate::ops::pcm_trigger(owner, true) { return 0; }
        let mut guard = PCM.lock();
        let Some(p) = guard.iter_mut().find(|p| p.owner == owner) else { return 0; };
        p.state = STATE_RUNNING;
    }
    let n = crate::ops::pcm_submit(owner, buf);
    if n > 0 {
        let frames = n as u64 / fb.max(1);
        let mut guard = PCM.lock();
        let Some(p) = guard.iter_mut().find(|p| p.owner == owner) else { return n; };
        p.appl_ptr = p.appl_ptr.wrapping_add(frames) % BOUNDARY;
        p.hw_ptr = p.appl_ptr;
    }
    n
}

fn hw_free(owner: crate::SoundOwnerKey) -> i64 {
    if !crate::ops::pcm_hw_free(owner) { return err(Errno::Eio); }
    let mut guard = PCM.lock();
    let Some(p) = guard.iter_mut().find(|p| p.owner == owner) else { return err(Errno::Enodev); };
    p.state = STATE_OPEN;
    0
}

fn prepare(owner: crate::SoundOwnerKey) -> i64 {
    if !crate::ops::pcm_prepare(owner) { return err(Errno::Eio); }
    let mut guard = PCM.lock();
    let Some(p) = guard.iter_mut().find(|p| p.owner == owner) else { return err(Errno::Enodev); };
    p.state = STATE_PREPARED;
    p.appl_ptr = 0;
    p.hw_ptr = 0;
    0
}

fn start(owner: crate::SoundOwnerKey) -> i64 {
    if !crate::ops::pcm_trigger(owner, true) { return err(Errno::Eio); }
    let mut guard = PCM.lock();
    let Some(p) = guard.iter_mut().find(|p| p.owner == owner) else { return err(Errno::Enodev); };
    p.state = STATE_RUNNING;
    0
}

fn drop_stream(owner: crate::SoundOwnerKey) -> i64 {
    if !crate::ops::pcm_trigger(owner, false) { return err(Errno::Eio); }
    let mut guard = PCM.lock();
    let Some(p) = guard.iter_mut().find(|p| p.owner == owner) else { return err(Errno::Enodev); };
    p.state = STATE_SETUP;
    p.appl_ptr = 0;
    p.hw_ptr = 0;
    0
}

fn write_int(arg: u64, v: u32) -> i64 {
    match UserBuf::new(arg, 4) { Some(b) => { b.w32(0, v); 0 } None => err(Errno::Efault) }
}

fn write_long(arg: u64, v: u64) -> i64 {
    match UserBuf::new(arg, 8) { Some(b) => { b.w64(0, v); 0 } None => err(Errno::Efault) }
}

fn pcm_info(owner: crate::SoundOwnerKey, card: u32, arg: u64) -> i64 {
    if caps(owner).is_none() || !is_registered(owner) { return err(Errno::Enodev); }
    let b = match UserBuf::new(arg, PCM_INFO_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    b.zero(0, PCM_INFO_SIZE);
    b.w32(PI_DEVICE, 0);
    b.w32(PI_SUBDEVICE, 0);
    b.w32(PI_STREAM, STREAM_PLAYBACK as u32);
    b.w32(PI_CARD, card);
    b.wstr(PI_ID, b"virtio-snd", 64);
    b.wstr(PI_NAME, b"virtio-snd PCM", 80);
    b.wstr(PI_SUBNAME, b"subdevice #0", 32);
    b.w32(PI_SUBDEVICES_COUNT, 1);
    b.w32(PI_SUBDEVICES_AVAIL, 1);
    0
}

fn sw_params(owner: crate::SoundOwnerKey, arg: u64) -> i64 {
    let b = match UserBuf::new(arg, SW_PARAMS_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let st = b.r64(SWP_START_THRESHOLD);
    let mut guard = PCM.lock();
    let Some(p) = guard.iter_mut().find(|p| p.owner == owner) else { return err(Errno::Enodev); };
    p.start_threshold = if st == 0 { 1 } else { st };
    b.w64(SWP_BOUNDARY, BOUNDARY);
    0
}

fn pcm_status(owner: crate::SoundOwnerKey, arg: u64) -> i64 {
    let b = match UserBuf::new(arg, STATUS_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let guard = PCM.lock();
    let Some(p) = guard.iter().find(|p| p.owner == owner) else { return err(Errno::Enodev); };
    let avail = p.buffer_frames as u64;
    b.zero(0, STATUS_SIZE);
    b.w32(ST_STATE, p.state);
    b.w64(ST_APPL_PTR, p.appl_ptr);
    b.w64(ST_HW_PTR, p.hw_ptr);
    b.w64(ST_AVAIL, avail);
    b.w64(ST_AVAIL_MAX, avail);
    0
}

fn sync_ptr(owner: crate::SoundOwnerKey, arg: u64) -> i64 {
    let b = match UserBuf::new(arg, SYNC_PTR_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let flags = b.r32(SP_FLAGS);
    let mut guard = PCM.lock();
    let Some(p) = guard.iter_mut().find(|p| p.owner == owner) else { return err(Errno::Enodev); };
    if flags & SYNC_PTR_APPL == 0 {
        p.appl_ptr = b.r64(SP_CONTROL_APPL_PTR);
    }
    b.w32(SP_STATUS_STATE, p.state);
    b.w64(SP_STATUS_HW_PTR, p.hw_ptr);
    b.w64(SP_CONTROL_APPL_PTR, p.appl_ptr);
    0
}

fn writei(owner: crate::SoundOwnerKey, arg: u64) -> i64 {
    let xf = match UserBuf::new(arg, XFERI_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let ubuf = xf.r64(XFERI_BUF);
    let frames = xf.r64(XFERI_FRAMES);
    let (fb, mut state, start_thr) = {
        let guard = PCM.lock();
        let Some(p) = guard.iter().find(|p| p.owner == owner) else { return err(Errno::Enodev); };
        (p.frame_bytes as u64, p.state, p.start_threshold)
    };
    if fb == 0 || frames == 0 { return 0; }
    let bytes = frames * fb;
    let src = match UserBuf::new(ubuf, bytes as usize) { Some(b) => b, None => return err(Errno::Efault) };
    if state == STATE_OPEN || state == STATE_SETUP { return err(Errno::Ebadf); }

    if state == STATE_PREPARED {
        let appl = {
            let guard = PCM.lock();
            let Some(p) = guard.iter().find(|p| p.owner == owner) else { return err(Errno::Enodev); };
            p.appl_ptr
        };
        if appl + frames >= start_thr {
            if !crate::ops::pcm_trigger(owner, true) { return err(Errno::Eio); }
            let mut guard = PCM.lock();
            let Some(p) = guard.iter_mut().find(|p| p.owner == owner) else { return err(Errno::Enodev); };
            p.state = STATE_RUNNING;
            state = STATE_RUNNING;
        }
    }
    if state != STATE_RUNNING {}

    let mut staged = [0u8; hal::PAGE_SIZE_BYTES as usize];
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
        let Some(p) = guard.iter_mut().find(|p| p.owner == owner) else { return err(Errno::Enodev); };
        p.appl_ptr = p.appl_ptr.wrapping_add(wrote_frames) % BOUNDARY;
        p.hw_ptr = p.appl_ptr;
    }
    xf.w64(XFERI_RESULT, wrote_frames);
    if wrote_frames == 0 { err(Errno::Eio) } else { wrote_frames as i64 }
}
