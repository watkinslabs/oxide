use syscall::errno::Errno;

use crate::pcm::pcm_refine::{limits_for, refine_params};
use crate::pcm::pcm_state::{is_registered, PCM};
use crate::uapi::*;

const BOUNDARY: u64 = 0x4000_0000_0000;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn caps(owner: crate::SoundOwnerKey, device: crate::ops::PcmDevice) -> Option<(u64, u64, u8, u8)> { crate::ops::pcm_caps_for(owner, device) }

fn refine(owner: crate::SoundOwnerKey, device: crate::ops::PcmDevice, b: &UserBuf, commit: bool) -> i64 {
    let Some((vf, vr, ch_min, ch_max)) = caps(owner, device) else { return err(Errno::Enodev); };
    let r = match refine_params(b, vf, vr, ch_min, ch_max, &limits_for(owner, device), crate::ops::info_flags_for(owner, device)) { Ok(r) => r, Err(e) => return e };
    if commit {
        if !crate::ops::pcm_hw_params_for(owner, device, r.format, r.rate, r.channels as u8, r.period_bytes, r.buffer_bytes) {
            return err(Errno::Eio);
        }
        let mut guard = PCM.lock();
        let Some(p) = guard.iter_mut().find(|p| p.owner == owner && p.device == device) else { return err(Errno::Enodev); };
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
pub fn handle(owner: crate::SoundOwnerKey, card: u32, device: crate::ops::PcmDevice, nr: u64, arg: u64) -> i64 {
    match nr {
        PCM_PVERSION => write_int(arg, SNDRV_PCM_VERSION),
        PCM_INFO => pcm_info(owner, card, device, arg),
        PCM_TSTAMP | PCM_TTSTAMP => tstamp(owner, device, arg),
        PCM_HW_REFINE => match UserBuf::new(arg, HW_PARAMS_SIZE) { Some(b) => refine(owner, device, &b, false), None => err(Errno::Efault) },
        PCM_HW_PARAMS => match UserBuf::new(arg, HW_PARAMS_SIZE) { Some(b) => refine(owner, device, &b, true), None => err(Errno::Efault) },
        PCM_HW_FREE => hw_free(owner, device),
        PCM_SW_PARAMS => sw_params(owner, device, arg),
        PCM_PREPARE => prepare(owner, device),
        PCM_START => start(owner, device),
        PCM_DROP => drop_stream(owner, device),
        PCM_DRAIN => drain(owner, device),
        PCM_PAUSE => pause(owner, device, arg),
        PCM_RESET => reset(owner, device),
        PCM_HWSYNC => { sync_hw_ptr(owner, device); 0 }
        PCM_DELAY => delay(owner, device, arg),
        PCM_STATUS => pcm_status(owner, device, arg),
        PCM_SYNC_PTR => sync_ptr(owner, device, arg),
        PCM_WRITEI => writei(owner, device, arg),
        PCM_READI => err(Errno::Ebadf),
        _ => err(Errno::Enotty),
    }
}

/// Raw `write(2)` on the pcm fd.
/// # C: O(bytes/period × TXQ round-trip)
pub fn write_bytes(owner: crate::SoundOwnerKey, device: crate::ops::PcmDevice, buf: &[u8]) -> usize {
    let (fb, state) = {
        let guard = PCM.lock();
        let Some(p) = guard.iter().find(|p| p.owner == owner && p.device == device) else { return 0; };
        (p.frame_bytes as u64, p.state)
    };
    if state == STATE_OPEN || state == STATE_SETUP { return 0; }
    if state == STATE_PREPARED {
        if !crate::ops::pcm_trigger_for(owner, device, true) { return 0; }
        let mut guard = PCM.lock();
        let Some(p) = guard.iter_mut().find(|p| p.owner == owner && p.device == device) else { return 0; };
        p.state = STATE_RUNNING;
        p.time.stamp_trigger();
    }
    let n = crate::ops::pcm_submit_for(owner, device, buf);
    if n > 0 {
        let frames = n as u64 / fb.max(1);
        let reported = crate::ops::pcm_pointer_for(owner, device);
        let mut guard = PCM.lock();
        let Some(p) = guard.iter_mut().find(|p| p.owner == owner && p.device == device) else { return n; };
        p.appl_ptr = p.appl_ptr.wrapping_add(frames) % BOUNDARY;
        p.hw_ptr = reported.map(|f| f % BOUNDARY).unwrap_or(p.appl_ptr);
    }
    n
}

/// Refresh `hw_ptr` from the card's real DMA position when it reports one.
/// Without a reporting card the core keeps `hw_ptr` at `appl_ptr`, which is
/// the truthful answer for a blocking submit path.
/// # C: O(1)
fn sync_hw_ptr(owner: crate::SoundOwnerKey, device: crate::ops::PcmDevice) {
    let Some(frames) = crate::ops::pcm_pointer_for(owner, device) else { return; };
    let mut guard = PCM.lock();
    let Some(p) = guard.iter_mut().find(|p| p.owner == owner && p.device == device) else { return; };
    p.hw_ptr = frames % BOUNDARY;
}

/// SNDRV_PCM_IOCTL_DELAY: frames queued ahead of the hardware.
fn delay(owner: crate::SoundOwnerKey, device: crate::ops::PcmDevice, arg: u64) -> i64 {
    sync_hw_ptr(owner, device);
    let guard = PCM.lock();
    let Some(p) = guard.iter().find(|p| p.owner == owner && p.device == device) else { return err(Errno::Enodev); };
    write_long(arg, p.appl_ptr.saturating_sub(p.hw_ptr))
}

/// SNDRV_PCM_IOCTL_PAUSE: `arg` non-zero pauses, zero releases.
fn pause(owner: crate::SoundOwnerKey, device: crate::ops::PcmDevice, arg: u64) -> i64 {
    let want_pause = arg != 0;
    if crate::ops::info_flags_for(owner, device) & PCM_INFO_PAUSE == 0 { return err(Errno::Enosys); }
    {
        let guard = PCM.lock();
        let Some(p) = guard.iter().find(|p| p.owner == owner && p.device == device) else { return err(Errno::Enodev); };
        if want_pause && p.state != STATE_RUNNING { return err(Errno::Ebadfd); }
        if !want_pause && p.state != STATE_PAUSED { return err(Errno::Ebadfd); }
    }
    if !crate::ops::pcm_pause_for(owner, device, want_pause) { return err(Errno::Enotty); }
    let mut guard = PCM.lock();
    let Some(p) = guard.iter_mut().find(|p| p.owner == owner && p.device == device) else { return err(Errno::Enodev); };
    p.state = if want_pause { STATE_PAUSED } else { STATE_RUNNING };
    p.time.stamp_trigger();
    0
}

/// SNDRV_PCM_IOCTL_DRAIN: play out what is queued, then stop.
fn drain(owner: crate::SoundOwnerKey, device: crate::ops::PcmDevice) -> i64 {
    let state = {
        let guard = PCM.lock();
        let Some(p) = guard.iter().find(|p| p.owner == owner && p.device == device) else { return err(Errno::Enodev); };
        p.state
    };
    if state == STATE_OPEN { return err(Errno::Ebadfd); }
    if state == STATE_RUNNING && !crate::ops::pcm_drain_for(owner, device) { return err(Errno::Eio); }
    drop_stream(owner, device)
}

/// SNDRV_PCM_IOCTL_RESET: zero the pointers without leaving PREPARED.
fn reset(owner: crate::SoundOwnerKey, device: crate::ops::PcmDevice) -> i64 {
    let mut guard = PCM.lock();
    let Some(p) = guard.iter_mut().find(|p| p.owner == owner && p.device == device) else { return err(Errno::Enodev); };
    p.appl_ptr = 0;
    p.hw_ptr = 0;
    0
}

fn hw_free(owner: crate::SoundOwnerKey, device: crate::ops::PcmDevice) -> i64 {
    if !crate::ops::pcm_hw_free_for(owner, device) { return err(Errno::Eio); }
    let mut guard = PCM.lock();
    let Some(p) = guard.iter_mut().find(|p| p.owner == owner && p.device == device) else { return err(Errno::Enodev); };
    p.state = STATE_OPEN;
    0
}

fn prepare(owner: crate::SoundOwnerKey, device: crate::ops::PcmDevice) -> i64 {
    if !crate::ops::pcm_prepare_for(owner, device) { return err(Errno::Eio); }
    let mut guard = PCM.lock();
    let Some(p) = guard.iter_mut().find(|p| p.owner == owner && p.device == device) else { return err(Errno::Enodev); };
    p.state = STATE_PREPARED;
    p.appl_ptr = 0;
    p.hw_ptr = 0;
    0
}

fn start(owner: crate::SoundOwnerKey, device: crate::ops::PcmDevice) -> i64 {
    if !crate::ops::pcm_trigger_for(owner, device, true) { return err(Errno::Eio); }
    let mut guard = PCM.lock();
    let Some(p) = guard.iter_mut().find(|p| p.owner == owner && p.device == device) else { return err(Errno::Enodev); };
    p.state = STATE_RUNNING;
    p.time.stamp_trigger();
    0
}

fn drop_stream(owner: crate::SoundOwnerKey, device: crate::ops::PcmDevice) -> i64 {
    if !crate::ops::pcm_trigger_for(owner, device, false) { return err(Errno::Eio); }
    let mut guard = PCM.lock();
    let Some(p) = guard.iter_mut().find(|p| p.owner == owner && p.device == device) else { return err(Errno::Enodev); };
    p.state = STATE_SETUP;
    p.appl_ptr = 0;
    p.hw_ptr = 0;
    p.time.stamp_trigger();
    0
}

fn write_int(arg: u64, v: u32) -> i64 {
    match UserBuf::new(arg, 4) { Some(b) => { b.w32(0, v); 0 } None => err(Errno::Efault) }
}

fn write_long(arg: u64, v: u64) -> i64 {
    match UserBuf::new(arg, 8) { Some(b) => { b.w64(0, v); 0 } None => err(Errno::Efault) }
}

fn tstamp(owner: crate::SoundOwnerKey, device: crate::ops::PcmDevice, arg: u64) -> i64 {
    let b = match UserBuf::new(arg, 4) { Some(b) => b, None => return err(Errno::Efault) };
    let mut guard = PCM.lock();
    let Some(p) = guard.iter_mut().find(|p| p.owner == owner && p.device == device) else { return err(Errno::Enodev); };
    match p.time.set_kind(b.r32(0)) { Ok(()) => 0, Err(e) => err(e) }
}

fn pcm_info(owner: crate::SoundOwnerKey, card: u32, device: crate::ops::PcmDevice, arg: u64) -> i64 {
    if caps(owner, device).is_none() || !is_registered(owner) { return err(Errno::Enodev); }
    let b = match UserBuf::new(arg, PCM_INFO_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let Some(ident) = crate::ops::identity(owner) else { return err(Errno::Enodev); };
    crate::pcm_info::write(&b, card, device, STREAM_PLAYBACK, &ident.id,
                           &crate::identity::pcm_stream_name(&ident, false));
    0
}

fn sw_params(owner: crate::SoundOwnerKey, device: crate::ops::PcmDevice, arg: u64) -> i64 {
    let b = match UserBuf::new(arg, SW_PARAMS_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let st = b.r64(SWP_START_THRESHOLD);
    let mut guard = PCM.lock();
    let Some(p) = guard.iter_mut().find(|p| p.owner == owner && p.device == device) else { return err(Errno::Enodev); };
    if let Err(e) = p.time.apply_sw(&b) { return err(e); }
    p.start_threshold = if st == 0 { 1 } else { st };
    b.w64(SWP_BOUNDARY, BOUNDARY);
    0
}

fn pcm_status(owner: crate::SoundOwnerKey, device: crate::ops::PcmDevice, arg: u64) -> i64 {
    let b = match UserBuf::new(arg, STATUS_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    sync_hw_ptr(owner, device);
    let guard = PCM.lock();
    let Some(p) = guard.iter().find(|p| p.owner == owner && p.device == device) else { return err(Errno::Enodev); };
    let avail = p.buffer_frames as u64;
    b.zero(0, STATUS_SIZE);
    b.w32(ST_STATE, p.state);
    b.w64(ST_APPL_PTR, p.appl_ptr);
    b.w64(ST_HW_PTR, p.hw_ptr);
    b.w64(ST_AVAIL, avail);
    b.w64(ST_AVAIL_MAX, avail);
    p.time.write_status(&b, p.state);
    0
}

fn sync_ptr(owner: crate::SoundOwnerKey, device: crate::ops::PcmDevice, arg: u64) -> i64 {
    let b = match UserBuf::new(arg, SYNC_PTR_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let flags = b.r32(SP_FLAGS);
    if flags & SYNC_PTR_HWSYNC != 0 { sync_hw_ptr(owner, device); }
    let mut guard = PCM.lock();
    let Some(p) = guard.iter_mut().find(|p| p.owner == owner && p.device == device) else { return err(Errno::Enodev); };
    if flags & SYNC_PTR_APPL == 0 {
        p.appl_ptr = b.r64(SP_CONTROL_APPL_PTR);
    }
    b.w32(SP_STATUS_STATE, p.state);
    b.w64(SP_STATUS_HW_PTR, p.hw_ptr);
    b.w64(SP_CONTROL_APPL_PTR, p.appl_ptr);
    p.time.write_sync(&b, p.state);
    0
}

fn writei(owner: crate::SoundOwnerKey, device: crate::ops::PcmDevice, arg: u64) -> i64 {
    let xf = match UserBuf::new(arg, XFERI_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let ubuf = xf.r64(XFERI_BUF);
    let frames = xf.r64(XFERI_FRAMES);
    let (fb, mut state, start_thr) = {
        let guard = PCM.lock();
        let Some(p) = guard.iter().find(|p| p.owner == owner && p.device == device) else { return err(Errno::Enodev); };
        (p.frame_bytes as u64, p.state, p.start_threshold)
    };
    if fb == 0 || frames == 0 { return 0; }
    let bytes = frames * fb;
    let src = match UserBuf::new(ubuf, bytes as usize) { Some(b) => b, None => return err(Errno::Efault) };
    if state == STATE_OPEN || state == STATE_SETUP { return err(Errno::Ebadf); }

    if state == STATE_PREPARED {
        let appl = {
            let guard = PCM.lock();
            let Some(p) = guard.iter().find(|p| p.owner == owner && p.device == device) else { return err(Errno::Enodev); };
            p.appl_ptr
        };
        if appl + frames >= start_thr {
            if !crate::ops::pcm_trigger_for(owner, device, true) { return err(Errno::Eio); }
            let mut guard = PCM.lock();
            let Some(p) = guard.iter_mut().find(|p| p.owner == owner && p.device == device) else { return err(Errno::Enodev); };
            p.state = STATE_RUNNING;
            p.time.stamp_trigger();
            state = STATE_RUNNING;
        }
    }
    if state != STATE_RUNNING {}

    let mut staged = [0u8; hal::PAGE_SIZE_BYTES as usize];
    let mut done: u64 = 0;
    while done < bytes {
        let chunk = ((bytes - done) as usize).min(staged.len());
        for i in 0..chunk { staged[i] = src.r8(done as usize + i); }
        let n = crate::ops::pcm_submit_for(owner, device, &staged[..chunk]);
        if n == 0 { break; }
        done += n as u64;
        if n < chunk { break; }
    }
    let wrote_frames = done / fb;
    {
        let reported = crate::ops::pcm_pointer_for(owner, device);
        let mut guard = PCM.lock();
        let Some(p) = guard.iter_mut().find(|p| p.owner == owner && p.device == device) else { return err(Errno::Enodev); };
        p.appl_ptr = p.appl_ptr.wrapping_add(wrote_frames) % BOUNDARY;
        p.hw_ptr = reported.map(|f| f % BOUNDARY).unwrap_or(p.appl_ptr);
    }
    xf.w64(XFERI_RESULT, wrote_frames);
    if wrote_frames == 0 { err(Errno::Eio) } else { wrote_frames as i64 }
}
