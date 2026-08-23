// ALSA PCM core for virtio-snd INPUT substreams (card N, dev 0 capture).
// Mirror of pcm.rs for the RXQ direction: substream state machine + the
// SNDRV_PCM_IOCTL_* ABI, sharing pcm::refine_params (the device-free
// refinement) and driving the card driver's capture ops (cap_hw_params /
// cap_prepare / cap_trigger / cap_hw_free / pcm_recv).
//
// Transfer model: blocking interleaved readi — pcm_recv posts an RXQ buffer
// and blocks until the device fills it, so a READI returns one period of
// captured PCM (silence when the host audiodev has no input source).

use alloc::vec::Vec;
use sync::{Spinlock, TaskList as L};
use syscall::errno::Errno;

use crate::uapi::*;
use crate::pcm::{limits_for, refine_params};

const BOUNDARY: u64 = 0x4000_0000_0000;

struct Cap {
    owner: crate::SoundOwnerKey,
    device: crate::ops::PcmDevice,
    state: u32,
    frame_bytes: u32,
    buffer_frames: u32,
    appl_ptr: u64,
    hw_ptr: u64,
    time: crate::pcm_time::PcmTime,
}
static CAP: Spinlock<Vec<Cap>, L> = Spinlock::new(Vec::new());

fn initial(owner: crate::SoundOwnerKey, device: crate::ops::PcmDevice) -> Cap {
    Cap { owner, device, state: STATE_OPEN, frame_bytes: 4, buffer_frames: 1024, appl_ptr: 0, hw_ptr: 0,
          time: crate::pcm_time::PcmTime::new() }
}

/// # C: O(cards)
pub(crate) fn register_card(owner: crate::SoundOwnerKey) {
    let mut guard = CAP.lock();
    if !guard.iter().any(|c| c.owner == owner) {
        let count = crate::ops::pcm_devices(owner).max(1);
        for device in 0..count {
            if device == 0 || crate::ops::cap_caps_for(owner, device).is_some() {
                guard.push(initial(owner, device));
            }
        }
    }
}

/// # C: O(cards)
pub(crate) fn unregister_card(owner: crate::SoundOwnerKey) {
    let mut guard = CAP.lock();
    guard.retain(|c| c.owner != owner);
}

#[cfg(test)]
/// # C: O(cards)
pub(crate) fn registered_count() -> usize {
    CAP.lock().len()
}

fn is_registered(owner: crate::SoundOwnerKey) -> bool {
    CAP.lock().iter().any(|c| c.owner == owner)
}

#[cfg(test)]
/// # C: O(cards)
pub(crate) fn has_card(owner: crate::SoundOwnerKey) -> bool { is_registered(owner) }

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Device INPUT caps `(virtio_formats, virtio_rates, ch_min, ch_max)`.
fn caps(owner: crate::SoundOwnerKey, device: crate::ops::PcmDevice) -> Option<(u64, u64, u8, u8)> { crate::ops::cap_caps_for(owner, device) }

/// Capture HW_REFINE/HW_PARAMS: refine against the INPUT caps; on commit
/// apply via the capture ops + record geometry. # C: O(CONTROLQ)
fn refine(owner: crate::SoundOwnerKey, device: crate::ops::PcmDevice, b: &UserBuf, commit: bool) -> i64 {
    let Some((vf, vr, ch_min, ch_max)) = caps(owner, device) else {
        return err(Errno::Enodev);
    };
    let r = match refine_params(b, vf, vr, ch_min, ch_max, &limits_for(owner, device), crate::ops::info_flags_for(owner, device)) { Ok(r) => r, Err(e) => return e };
    if commit {
        if !crate::ops::cap_hw_params_for(owner, device, r.format, r.rate,
                                      r.channels as u8, r.period_bytes, r.buffer_bytes) {
            return err(Errno::Eio);
        }
        let mut guard = CAP.lock();
        let Some(c) = guard.iter_mut().find(|c| c.owner == owner && c.device == device) else {
            return err(Errno::Enodev);
        };
        c.frame_bytes = r.frame_bytes; c.buffer_frames = r.buffer_frames;
        c.state = STATE_SETUP; c.appl_ptr = 0; c.hw_ptr = 0;
    }
    0
}

/// Handle one `SNDRV_PCM_IOCTL_*` on the capture substream. # C: O(1)
/// excluding the blocking transfer in READI
pub fn handle(owner: crate::SoundOwnerKey, card: u32, device: crate::ops::PcmDevice, nr: u64, arg: u64) -> i64 {
    match nr {
        PCM_PVERSION => match UserBuf::new(arg, 4) { Some(b) => { b.w32(0, SNDRV_PCM_VERSION); 0 } None => err(Errno::Efault) },
        PCM_INFO => pcm_info(owner, card, device, arg),
        PCM_TSTAMP | PCM_TTSTAMP => tstamp(owner, device, arg),
        PCM_HW_REFINE => match UserBuf::new(arg, HW_PARAMS_SIZE) { Some(b) => refine(owner, device, &b, false), None => err(Errno::Efault) },
        PCM_HW_PARAMS => match UserBuf::new(arg, HW_PARAMS_SIZE) { Some(b) => refine(owner, device, &b, true), None => err(Errno::Efault) },
        PCM_HW_FREE => {
            if !crate::ops::cap_hw_free_for(owner, device) {
                return err(Errno::Eio);
            }
            let mut guard = CAP.lock();
            let Some(c) = guard.iter_mut().find(|c| c.owner == owner && c.device == device) else {
                return err(Errno::Enodev);
            };
            c.state = STATE_OPEN;
            0
        }
        PCM_SW_PARAMS => sw_params(owner, device, arg),
        PCM_PREPARE => {
            if !crate::ops::cap_prepare_for(owner, device) { return err(Errno::Eio); }
            let mut guard = CAP.lock();
            let Some(c) = guard.iter_mut().find(|c| c.owner == owner && c.device == device) else {
                return err(Errno::Enodev);
            };
            c.state = STATE_PREPARED; c.appl_ptr = 0; c.hw_ptr = 0; 0
        }
        PCM_START => {
            if !crate::ops::cap_trigger_for(owner, device, true) { return err(Errno::Eio); }
            let mut guard = CAP.lock();
            let Some(c) = guard.iter_mut().find(|c| c.owner == owner && c.device == device) else {
                return err(Errno::Enodev);
            };
            c.state = STATE_RUNNING; c.time.stamp_trigger(); 0
        }
        PCM_DROP | PCM_DRAIN => {
            if !crate::ops::cap_trigger_for(owner, device, false) {
                return err(Errno::Eio);
            }
            let mut guard = CAP.lock();
            let Some(c) = guard.iter_mut().find(|c| c.owner == owner && c.device == device) else {
                return err(Errno::Enodev);
            };
            c.state = STATE_SETUP; c.appl_ptr = 0; c.hw_ptr = 0;
            c.time.stamp_trigger(); 0
        }
        PCM_HWSYNC => { sync_hw_ptr(owner, device); 0 }
        PCM_DELAY => match UserBuf::new(arg, 8) { Some(b) => { b.w64(0, 0); 0 } None => err(Errno::Efault) },
        PCM_STATUS => status(owner, device, arg),
        PCM_SYNC_PTR => sync_ptr(owner, device, arg),
        PCM_READI => readi(owner, device, arg),
        PCM_WRITEI => err(Errno::Ebadf),
        _ => err(Errno::Enotty),
    }
}

fn pcm_info(owner: crate::SoundOwnerKey, card: u32, device: crate::ops::PcmDevice, arg: u64) -> i64 {
    if caps(owner, device).is_none() || !is_registered(owner) {
        return err(Errno::Enodev);
    }
    let b = match UserBuf::new(arg, PCM_INFO_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let Some(ident) = crate::ops::identity(owner) else { return err(Errno::Enodev); };
    crate::pcm_info::write(&b, card, device, STREAM_CAPTURE, &ident.id,
                           &crate::identity::pcm_stream_name(&ident, true));
    0
}

fn tstamp(owner: crate::SoundOwnerKey, device: crate::ops::PcmDevice, arg: u64) -> i64 {
    let b = match UserBuf::new(arg, 4) { Some(b) => b, None => return err(Errno::Efault) };
    let mut guard = CAP.lock();
    let Some(c) = guard.iter_mut().find(|c| c.owner == owner && c.device == device) else { return err(Errno::Enodev); };
    match c.time.set_kind(b.r32(0)) { Ok(()) => 0, Err(e) => err(e) }
}

fn sw_params(owner: crate::SoundOwnerKey, device: crate::ops::PcmDevice, arg: u64) -> i64 {
    let b = match UserBuf::new(arg, SW_PARAMS_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let mut guard = CAP.lock();
    let Some(c) = guard.iter_mut().find(|c| c.owner == owner && c.device == device) else { return err(Errno::Enodev); };
    if let Err(e) = c.time.apply_sw(&b) { return err(e); }
    b.w64(SWP_BOUNDARY, BOUNDARY);
    0
}

/// Refresh `hw_ptr` from the card's real capture position when it reports
/// one; otherwise the core's own accounting is the truthful answer.
/// # C: O(1)
fn sync_hw_ptr(owner: crate::SoundOwnerKey, device: crate::ops::PcmDevice) {
    let Some(frames) = crate::ops::cap_pointer_for(owner, device) else { return; };
    let mut guard = CAP.lock();
    let Some(c) = guard.iter_mut().find(|c| c.owner == owner && c.device == device) else { return; };
    c.hw_ptr = frames % BOUNDARY;
}

fn status(owner: crate::SoundOwnerKey, device: crate::ops::PcmDevice, arg: u64) -> i64 {
    let b = match UserBuf::new(arg, STATUS_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    sync_hw_ptr(owner, device);
    let guard = CAP.lock();
    let Some(c) = guard.iter().find(|c| c.owner == owner && c.device == device) else {
        return err(Errno::Enodev);
    };
    b.zero(0, STATUS_SIZE);
    b.w32(ST_STATE, c.state);
    b.w64(ST_APPL_PTR, c.appl_ptr);
    b.w64(ST_HW_PTR, c.hw_ptr);
    b.w64(ST_AVAIL, c.buffer_frames as u64);
    b.w64(ST_AVAIL_MAX, c.buffer_frames as u64);
    c.time.write_status(&b, c.state);
    0
}

fn sync_ptr(owner: crate::SoundOwnerKey, device: crate::ops::PcmDevice, arg: u64) -> i64 {
    let b = match UserBuf::new(arg, SYNC_PTR_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let flags = b.r32(SP_FLAGS);
    if flags & SYNC_PTR_HWSYNC != 0 { sync_hw_ptr(owner, device); }
    let mut guard = CAP.lock();
    let Some(c) = guard.iter_mut().find(|c| c.owner == owner && c.device == device) else {
        return err(Errno::Enodev);
    };
    if flags & SYNC_PTR_APPL == 0 { c.appl_ptr = b.r64(SP_CONTROL_APPL_PTR); }
    b.w32(SP_STATUS_STATE, c.state);
    b.w64(SP_STATUS_HW_PTR, c.hw_ptr);
    b.w64(SP_CONTROL_APPL_PTR, c.appl_ptr);
    c.time.write_sync(&b, c.state);
    0
}

/// SNDRV_PCM_IOCTL_READI_FRAMES — interleaved blocking capture. Auto-starts a
/// PREPARED stream, pulls frames from the device, copies them into the app
/// buffer, advances appl_ptr/hw_ptr. Returns frames captured.
fn readi(owner: crate::SoundOwnerKey, device: crate::ops::PcmDevice, arg: u64) -> i64 {
    let xf = match UserBuf::new(arg, XFERI_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let ubuf = xf.r64(XFERI_BUF);
    let frames = xf.r64(XFERI_FRAMES);
    let (fb, state) = {
        let guard = CAP.lock();
        let Some(c) = guard.iter().find(|c| c.owner == owner && c.device == device) else {
            return err(Errno::Enodev);
        };
        (c.frame_bytes as u64, c.state)
    };
    if fb == 0 || frames == 0 { return 0; }
    let bytes = frames * fb;
    let dst = match UserBuf::new(ubuf, bytes as usize) { Some(b) => b, None => return err(Errno::Efault) };
    if state == STATE_OPEN || state == STATE_SETUP { return err(Errno::Ebadf); }
    if state == STATE_PREPARED {
        if !crate::ops::cap_trigger_for(owner, device, true) { return err(Errno::Eio); }
        let mut guard = CAP.lock();
        let Some(c) = guard.iter_mut().find(|c| c.owner == owner && c.device == device) else {
            return err(Errno::Enodev);
        };
        c.state = STATE_RUNNING;
        c.time.stamp_trigger();
    }

    let mut staged = [0u8; hal::PAGE_SIZE_BYTES as usize];
    let mut done: u64 = 0;
    while done < bytes {
        let chunk = ((bytes - done) as usize).min(staged.len());
        let got = crate::ops::pcm_recv_for(owner, device, &mut staged[..chunk]);
        if got == 0 { break; }
        dst.wbytes(done as usize, &staged[..got]);
        done += got as u64;
        if got < chunk { break; }
    }
    let got_frames = done / fb;
    {
        let mut guard = CAP.lock();
        let Some(c) = guard.iter_mut().find(|c| c.owner == owner && c.device == device) else {
            return err(Errno::Enodev);
        };
        c.appl_ptr = c.appl_ptr.wrapping_add(got_frames) % BOUNDARY;
        c.hw_ptr = c.appl_ptr;
    }
    xf.w64(XFERI_RESULT, got_frames);
    if got_frames == 0 { err(Errno::Eio) } else { got_frames as i64 }
}

/// Raw `read(2)` on the capture fd — the byte-stream equivalent of READI.
/// Auto-starts a PREPARED stream and returns captured bytes. # C: O(bytes/period)
pub fn read_bytes(owner: crate::SoundOwnerKey, device: crate::ops::PcmDevice, buf: &mut [u8]) -> usize {
    let state = {
        let guard = CAP.lock();
        let Some(c) = guard.iter().find(|c| c.owner == owner && c.device == device) else {
            return 0;
        };
        c.state
    };
    if state == STATE_OPEN || state == STATE_SETUP { return 0; }
    if state == STATE_PREPARED {
        if !crate::ops::cap_trigger_for(owner, device, true) { return 0; }
        let mut guard = CAP.lock();
        let Some(c) = guard.iter_mut().find(|c| c.owner == owner && c.device == device) else {
            return 0;
        };
        c.state = STATE_RUNNING;
    }
    let fb = {
        let guard = CAP.lock();
        let Some(c) = guard.iter().find(|c| c.owner == owner && c.device == device) else {
            return 0;
        };
        c.frame_bytes as u64
    };
    let n = crate::ops::pcm_recv_for(owner, device, buf);
    if n > 0 {
        let frames = n as u64 / fb.max(1);
        let mut guard = CAP.lock();
        let Some(c) = guard.iter_mut().find(|c| c.owner == owner && c.device == device) else {
            return n;
        };
        c.appl_ptr = c.appl_ptr.wrapping_add(frames) % BOUNDARY;
        c.hw_ptr = c.appl_ptr;
    }
    n
}
