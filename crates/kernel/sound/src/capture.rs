// ALSA PCM core for a virtio-snd INPUT substream, keyed by ALSA card id.
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
use crate::pcm::{refine_params, fmt_alsa_to_virtio, rate_hz_to_enum};

const BOUNDARY: u64 = 0x4000_0000_0000;

#[derive(Clone, Copy)]
struct Cap {
    card_id: u32,
    state: u32,
    frame_bytes: u32,
    buffer_frames: u32,
    appl_ptr: u64,
    hw_ptr: u64,
}
static CAPS: Spinlock<Vec<Cap>, L> = Spinlock::new(Vec::new());

fn default_cap(card_id: u32) -> Cap {
    Cap {
        card_id,
        state: STATE_OPEN, frame_bytes: 4, buffer_frames: 1024, appl_ptr: 0, hw_ptr: 0,
    }
}

fn with_cap<R>(card_id: u32, f: impl FnOnce(&mut Cap) -> R) -> R {
    let mut caps = CAPS.lock();
    let idx = match caps.iter().position(|cap| cap.card_id == card_id) {
        Some(idx) => idx,
        None => {
            caps.push(default_cap(card_id));
            caps.len() - 1
        }
    };
    f(&mut caps[idx])
}

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Device INPUT caps `(virtio_formats, virtio_rates, ch_min, ch_max)`.
fn caps(card_id: u32) -> (u64, u64, u8, u8) {
    crate::ops::cap_caps(card_id).unwrap_or((1 << 5, 1 << 6, 1, 2))
}

/// Capture HW_REFINE/HW_PARAMS: refine against the INPUT caps; on commit
/// apply via the capture ops + record geometry. # C: O(CONTROLQ)
fn refine(card_id: u32, b: &UserBuf, commit: bool) -> i64 {
    let (vf, vr, ch_min, ch_max) = caps(card_id);
    let r = match refine_params(b, vf, vr, ch_min, ch_max) { Ok(r) => r, Err(e) => return e };
    if commit {
        if !crate::ops::cap_hw_params(card_id, rate_hz_to_enum(r.rate), fmt_alsa_to_virtio(r.format),
                                          r.channels as u8, r.period_bytes, r.buffer_bytes) {
            return err(Errno::Eio);
        }
        with_cap(card_id, |c| {
        c.frame_bytes = r.frame_bytes; c.buffer_frames = r.buffer_frames;
        c.state = STATE_SETUP; c.appl_ptr = 0; c.hw_ptr = 0;
        });
    }
    0
}

/// Handle one `SNDRV_PCM_IOCTL_*` on the capture substream. # C: O(1)
/// excluding the blocking transfer in READI
pub fn handle(card_id: u32, nr: u64, arg: u64) -> i64 {
    match nr {
        PCM_PVERSION => match UserBuf::new(arg, 4) { Some(b) => { b.w32(0, SNDRV_PCM_VERSION); 0 } None => err(Errno::Efault) },
        PCM_INFO => pcm_info(card_id, arg),
        PCM_TSTAMP | PCM_TTSTAMP => 0,
        PCM_HW_REFINE => match UserBuf::new(arg, HW_PARAMS_SIZE) { Some(b) => refine(card_id, &b, false), None => err(Errno::Efault) },
        PCM_HW_PARAMS => match UserBuf::new(arg, HW_PARAMS_SIZE) { Some(b) => refine(card_id, &b, true), None => err(Errno::Efault) },
        PCM_HW_FREE => { crate::ops::cap_hw_free(card_id); with_cap(card_id, |c| c.state = STATE_OPEN); 0 }
        PCM_SW_PARAMS => match UserBuf::new(arg, SW_PARAMS_SIZE) { Some(b) => { b.w64(SWP_BOUNDARY, BOUNDARY); 0 } None => err(Errno::Efault) },
        PCM_PREPARE => {
            if !crate::ops::cap_prepare(card_id) { return err(Errno::Eio); }
            with_cap(card_id, |c| { c.state = STATE_PREPARED; c.appl_ptr = 0; c.hw_ptr = 0; });
            0
        }
        PCM_START => {
            if !crate::ops::cap_trigger(card_id, true) { return err(Errno::Eio); }
            with_cap(card_id, |c| c.state = STATE_RUNNING);
            0
        }
        PCM_DROP | PCM_DRAIN => {
            let _ = crate::ops::cap_trigger(card_id, false);
            with_cap(card_id, |c| { c.state = STATE_SETUP; c.appl_ptr = 0; c.hw_ptr = 0; });
            0
        }
        PCM_HWSYNC => 0,
        PCM_DELAY => match UserBuf::new(arg, 8) { Some(b) => { b.w64(0, 0); 0 } None => err(Errno::Efault) },
        PCM_STATUS => status(card_id, arg),
        PCM_SYNC_PTR => sync_ptr(card_id, arg),
        PCM_READI => readi(card_id, arg),
        PCM_WRITEI => err(Errno::Ebadf),
        _ => err(Errno::Enotty),
    }
}

fn pcm_info(card_id: u32, arg: u64) -> i64 {
    let b = match UserBuf::new(arg, PCM_INFO_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    b.zero(0, PCM_INFO_SIZE);
    b.w32(PI_DEVICE, 0);
    b.w32(PI_SUBDEVICE, 0);
    b.w32(PI_STREAM, STREAM_CAPTURE as u32);
    b.w32(PI_CARD, card_id);
    b.wstr(PI_ID, b"virtio-snd", 64);
    b.wstr(PI_NAME, b"virtio-snd PCM", 80);
    b.wstr(PI_SUBNAME, b"subdevice #0", 32);
    b.w32(PI_SUBDEVICES_COUNT, 1);
    b.w32(PI_SUBDEVICES_AVAIL, 1);
    0
}

fn status(card_id: u32, arg: u64) -> i64 {
    let b = match UserBuf::new(arg, STATUS_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let (state, appl_ptr, hw_ptr, avail) = with_cap(card_id, |c| {
        (c.state, c.appl_ptr, c.hw_ptr, c.buffer_frames as u64)
    });
    b.zero(0, STATUS_SIZE);
    b.w32(ST_STATE, state);
    b.w64(ST_APPL_PTR, appl_ptr);
    b.w64(ST_HW_PTR, hw_ptr);
    b.w64(ST_AVAIL, avail);
    b.w64(ST_AVAIL_MAX, avail);
    0
}

fn sync_ptr(card_id: u32, arg: u64) -> i64 {
    let b = match UserBuf::new(arg, SYNC_PTR_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let flags = b.r32(SP_FLAGS);
    let (state, hw_ptr, appl_ptr) = with_cap(card_id, |c| {
    if flags & SYNC_PTR_APPL == 0 { c.appl_ptr = b.r64(SP_CONTROL_APPL_PTR); }
    c.hw_ptr = c.appl_ptr;
        (c.state, c.hw_ptr, c.appl_ptr)
    });
    b.w32(SP_STATUS_STATE, state);
    b.w64(SP_STATUS_HW_PTR, hw_ptr);
    b.w64(SP_CONTROL_APPL_PTR, appl_ptr);
    0
}

/// SNDRV_PCM_IOCTL_READI_FRAMES — interleaved blocking capture. Auto-starts a
/// PREPARED stream, pulls frames from the device, copies them into the app
/// buffer, advances appl_ptr/hw_ptr. Returns frames captured.
fn readi(card_id: u32, arg: u64) -> i64 {
    let xf = match UserBuf::new(arg, XFERI_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let ubuf = xf.r64(XFERI_BUF);
    let frames = xf.r64(XFERI_FRAMES);
    let (fb, state) = with_cap(card_id, |c| (c.frame_bytes as u64, c.state));
    if fb == 0 || frames == 0 { return 0; }
    let bytes = frames * fb;
    let dst = match UserBuf::new(ubuf, bytes as usize) { Some(b) => b, None => return err(Errno::Efault) };
    if state == STATE_OPEN || state == STATE_SETUP { return err(Errno::Ebadf); }
    if state == STATE_PREPARED {
        if !crate::ops::cap_trigger(card_id, true) { return err(Errno::Eio); }
        with_cap(card_id, |c| c.state = STATE_RUNNING);
    }

    let mut staged = [0u8; 0x1000];
    let mut done: u64 = 0;
    while done < bytes {
        let chunk = ((bytes - done) as usize).min(staged.len());
        let got = crate::ops::pcm_recv(card_id, &mut staged[..chunk]);
        if got == 0 { break; }
        dst.wbytes(done as usize, &staged[..got]);
        done += got as u64;
        if got < chunk { break; }
    }
    let got_frames = done / fb;
    {
        with_cap(card_id, |c| {
        c.appl_ptr = c.appl_ptr.wrapping_add(got_frames) % BOUNDARY;
        c.hw_ptr = c.appl_ptr;
        });
    }
    xf.w64(XFERI_RESULT, got_frames);
    if got_frames == 0 { err(Errno::Eio) } else { got_frames as i64 }
}

/// Raw `read(2)` on the capture fd — the byte-stream equivalent of READI.
/// Auto-starts a PREPARED stream and returns captured bytes. # C: O(bytes/period)
pub fn read_bytes(card_id: u32, buf: &mut [u8]) -> usize {
    let state = with_cap(card_id, |c| c.state);
    if state == STATE_OPEN || state == STATE_SETUP { return 0; }
    if state == STATE_PREPARED {
        if !crate::ops::cap_trigger(card_id, true) { return 0; }
        with_cap(card_id, |c| c.state = STATE_RUNNING);
    }
    let fb = with_cap(card_id, |c| c.frame_bytes as u64);
    let n = crate::ops::pcm_recv(card_id, buf);
    if n > 0 {
        let frames = n as u64 / fb.max(1);
        with_cap(card_id, |c| {
        c.appl_ptr = c.appl_ptr.wrapping_add(frames) % BOUNDARY;
        c.hw_ptr = c.appl_ptr;
        });
    }
    n
}
