// OSS /dev/dsp + /dev/mixer emulation (the snd-pcm-oss role), layered on the
// SAME drv-virtio-snd OUTPUT substream the ALSA core drives. Modern Linux
// has no standalone OSS driver — /dev/dsp is a compat shim over ALSA. Here
// write(2) lazily applies hw_params→prepare→trigger then transfers; the
// SNDCTL_DSP_* ioctls set rate/format/channels and report buffer geometry.

use alloc::vec::Vec;
use sync::{Spinlock, TaskList as L};
use syscall::errno::Errno;

use crate::uapi::*;

// virtio_snd PCM format enums.
const V_MU_LAW: u8 = 1;
const V_A_LAW: u8 = 2;
const V_S8: u8 = 3;
const V_U8: u8 = 4;
const V_S16: u8 = 5;
const V_U16: u8 = 6;

// OSS AFMT_* sample-format bits (linux/soundcard.h).
const AFMT_MU_LAW: u32 = 0x0000_0001;
const AFMT_A_LAW: u32 = 0x0000_0002;
const AFMT_U8: u32 = 0x0000_0008;
const AFMT_S16_LE: u32 = 0x0000_0010;
const AFMT_S8: u32 = 0x0000_0040;
const AFMT_U16_LE: u32 = 0x0000_0080;

/// OSS lazily-applied params (virtio enums) + whether each direction is
/// armed (`running` = playback, `cap_running` = capture).
#[derive(Clone, Copy)]
struct Oss { card_id: u32, rate: u8, format: u8, channels: u8, running: bool, cap_running: bool }
static OSS: Spinlock<Vec<Oss>, L> = Spinlock::new(Vec::new());

fn default_oss(card_id: u32) -> Oss {
    Oss { card_id, rate: 6 /*44100*/, format: V_S16, channels: 2, running: false, cap_running: false }
}

fn with_oss<R>(card_id: u32, f: impl FnOnce(&mut Oss) -> R) -> R {
    let mut all = OSS.lock();
    let idx = match all.iter().position(|oss| oss.card_id == card_id) {
        Some(idx) => idx,
        None => {
            all.push(default_oss(card_id));
            all.len() - 1
        }
    };
    f(&mut all[idx])
}

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn afmt_to_virtio(a: u32) -> u8 {
    match a {
        AFMT_MU_LAW => V_MU_LAW, AFMT_A_LAW => V_A_LAW, AFMT_S8 => V_S8,
        AFMT_U8 => V_U8, AFMT_S16_LE => V_S16, AFMT_U16_LE => V_U16, _ => V_S16,
    }
}
fn virtio_to_afmt(v: u8) -> u32 {
    match v {
        V_MU_LAW => AFMT_MU_LAW, V_A_LAW => AFMT_A_LAW, V_S8 => AFMT_S8,
        V_U8 => AFMT_U8, V_U16 => AFMT_U16_LE, _ => AFMT_S16_LE,
    }
}
fn hz_to_rate_enum(hz: u32) -> u8 {
    const HZ: [u32; 14] = [5512, 8000, 11025, 16000, 22050, 32000, 44100,
                           48000, 64000, 88200, 96000, 176400, 192000, 384000];
    let mut best = 6u8; let mut bd = u32::MAX;
    for (i, &h) in HZ.iter().enumerate() {
        let d = if h > hz { h - hz } else { hz - h };
        if d < bd { bd = d; best = i as u8; }
    }
    best
}
fn rate_enum_to_hz(e: u8) -> u32 {
    const HZ: [u32; 14] = [5512, 8000, 11025, 16000, 22050, 32000, 44100,
                           48000, 64000, 88200, 96000, 176400, 192000, 384000];
    HZ[(e as usize).min(13)]
}

/// Stop + release both directions and disarm, so the next I/O re-applies
/// params (SNDCTL_DSP_RESET / a param change).
fn reset(card_id: u32) {
    let (running, cap_running) = with_oss(card_id, |o| (o.running, o.cap_running));
    if running {
        let _ = crate::ops::pcm_trigger(card_id, false);
        let _ = crate::ops::pcm_hw_free(card_id);
    }
    if cap_running {
        let _ = crate::ops::cap_trigger(card_id, false);
        let _ = crate::ops::cap_hw_free(card_id);
    }
    with_oss(card_id, |o| {
    if o.running {
        o.running = false;
    }
    if o.cap_running {
        o.cap_running = false;
    }
    });
}

/// /dev/dsp read(2): lazily cap_hw_params→cap_prepare→cap_trigger on the
/// first read after a param change, then capture (blocking). Returns bytes.
/// # C: O(bytes/period × RXQ round-trip)
pub fn read(card_id: u32, buf: &mut [u8]) -> usize {
    if buf.is_empty() { return 0; }
    let (rate, fmt, ch, cap_running) = with_oss(card_id, |o| (o.rate, o.format, o.channels, o.cap_running));
    if !cap_running {
        let period = crate::ops::period_bytes(card_id) as u32;
        if !crate::ops::cap_hw_params(card_id, rate, fmt, ch, period, period * 2) { return 0; }
        if !crate::ops::cap_prepare(card_id) { return 0; }
        if !crate::ops::cap_trigger(card_id, true) { return 0; }
        with_oss(card_id, |o| o.cap_running = true);
    }
    crate::ops::pcm_recv(card_id, buf)
}

/// /dev/dsp write(2): lazily hw_params→prepare→trigger on the first write
/// after a param change, then transfer (blocking). Returns bytes accepted.
/// # C: O(bytes/period × TXQ round-trip)
pub fn write(card_id: u32, buf: &[u8]) -> usize {
    if buf.is_empty() { return 0; }
    let (rate, fmt, ch, running) = with_oss(card_id, |o| (o.rate, o.format, o.channels, o.running));
    if !running {
        let period = crate::ops::period_bytes(card_id) as u32;
        if !crate::ops::pcm_hw_params(card_id, rate, fmt, ch, period, period * 2) { return 0; }
        if !crate::ops::pcm_prepare(card_id) { return 0; }
        if !crate::ops::pcm_trigger(card_id, true) { return 0; }
        with_oss(card_id, |o| o.running = true);
    }
    crate::ops::pcm_submit(card_id, buf)
}

/// Handle a SNDCTL_DSP_* (`/dev/dsp`, minor=DSP/AUDIO) or SOUND_MIXER_*
/// (`/dev/mixer`) ioctl. # C: O(1)
pub fn handle(card_id: u32, is_mixer: bool, req: u64, arg: u64) -> i64 {
    let group = (req >> 8) & 0xFF;
    let nr = req & 0xFF;

    if is_mixer || group == b'M' as u64 {
        // Master level reads → 75/75; writes accepted (no real mixer element).
        if let Some(b) = UserBuf::new(arg, 4) { b.w32(0, 75 | (75 << 8)); }
        return 0;
    }
    if group != b'P' as u64 { return err(Errno::Enotty); }

    let ri = |a: u64| UserBuf::new(a, 4).map(|b| b.r32(0));
    let wi = |a: u64, v: u32| { if let Some(b) = UserBuf::new(a, 4) { b.w32(0, v); } };

    match nr {
        0 => { reset(card_id); 0 }                                   // RESET
        1 | 8 => 0,                                                  // SYNC / POST
        2 => {                                                       // SPEED
            let hz = match ri(arg) { Some(v) => v, None => return err(Errno::Efault) };
            let e = hz_to_rate_enum(hz);
            with_oss(card_id, |o| { o.rate = e; o.running = false; o.cap_running = false; });
            reset(card_id);
            wi(arg, rate_enum_to_hz(e));
            0
        }
        3 => {                                                       // STEREO
            let st = match ri(arg) { Some(v) => v, None => return err(Errno::Efault) };
            with_oss(card_id, |o| { o.channels = if st != 0 { 2 } else { 1 }; o.running = false; o.cap_running = false; });
            reset(card_id);
            wi(arg, with_oss(card_id, |o| (o.channels - 1) as u32));
            0
        }
        4 => { if UserBuf::new(arg, 4).is_none() { return err(Errno::Efault); }   // GETBLKSIZE
               wi(arg, crate::ops::period_bytes(card_id) as u32); 0 }
        5 => {                                                       // SETFMT
            let a = match ri(arg) { Some(v) => v, None => return err(Errno::Efault) };
            if a == 0 { wi(arg, virtio_to_afmt(with_oss(card_id, |o| o.format))); return 0; }
            with_oss(card_id, |o| { o.format = afmt_to_virtio(a); o.running = false; o.cap_running = false; });
            reset(card_id);
            wi(arg, virtio_to_afmt(with_oss(card_id, |o| o.format)));
            0
        }
        6 => {                                                       // CHANNELS
            let n = match ri(arg) { Some(v) => v, None => return err(Errno::Efault) };
            with_oss(card_id, |o| { o.channels = n.clamp(1, 2) as u8; o.running = false; o.cap_running = false; });
            reset(card_id);
            wi(arg, with_oss(card_id, |o| o.channels as u32));
            0
        }
        11 => { if UserBuf::new(arg, 4).is_none() { return err(Errno::Efault); }  // GETFMTS
                wi(arg, AFMT_S16_LE | AFMT_U8 | AFMT_S8 | AFMT_U16_LE | AFMT_MU_LAW | AFMT_A_LAW); 0 }
        12 | 13 => {                                                 // GET[OI]SPACE
            let b = match UserBuf::new(arg, 16) { Some(b) => b, None => return err(Errno::Efault) };
            let frag = crate::ops::period_bytes(card_id) as u32;
            b.w32(0, 2); b.w32(4, 2); b.w32(8, frag); b.w32(12, 2 * frag);
            0
        }
        15 => { if UserBuf::new(arg, 4).is_none() { return err(Errno::Efault); } wi(arg, 0); 0 } // GETCAPS
        10 | 14 => 0,                                                // SUBDIVIDE / SETFRAGMENT
        _ => err(Errno::Enotty),
    }
}
