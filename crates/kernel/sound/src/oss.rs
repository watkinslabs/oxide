// OSS /dev/dsp + /dev/mixer emulation (the snd-pcm-oss role), layered on the
// SAME drv-virtio-snd OUTPUT substream the ALSA core drives. Modern Linux
// has no standalone OSS driver — /dev/dsp is a compat shim over ALSA. Here
// write(2) lazily applies hw_params→prepare→trigger then transfers; the
// SNDCTL_DSP_* ioctls set rate/format/channels and report buffer geometry.

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
struct Oss { rate: u8, format: u8, channels: u8, running: bool, cap_running: bool }
static OSS: Spinlock<Oss, L> =
    Spinlock::new(Oss { rate: 6 /*44100*/, format: V_S16, channels: 2, running: false, cap_running: false });

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
fn reset() {
    let mut o = OSS.lock();
    if o.running {
        let _ = crate::ops::pcm_trigger(false);
        let _ = crate::ops::pcm_hw_free();
        o.running = false;
    }
    if o.cap_running {
        let _ = crate::ops::cap_trigger(false);
        let _ = crate::ops::cap_hw_free();
        o.cap_running = false;
    }
}

/// /dev/dsp read(2): lazily cap_hw_params→cap_prepare→cap_trigger on the
/// first read after a param change, then capture (blocking). Returns bytes.
/// # C: O(bytes/period × RXQ round-trip)
pub fn read(buf: &mut [u8]) -> usize {
    if buf.is_empty() { return 0; }
    let (rate, fmt, ch) = { let o = OSS.lock(); (o.rate, o.format, o.channels) };
    if !OSS.lock().cap_running {
        let period = crate::ops::period_bytes() as u32;
        if !crate::ops::cap_hw_params(rate, fmt, ch, period, period * 2) { return 0; }
        if !crate::ops::cap_prepare() { return 0; }
        if !crate::ops::cap_trigger(true) { return 0; }
        OSS.lock().cap_running = true;
    }
    crate::ops::pcm_recv(buf)
}

/// /dev/dsp write(2): lazily hw_params→prepare→trigger on the first write
/// after a param change, then transfer (blocking). Returns bytes accepted.
/// # C: O(bytes/period × TXQ round-trip)
pub fn write(buf: &[u8]) -> usize {
    if buf.is_empty() { return 0; }
    let (rate, fmt, ch) = {
        let o = OSS.lock();
        (o.rate, o.format, o.channels)
    };
    if !OSS.lock().running {
        let period = crate::ops::period_bytes() as u32;
        if !crate::ops::pcm_hw_params(rate, fmt, ch, period, period * 2) { return 0; }
        if !crate::ops::pcm_prepare() { return 0; }
        if !crate::ops::pcm_trigger(true) { return 0; }
        OSS.lock().running = true;
    }
    crate::ops::pcm_submit(buf)
}

/// Handle a SNDCTL_DSP_* (`/dev/dsp`, minor=DSP/AUDIO) or SOUND_MIXER_*
/// (`/dev/mixer`) ioctl. # C: O(1)
pub fn handle(is_mixer: bool, req: u64, arg: u64) -> i64 {
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
        0 => { reset(); 0 }                                          // RESET
        1 | 8 => 0,                                                  // SYNC / POST
        2 => {                                                       // SPEED
            let hz = match ri(arg) { Some(v) => v, None => return err(Errno::Efault) };
            let e = hz_to_rate_enum(hz);
            { let mut o = OSS.lock(); o.rate = e; o.running = false; o.cap_running = false; }
            reset();
            wi(arg, rate_enum_to_hz(e));
            0
        }
        3 => {                                                       // STEREO
            let st = match ri(arg) { Some(v) => v, None => return err(Errno::Efault) };
            { let mut o = OSS.lock(); o.channels = if st != 0 { 2 } else { 1 }; o.running = false; o.cap_running = false; }
            reset();
            wi(arg, (OSS.lock().channels - 1) as u32);
            0
        }
        4 => { if UserBuf::new(arg, 4).is_none() { return err(Errno::Efault); }   // GETBLKSIZE
               wi(arg, crate::ops::period_bytes() as u32); 0 }
        5 => {                                                       // SETFMT
            let a = match ri(arg) { Some(v) => v, None => return err(Errno::Efault) };
            if a == 0 { wi(arg, virtio_to_afmt(OSS.lock().format)); return 0; }
            { let mut o = OSS.lock(); o.format = afmt_to_virtio(a); o.running = false; o.cap_running = false; }
            reset();
            wi(arg, virtio_to_afmt(OSS.lock().format));
            0
        }
        6 => {                                                       // CHANNELS
            let n = match ri(arg) { Some(v) => v, None => return err(Errno::Efault) };
            { let mut o = OSS.lock(); o.channels = n.clamp(1, 2) as u8; o.running = false; o.cap_running = false; }
            reset();
            wi(arg, OSS.lock().channels as u32);
            0
        }
        11 => { if UserBuf::new(arg, 4).is_none() { return err(Errno::Efault); }  // GETFMTS
                wi(arg, AFMT_S16_LE | AFMT_U8 | AFMT_S8 | AFMT_U16_LE | AFMT_MU_LAW | AFMT_A_LAW); 0 }
        12 | 13 => {                                                 // GET[OI]SPACE
            let b = match UserBuf::new(arg, 16) { Some(b) => b, None => return err(Errno::Efault) };
            let frag = crate::ops::period_bytes() as u32;
            b.w32(0, 2); b.w32(4, 2); b.w32(8, frag); b.w32(12, 2 * frag);
            0
        }
        15 => { if UserBuf::new(arg, 4).is_none() { return err(Errno::Efault); } wi(arg, 0); 0 } // GETCAPS
        10 | 14 => 0,                                                // SUBDIVIDE / SETFRAGMENT
        _ => err(Errno::Enotty),
    }
}
