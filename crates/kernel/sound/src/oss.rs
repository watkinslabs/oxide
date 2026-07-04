// OSS /dev/dsp emulation (the snd-pcm-oss role), layered on the SAME
// drv-virtio-snd OUTPUT substream the ALSA core drives. Modern Linux has no
// standalone OSS driver — /dev/dsp is a compat shim over ALSA. Here write(2)
// lazily applies hw_params→prepare→trigger then transfers; the SNDCTL_DSP_*
// ioctls set rate/format/channels and report buffer geometry. /dev/mixer
// ioctls are rejected until a real ALSA control backend exists.

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
struct Oss {
    owner: u32,
    rate: u8,
    format: u8,
    channels: u8,
    running: bool,
    cap_running: bool,
}

static OSS: Spinlock<Vec<Oss>, L> = Spinlock::new(Vec::new());

fn initial(owner: u32) -> Oss {
    let (rate, format, channels) = initial_params(owner);
    Oss { owner, rate, format, channels, running: false, cap_running: false }
}

pub(crate) fn register_card(owner: u32) {
    let mut guard = OSS.lock();
    if !guard.iter().any(|o| o.owner == owner) {
        guard.push(initial(owner));
    }
}

pub(crate) fn unregister_card(owner: u32) {
    reset(owner);
    let mut guard = OSS.lock();
    guard.retain(|o| o.owner != owner);
}

#[cfg(test)]
pub(crate) fn registered_count() -> usize {
    OSS.lock().len()
}

#[cfg(test)]
pub(crate) fn has_card(owner: u32) -> bool {
    OSS.lock().iter().any(|o| o.owner == owner)
}

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn afmt_to_virtio(a: u32) -> Option<u8> {
    match a {
        AFMT_MU_LAW => Some(V_MU_LAW), AFMT_A_LAW => Some(V_A_LAW), AFMT_S8 => Some(V_S8),
        AFMT_U8 => Some(V_U8), AFMT_S16_LE => Some(V_S16), AFMT_U16_LE => Some(V_U16), _ => None,
    }
}
fn virtio_to_afmt(v: u8) -> u32 {
    match v {
        V_MU_LAW => AFMT_MU_LAW, V_A_LAW => AFMT_A_LAW, V_S8 => AFMT_S8,
        V_U8 => AFMT_U8, V_U16 => AFMT_U16_LE, _ => AFMT_S16_LE,
    }
}

const RATE_HZ: [u32; 14] = [5512, 8000, 11025, 16000, 22050, 32000, 44100,
                            48000, 64000, 88200, 96000, 176400, 192000, 384000];

fn nearest_supported_rate_enum(hz: u32, rates: u64) -> Option<u8> {
    let mut best = None;
    let mut best_delta = u32::MAX;
    for (i, &rate_hz) in RATE_HZ.iter().enumerate() {
        if (rates & (1u64 << i)) == 0 {
            continue;
        }
        let delta = rate_hz.abs_diff(hz);
        if delta < best_delta {
            best = Some(i as u8);
            best_delta = delta;
        }
    }
    best
}

fn rate_enum_to_hz(e: u8) -> u32 { RATE_HZ[(e as usize).min(RATE_HZ.len() - 1)] }

fn first_supported_format(formats: u64) -> Option<u8> {
    [V_S16, V_U8, V_S8, V_U16, V_MU_LAW, V_A_LAW]
        .iter()
        .copied()
        .find(|format| (formats & (1u64 << *format)) != 0)
}

fn formats_to_afmt(formats: u64) -> u32 {
    let mut out = 0;
    for format in [V_MU_LAW, V_A_LAW, V_S8, V_U8, V_S16, V_U16] {
        if (formats & (1u64 << format)) != 0 {
            out |= virtio_to_afmt(format);
        }
    }
    out
}

fn caps(owner: u32) -> Option<(u64, u64, u8, u8)> {
    match (crate::ops::pcm_caps(owner), crate::ops::cap_caps(owner)) {
        (Some((pf, pr, pcmin, pcmax)), Some((cf, cr, ccmin, ccmax))) => {
            let formats = pf & cf;
            let rates = pr & cr;
            let ch_min = pcmin.max(ccmin);
            let ch_max = pcmax.min(ccmax);
            if formats == 0 || rates == 0 || ch_min > ch_max {
                None
            } else {
                Some((formats, rates, ch_min, ch_max))
            }
        }
        (Some(caps), None) | (None, Some(caps)) => Some(caps),
        (None, None) => None,
    }
}

fn initial_params(owner: u32) -> (u8, u8, u8) {
    let Some((formats, rates, ch_min, ch_max)) = caps(owner) else {
        return (6, V_S16, 2);
    };
    let rate = nearest_supported_rate_enum(44_100, rates).unwrap_or(6);
    let format = first_supported_format(formats).unwrap_or(V_S16);
    let channels = 2u8.clamp(ch_min, ch_max);
    (rate, format, channels)
}

/// Stop + release both directions and disarm, so the next I/O re-applies
/// params (SNDCTL_DSP_RESET / a param change).
fn reset(owner: u32) -> bool {
    let (running, cap_running) = {
        let mut guard = OSS.lock();
        let Some(o) = guard.iter_mut().find(|o| o.owner == owner) else {
            return false;
        };
        (o.running, o.cap_running)
    };
    if running {
        if !crate::ops::pcm_trigger(owner, false) || !crate::ops::pcm_hw_free(owner) {
            return false;
        }
        if let Some(o) = OSS.lock().iter_mut().find(|o| o.owner == owner) {
            o.running = false;
        }
    }
    if cap_running {
        if !crate::ops::cap_trigger(owner, false) || !crate::ops::cap_hw_free(owner) {
            return false;
        }
        if let Some(o) = OSS.lock().iter_mut().find(|o| o.owner == owner) {
            o.cap_running = false;
        }
    }
    true
}

/// /dev/dsp read(2): lazily cap_hw_params→cap_prepare→cap_trigger on the
/// first read after a param change, then capture (blocking). Returns bytes.
/// # C: O(bytes/period × RXQ round-trip)
pub fn read(owner: u32, buf: &mut [u8]) -> usize {
    if buf.is_empty() { return 0; }
    let (rate, fmt, ch, cap_running) = {
        let guard = OSS.lock();
        let Some(o) = guard.iter().find(|o| o.owner == owner) else {
            return 0;
        };
        (o.rate, o.format, o.channels, o.cap_running)
    };
    if !cap_running {
        let period = crate::ops::period_bytes(owner) as u32;
        if !crate::ops::cap_hw_params(owner, rate, fmt, ch, period, period * 2) { return 0; }
        if !crate::ops::cap_prepare(owner) { return 0; }
        if !crate::ops::cap_trigger(owner, true) { return 0; }
        let mut guard = OSS.lock();
        let Some(o) = guard.iter_mut().find(|o| o.owner == owner) else {
            return 0;
        };
        o.cap_running = true;
    }
    crate::ops::pcm_recv(owner, buf)
}

/// /dev/dsp write(2): lazily hw_params→prepare→trigger on the first write
/// after a param change, then transfer (blocking). Returns bytes accepted.
/// # C: O(bytes/period × TXQ round-trip)
pub fn write(owner: u32, buf: &[u8]) -> usize {
    if buf.is_empty() { return 0; }
    let (rate, fmt, ch, running) = {
        let guard = OSS.lock();
        let Some(o) = guard.iter().find(|o| o.owner == owner) else {
            return 0;
        };
        (o.rate, o.format, o.channels, o.running)
    };
    if !running {
        let period = crate::ops::period_bytes(owner) as u32;
        if !crate::ops::pcm_hw_params(owner, rate, fmt, ch, period, period * 2) { return 0; }
        if !crate::ops::pcm_prepare(owner) { return 0; }
        if !crate::ops::pcm_trigger(owner, true) { return 0; }
        let mut guard = OSS.lock();
        let Some(o) = guard.iter_mut().find(|o| o.owner == owner) else {
            return 0;
        };
        o.running = true;
    }
    crate::ops::pcm_submit(owner, buf)
}

/// Handle a SNDCTL_DSP_* (`/dev/dsp`, minor=DSP/AUDIO) or SOUND_MIXER_*
/// (`/dev/mixer`) ioctl. # C: O(1)
pub fn handle(owner: u32, is_mixer: bool, req: u64, arg: u64) -> i64 {
    let group = (req >> 8) & 0xFF;
    let nr = req & 0xFF;
    let dir = (req >> 30) & 0x3;
    const IOC_WRITE: u64 = 1;

    if is_mixer || group == b'M' as u64 {
        let b = match UserBuf::new(arg, 4) { Some(b) => b, None => return err(Errno::Efault) };
        if (dir & IOC_WRITE) != 0 {
            let packed = b.r32(0);
            if !crate::control::set_mixer_level(owner, packed) {
                return err(Errno::Enodev);
            }
        }
        let Some(level) = crate::control::mixer_level(owner) else {
            return err(Errno::Enodev);
        };
        b.w32(0, level);
        return 0;
    }
    if group != b'P' as u64 { return err(Errno::Enotty); }

    let ri = |a: u64| UserBuf::new(a, 4).map(|b| b.r32(0));
    let wi = |a: u64, v: u32| { if let Some(b) = UserBuf::new(a, 4) { b.w32(0, v); } };

    match nr {
        0 => if reset(owner) { 0 } else { err(Errno::Eio) },          // RESET
        1 | 8 => 0,                                                  // SYNC / POST
        2 => {                                                       // SPEED
            let hz = match ri(arg) { Some(v) => v, None => return err(Errno::Efault) };
            let Some((_, rates, _, _)) = caps(owner) else {
                return err(Errno::Enodev);
            };
            let Some(e) = nearest_supported_rate_enum(hz, rates) else {
                return err(Errno::Einval);
            };
            if !reset(owner) { return err(Errno::Eio); }
            {
                let mut guard = OSS.lock();
                let Some(o) = guard.iter_mut().find(|o| o.owner == owner) else {
                    return err(Errno::Enodev);
                };
                o.rate = e;
            }
            wi(arg, rate_enum_to_hz(e));
            0
        }
        3 => {                                                       // STEREO
            let st = match ri(arg) { Some(v) => v, None => return err(Errno::Efault) };
            let Some((_, _, ch_min, ch_max)) = caps(owner) else {
                return err(Errno::Enodev);
            };
            if !reset(owner) { return err(Errno::Eio); }
            let channels = (if st != 0 { 2 } else { 1 }).clamp(ch_min, ch_max);
            {
                let mut guard = OSS.lock();
                let Some(o) = guard.iter_mut().find(|o| o.owner == owner) else {
                    return err(Errno::Enodev);
                };
                o.channels = channels;
            }
            wi(arg, (channels - 1) as u32);
            0
        }
        4 => { if UserBuf::new(arg, 4).is_none() { return err(Errno::Efault); }   // GETBLKSIZE
               wi(arg, crate::ops::period_bytes(owner) as u32); 0 }
        5 => {                                                       // SETFMT
            let a = match ri(arg) { Some(v) => v, None => return err(Errno::Efault) };
            if a == 0 {
                let guard = OSS.lock();
                let Some(o) = guard.iter().find(|o| o.owner == owner) else {
                    return err(Errno::Enodev);
                };
                wi(arg, virtio_to_afmt(o.format));
                return 0;
            }
            let Some((formats, _, _, _)) = caps(owner) else {
                return err(Errno::Enodev);
            };
            let Some(format) = afmt_to_virtio(a) else {
                return err(Errno::Einval);
            };
            if (formats & (1u64 << format)) == 0 {
                return err(Errno::Einval);
            }
            if !reset(owner) { return err(Errno::Eio); }
            {
                let mut guard = OSS.lock();
                let Some(o) = guard.iter_mut().find(|o| o.owner == owner) else {
                    return err(Errno::Enodev);
                };
                o.format = format;
            }
            wi(arg, virtio_to_afmt(format));
            0
        }
        6 => {                                                       // CHANNELS
            let n = match ri(arg) { Some(v) => v, None => return err(Errno::Efault) };
            let Some((_, _, ch_min, ch_max)) = caps(owner) else {
                return err(Errno::Enodev);
            };
            if !reset(owner) { return err(Errno::Eio); }
            let channels = n.min(u8::MAX as u32) as u8;
            let channels = channels.clamp(ch_min, ch_max);
            {
                let mut guard = OSS.lock();
                let Some(o) = guard.iter_mut().find(|o| o.owner == owner) else {
                    return err(Errno::Enodev);
                };
                o.channels = channels;
            }
            wi(arg, channels as u32);
            0
        }
        11 => { if UserBuf::new(arg, 4).is_none() { return err(Errno::Efault); }  // GETFMTS
                let Some((formats, _, _, _)) = caps(owner) else {
                    return err(Errno::Enodev);
                };
                wi(arg, formats_to_afmt(formats)); 0 }
        12 | 13 => {                                                 // GET[OI]SPACE
            let b = match UserBuf::new(arg, 16) { Some(b) => b, None => return err(Errno::Efault) };
            let frag = crate::ops::period_bytes(owner) as u32;
            b.w32(0, 2); b.w32(4, 2); b.w32(8, frag); b.w32(12, 2 * frag);
            0
        }
        15 => { if UserBuf::new(arg, 4).is_none() { return err(Errno::Efault); } wi(arg, 0); 0 } // GETCAPS
        10 | 14 => 0,                                                // SUBDIVIDE / SETFRAGMENT
        _ => err(Errno::Enotty),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(_owner: u32) -> Option<(u32, u32, u32, u32)> { Some((0, 0, 0, 0)) }
    fn caps(_owner: u32) -> crate::ops::Caps { Some((1 << V_S16, 1 << 6, 1, 2)) }
    fn period(_owner: u32) -> usize { 2048 }
    fn hw_params(_owner: u32, _rate: u8, _format: u8, _channels: u8, _period_bytes: u32, _buffer_bytes: u32) -> bool { true }
    fn yes(_owner: u32) -> bool { true }
    fn start_only(_owner: u32, start: bool) -> bool { start }
    fn submit(_owner: u32, b: &[u8]) -> usize { b.len() }
    fn recv(_owner: u32, b: &mut [u8]) -> usize { b.len() }

    static STOP_FAIL_OPS: crate::ops::SoundOps = crate::ops::SoundOps {
        config: cfg,
        pcm_caps: caps,
        cap_caps: caps,
        period_bytes: period,
        pcm_hw_params: hw_params,
        pcm_prepare: yes,
        pcm_trigger: start_only,
        pcm_hw_free: yes,
        pcm_submit: submit,
        cap_hw_params: hw_params,
        cap_prepare: yes,
        cap_trigger: start_only,
        cap_hw_free: yes,
        pcm_recv: recv,
    };

    fn test_err(e: Errno) -> i64 { -(e.as_i32() as i64) }

    #[test]
    fn parameter_change_does_not_clear_running_state_when_reset_fails() {
        let owner = 0x7100;
        unregister_card(owner);
        let _ = crate::ops::clear(owner);
        let _ = crate::cancel_card_reservation(owner);

        assert!(crate::reserve_card(owner));
        assert!(crate::ops::register(owner, &STOP_FAIL_OPS));
        register_card(owner);

        let getfmts_req = (2u64 << 30) | (4u64 << 16) | ((b'P' as u64) << 8) | 11;
        let mut fmts = 0u32;
        assert_eq!(handle(owner, false, getfmts_req, (&mut fmts as *mut u32) as u64), 0);
        assert_eq!(fmts, AFMT_S16_LE);

        let bytes = [0x55u8; 128];
        assert_eq!(write(owner, &bytes), bytes.len());
        {
            let guard = OSS.lock();
            let o = guard.iter().find(|o| o.owner == owner).expect("registered OSS state");
            assert!(o.running);
            assert_eq!(o.rate, 6);
        }

        let setfmt_req = (1u64 << 30) | (4u64 << 16) | ((b'P' as u64) << 8) | 5;
        let mut fmt = AFMT_U8;
        assert_eq!(handle(owner, false, setfmt_req, (&mut fmt as *mut u32) as u64), test_err(Errno::Einval));
        {
            let guard = OSS.lock();
            let o = guard.iter().find(|o| o.owner == owner).expect("registered OSS state");
            assert!(o.running);
            assert_eq!(o.format, V_S16);
        }

        let speed_req = (1u64 << 30) | (4u64 << 16) | ((b'P' as u64) << 8) | 2;
        let mut hz = 48_000u32;
        assert_eq!(handle(owner, false, speed_req, (&mut hz as *mut u32) as u64), test_err(Errno::Eio));
        {
            let guard = OSS.lock();
            let o = guard.iter().find(|o| o.owner == owner).expect("registered OSS state");
            assert!(o.running);
            assert_eq!(o.rate, 6);
        }

        unregister_card(owner);
        let _ = crate::ops::clear(owner);
        let _ = crate::cancel_card_reservation(owner);
    }
}
