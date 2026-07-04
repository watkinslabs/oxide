use syscall::errno::Errno;

use crate::oss::oss_params::{afmt_to_virtio, caps, formats_to_afmt, fragment_geometry, nearest_supported_rate_enum, oss_period_buffer, rate_enum_to_hz, virtio_to_afmt};
use crate::oss::oss_state::OSS;
use crate::uapi::UserBuf;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

pub(crate) fn set_subdivision(owner: u32, subdivision: u32) -> i64 {
    if subdivision == 0 {
        let guard = OSS.lock();
        let Some(o) = guard.iter().find(|o| o.owner == owner) else { return err(Errno::Enodev); };
        return i64::from(if o.subdivision == 0 { 1 } else { o.subdivision as u32 });
    }
    if !matches!(subdivision, 1 | 2 | 4 | 8 | 16) { return err(Errno::Einval); }
    {
        let guard = OSS.lock();
        let Some(o) = guard.iter().find(|o| o.owner == owner) else { return err(Errno::Enodev); };
        if o.subdivision != 0 || o.fragshift != 0 { return err(Errno::Einval); }
    }
    if !reset(owner) { return err(Errno::Eio); }
    let mut guard = OSS.lock();
    let Some(o) = guard.iter_mut().find(|o| o.owner == owner) else { return err(Errno::Enodev); };
    o.subdivision = subdivision as u8;
    i64::from(subdivision)
}

pub(crate) fn set_fragment(owner: u32, val: u32) -> i64 {
    let mut fragshift = (val & 0xffff) as u8;
    if fragshift >= 25 { return err(Errno::Einval); }
    if fragshift < 4 { fragshift = 4; }
    let mut maxfrags = ((val >> 16) & 0xffff) as u16;
    if maxfrags < 2 { maxfrags = 2; }
    {
        let guard = OSS.lock();
        let Some(o) = guard.iter().find(|o| o.owner == owner) else { return err(Errno::Enodev); };
        if o.subdivision != 0 || o.fragshift != 0 { return err(Errno::Einval); }
    }
    if !reset(owner) { return err(Errno::Eio); }
    let mut guard = OSS.lock();
    let Some(o) = guard.iter_mut().find(|o| o.owner == owner) else { return err(Errno::Enodev); };
    o.fragshift = fragshift;
    o.maxfrags = maxfrags;
    0
}

/// Stop + release both directions and disarm, so the next I/O re-applies
/// params (SNDCTL_DSP_RESET / a param change).
pub(crate) fn reset(owner: u32) -> bool {
    let (running, cap_running) = {
        let mut guard = OSS.lock();
        let Some(o) = guard.iter_mut().find(|o| o.owner == owner) else { return false; };
        (o.running, o.cap_running)
    };
    if running {
        if !crate::ops::pcm_trigger(owner, false) || !crate::ops::pcm_hw_free(owner) { return false; }
        if let Some(o) = OSS.lock().iter_mut().find(|o| o.owner == owner) {
            o.running = false;
        }
    }
    if cap_running {
        if !crate::ops::cap_trigger(owner, false) || !crate::ops::cap_hw_free(owner) { return false; }
        if let Some(o) = OSS.lock().iter_mut().find(|o| o.owner == owner) {
            o.cap_running = false;
        }
    }
    true
}

/// /dev/dsp read(2): lazily arm capture then receive.
/// # C: O(bytes/period × RXQ round-trip)
pub fn read(owner: u32, buf: &mut [u8]) -> usize {
    if buf.is_empty() { return 0; }
    let (rate, fmt, ch, cap_running) = {
        let guard = OSS.lock();
        let Some(o) = guard.iter().find(|o| o.owner == owner) else { return 0; };
        (o.rate, o.format, o.channels, o.cap_running)
    };
    if !cap_running {
        let Some((period, buffer)) = oss_period_buffer(owner) else { return 0; };
        if !crate::ops::cap_hw_params(owner, rate, fmt, ch, period, buffer) { return 0; }
        if !crate::ops::cap_prepare(owner) { return 0; }
        if !crate::ops::cap_trigger(owner, true) { return 0; }
        let mut guard = OSS.lock();
        let Some(o) = guard.iter_mut().find(|o| o.owner == owner) else { return 0; };
        o.cap_running = true;
    }
    crate::ops::pcm_recv(owner, buf)
}

/// /dev/dsp write(2): lazily arm playback then submit.
/// # C: O(bytes/period × TXQ round-trip)
pub fn write(owner: u32, buf: &[u8]) -> usize {
    if buf.is_empty() { return 0; }
    let (rate, fmt, ch, running) = {
        let guard = OSS.lock();
        let Some(o) = guard.iter().find(|o| o.owner == owner) else { return 0; };
        (o.rate, o.format, o.channels, o.running)
    };
    if !running {
        let Some((period, buffer)) = oss_period_buffer(owner) else { return 0; };
        if !crate::ops::pcm_hw_params(owner, rate, fmt, ch, period, buffer) { return 0; }
        if !crate::ops::pcm_prepare(owner) { return 0; }
        if !crate::ops::pcm_trigger(owner, true) { return 0; }
        let mut guard = OSS.lock();
        let Some(o) = guard.iter_mut().find(|o| o.owner == owner) else { return 0; };
        o.running = true;
    }
    crate::ops::pcm_submit(owner, buf)
}

/// Handle a SNDCTL_DSP_* (`/dev/dsp`, minor=DSP/AUDIO) or SOUND_MIXER_* ioctl.
/// # C: O(1)
pub fn handle(owner: u32, is_mixer: bool, req: u64, arg: u64) -> i64 {
    let group = (req >> 8) & 0xFF;
    let nr = req & 0xFF;
    let dir = (req >> 30) & 0x3;
    const IOC_WRITE: u64 = 1;

    if is_mixer || group == b'M' as u64 {
        let b = match UserBuf::new(arg, 4) { Some(b) => b, None => return err(Errno::Efault) };
        if (dir & IOC_WRITE) != 0 {
            let packed = b.r32(0);
            if !crate::control::set_mixer_level(owner, packed) { return err(Errno::Enodev); }
        }
        let Some(level) = crate::control::mixer_level(owner) else { return err(Errno::Enodev); };
        b.w32(0, level);
        return 0;
    }
    if group != b'P' as u64 { return err(Errno::Enotty); }

    let ri = |a: u64| UserBuf::new(a, 4).map(|b| b.r32(0));
    let wi = |a: u64, v: u32| { if let Some(b) = UserBuf::new(a, 4) { b.w32(0, v); } };

    match nr {
        0 => if reset(owner) { 0 } else { err(Errno::Eio) },
        1 | 8 => 0,
        2 => {
            let hz = match ri(arg) { Some(v) => v, None => return err(Errno::Efault) };
            let Some((_, rates, _, _)) = caps(owner) else { return err(Errno::Enodev); };
            let Some(e) = nearest_supported_rate_enum(hz, rates) else { return err(Errno::Einval); };
            if !reset(owner) { return err(Errno::Eio); }
            let mut guard = OSS.lock();
            let Some(o) = guard.iter_mut().find(|o| o.owner == owner) else { return err(Errno::Enodev); };
            o.rate = e;
            wi(arg, rate_enum_to_hz(e));
            0
        }
        3 => {
            let st = match ri(arg) { Some(v) => v, None => return err(Errno::Efault) };
            let Some((_, _, ch_min, ch_max)) = caps(owner) else { return err(Errno::Enodev); };
            if !reset(owner) { return err(Errno::Eio); }
            let channels = (if st != 0 { 2 } else { 1 }).clamp(ch_min, ch_max);
            let mut guard = OSS.lock();
            let Some(o) = guard.iter_mut().find(|o| o.owner == owner) else { return err(Errno::Enodev); };
            o.channels = channels;
            wi(arg, (channels - 1) as u32);
            0
        }
        4 => {
            if UserBuf::new(arg, 4).is_none() { return err(Errno::Efault); }
            let Some((period, _)) = oss_period_buffer(owner) else { return err(Errno::Enodev); };
            wi(arg, period);
            0
        }
        5 => {
            let a = match ri(arg) { Some(v) => v, None => return err(Errno::Efault) };
            if a == 0 {
                let guard = OSS.lock();
                let Some(o) = guard.iter().find(|o| o.owner == owner) else { return err(Errno::Enodev); };
                wi(arg, virtio_to_afmt(o.format));
                return 0;
            }
            let Some((formats, _, _, _)) = caps(owner) else { return err(Errno::Enodev); };
            let Some(format) = afmt_to_virtio(a) else { return err(Errno::Einval); };
            if (formats & (1u64 << format)) == 0 { return err(Errno::Einval); }
            if !reset(owner) { return err(Errno::Eio); }
            let mut guard = OSS.lock();
            let Some(o) = guard.iter_mut().find(|o| o.owner == owner) else { return err(Errno::Enodev); };
            o.format = format;
            wi(arg, virtio_to_afmt(format));
            0
        }
        6 => {
            let n = match ri(arg) { Some(v) => v, None => return err(Errno::Efault) };
            let Some((_, _, ch_min, ch_max)) = caps(owner) else { return err(Errno::Enodev); };
            if !reset(owner) { return err(Errno::Eio); }
            let channels = (n.min(u8::MAX as u32) as u8).clamp(ch_min, ch_max);
            let mut guard = OSS.lock();
            let Some(o) = guard.iter_mut().find(|o| o.owner == owner) else { return err(Errno::Enodev); };
            o.channels = channels;
            wi(arg, channels as u32);
            0
        }
        11 => {
            if UserBuf::new(arg, 4).is_none() { return err(Errno::Efault); }
            let Some((formats, _, _, _)) = caps(owner) else { return err(Errno::Enodev); };
            wi(arg, formats_to_afmt(formats));
            0
        }
        12 | 13 => {
            let b = match UserBuf::new(arg, 16) { Some(b) => b, None => return err(Errno::Efault) };
            let Some((frag, maxfrags)) = ({ let guard = OSS.lock(); guard.iter().find(|o| o.owner == owner).and_then(fragment_geometry) }) else {
                return err(Errno::Enodev);
            };
            let Some(bytes) = maxfrags.checked_mul(frag) else { return err(Errno::Einval); };
            b.w32(0, maxfrags);
            b.w32(4, maxfrags);
            b.w32(8, frag);
            b.w32(12, bytes);
            0
        }
        15 => {
            if UserBuf::new(arg, 4).is_none() { return err(Errno::Efault); }
            wi(arg, 0);
            0
        }
        10 => {
            let subdivide = match ri(arg) { Some(v) => v, None => return err(Errno::Efault) };
            let res = set_subdivision(owner, subdivide);
            if res < 0 { return res; }
            wi(arg, res as u32);
            0
        }
        14 => {
            let fragment = match ri(arg) { Some(v) => v, None => return err(Errno::Efault) };
            set_fragment(owner, fragment)
        }
        _ => err(Errno::Enotty),
    }
}
