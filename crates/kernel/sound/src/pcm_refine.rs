use syscall::errno::Errno;

use crate::uapi::*;

/// SNDRV_PCM_INFO_INTERLEAVED | BLOCK_TRANSFER (no MMAP — blocking writei).
const PCM_INFO_FLAGS: u32 = 0x100 | 0x10000;
const DEF_PERIOD_BYTES: u32 = 2048;
const DEF_PERIODS: u32 = 2;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn alsa_fmt_to_virtio(f: u32) -> Option<u8> {
    Some(match f {
        FMT_S8 => 3, FMT_U8 => 4, FMT_S16_LE => 5, FMT_U16_LE => 6,
        FMT_MU_LAW => 1, FMT_A_LAW => 2, _ => return None,
    })
}

fn fmt_bits(f: u32) -> u32 {
    if f == FMT_S16_LE || f == FMT_U16_LE { 16 } else { 8 }
}

fn rate_enum_hz(e: u8) -> u32 {
    const HZ: [u32; 14] = [5512, 8000, 11025, 16000, 22050, 32000, 44100,
                           48000, 64000, 88200, 96000, 176400, 192000, 384000];
    HZ[(e as usize).min(13)]
}

fn hz_rate_enum(hz: u32) -> u8 {
    const HZ: [u32; 14] = [5512, 8000, 11025, 16000, 22050, 32000, 44100,
                           48000, 64000, 88200, 96000, 176400, 192000, 384000];
    let mut best = 6u8;
    let mut bd = u32::MAX;
    for (i, &h) in HZ.iter().enumerate() {
        let d = h.abs_diff(hz);
        if d < bd {
            bd = d;
            best = i as u8;
        }
    }
    best
}

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

fn iv_set(b: &UserBuf, param: usize, v: u32) {
    let o = iv_off(param);
    b.w32(o, v);
    b.w32(o + 4, v);
    b.w32(o + 8, 0b100);
}

/// Concrete geometry chosen by the refinement (ALSA enums + frame math).
pub(crate) struct Resolved {
    pub format: u32,
    pub rate: u32,
    pub channels: u32,
    pub frame_bytes: u32,
    pub period_frames: u32,
    pub buffer_frames: u32,
    pub period_bytes: u32,
    pub buffer_bytes: u32,
}

pub(crate) fn fmt_alsa_to_virtio(f: u32) -> Option<u8> { alsa_fmt_to_virtio(f) }
pub(crate) fn rate_hz_to_enum(hz: u32) -> u8 { hz_rate_enum(hz) }

/// Refine the app's snd_pcm_hw_params against caps, pin supported values,
/// write them back, and return the resolved geometry.
/// # C: O(1)
pub(crate) fn refine_params(b: &UserBuf, vf: u64, vr: u64, ch_min: u8, ch_max: u8) -> Result<Resolved, i64> {
    if !mask_test(b, P_ACCESS, ACCESS_RW_INTERLEAVED) { return Err(err(Errno::Einval)); }
    mask_set_single(b, P_ACCESS, ACCESS_RW_INTERLEAVED);

    const PREF: [u32; 6] = [FMT_S16_LE, FMT_U8, FMT_S8, FMT_U16_LE, FMT_MU_LAW, FMT_A_LAW];
    let mut format = None;
    for &f in &PREF {
        if let Some(ve) = alsa_fmt_to_virtio(f) {
            if (vf >> ve) & 1 != 0 && mask_test(b, P_FORMAT, f) {
                format = Some(f);
                break;
            }
        }
    }
    let format = match format { Some(f) => f, None => return Err(err(Errno::Einval)) };
    mask_set_single(b, P_FORMAT, format);
    mask_set_single(b, P_SUBFORMAT, 0);

    let want_ch = iv_min(b, P_CHANNELS).max(1);
    if iv_max(b, P_CHANNELS).max(1) < ch_min as u32 || want_ch > ch_max as u32 {
        return Err(err(Errno::Einval));
    }
    let channels = want_ch.clamp(ch_min as u32, ch_max as u32);
    iv_set(b, P_CHANNELS, channels);

    let (rmin, rmax) = (iv_min(b, P_RATE), iv_max(b, P_RATE).max(iv_min(b, P_RATE)));
    const RPREF: [u32; 8] = [44100, 48000, 22050, 32000, 16000, 11025, 8000, 96000];
    let mut rate = None;
    for &hz in &RPREF {
        let ve = hz_rate_enum(hz);
        if (vr >> ve) & 1 != 0 && hz >= rmin && hz <= rmax {
            rate = Some(hz);
            break;
        }
    }
    let rate = rate.or_else(|| {
        (0u8..14).map(rate_enum_hz).find(|&hz| {
            let ve = hz_rate_enum(hz);
            (vr >> ve) & 1 != 0 && hz >= rmin && hz <= rmax
        })
    });
    let rate = match rate { Some(r) => r, None => return Err(err(Errno::Einval)) };
    iv_set(b, P_RATE, rate);

    let sbits = fmt_bits(format);
    let frame_bytes = (sbits / 8) * channels;
    iv_set(b, P_SAMPLE_BITS, sbits);
    iv_set(b, P_FRAME_BITS, sbits * channels);

    let pb = iv_min(b, P_PERIOD_BYTES);
    let ps = iv_min(b, P_PERIOD_SIZE);
    let period_bytes = if pb != 0 { pb } else if ps != 0 { ps * frame_bytes } else { DEF_PERIOD_BYTES };
    let period_bytes = period_bytes.clamp(frame_bytes.max(1), hal::PAGE_SIZE_BYTES as u32);
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
