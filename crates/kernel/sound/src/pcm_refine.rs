use syscall::errno::Errno;

use crate::format::{self, FMT_PREF, RATE_PREF};
use crate::uapi::*;

/// Transfer model this core implements for every card: interleaved, whole
/// blocks. Card-specific capabilities are ORed in from the card's ops.
const CORE_INFO_FLAGS: u32 = PCM_INFO_INTERLEAVED | PCM_INFO_BLOCK_TRANSFER;
const DEF_PERIOD_BYTES: u32 = 2048;
const DEF_PERIODS: u32 = 2;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

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

/// Concrete geometry chosen by the refinement (ALSA format enum + Hz).
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

/// Transfer-path ceiling the card driver reports.
pub(crate) struct Limits {
    pub max_period_bytes: u32,
    pub max_buffer_bytes: u32,
}

/// Refine the app's snd_pcm_hw_params against caps, pin supported values,
/// write them back, and return the resolved geometry.
/// # C: O(1)
pub(crate) fn refine_params(b: &UserBuf, formats: u64, rates: u64, ch_min: u8, ch_max: u8,
                            limits: &Limits, info_flags: u32) -> Result<Resolved, i64> {
    if !mask_test(b, P_ACCESS, ACCESS_RW_INTERLEAVED) { return Err(err(Errno::Einval)); }
    mask_set_single(b, P_ACCESS, ACCESS_RW_INTERLEAVED);

    let Some(fmt) = FMT_PREF.iter().copied()
        .find(|&f| format::mask_has(formats, f) && mask_test(b, P_FORMAT, f)) else {
            return Err(err(Errno::Einval));
        };
    mask_set_single(b, P_FORMAT, fmt);
    mask_set_single(b, P_SUBFORMAT, 0);

    let want_ch = iv_min(b, P_CHANNELS).max(1);
    if iv_max(b, P_CHANNELS).max(1) < ch_min as u32 || want_ch > ch_max as u32 {
        return Err(err(Errno::Einval));
    }
    let channels = want_ch.clamp(ch_min as u32, ch_max as u32);
    iv_set(b, P_CHANNELS, channels);

    let (rmin, rmax) = (iv_min(b, P_RATE), iv_max(b, P_RATE).max(iv_min(b, P_RATE)));
    let acceptable = |hz: u32| {
        let index = format::nearest_rate_index(hz);
        format::rate_hz(index) == hz && (rates >> index) & 1 != 0 && hz >= rmin && hz <= rmax
    };
    let Some(rate) = RATE_PREF.iter().copied().find(|&hz| acceptable(hz))
        .or_else(|| format::RATE_HZ.iter().copied().find(|&hz| acceptable(hz))) else {
            return Err(err(Errno::Einval));
        };
    iv_set(b, P_RATE, rate);

    let sbits = format::phys_bits(fmt).unwrap_or(8);
    let frame_bytes = format::frame_bytes(fmt, channels).max(1);
    iv_set(b, P_SAMPLE_BITS, sbits);
    iv_set(b, P_FRAME_BITS, sbits * channels);

    let pb = iv_min(b, P_PERIOD_BYTES);
    let ps = iv_min(b, P_PERIOD_SIZE);
    let period_bytes = if pb != 0 { pb } else if ps != 0 { ps * frame_bytes } else { DEF_PERIOD_BYTES };
    let period_bytes = period_bytes.clamp(frame_bytes, limits.max_period_bytes.max(frame_bytes));
    let period_frames = (period_bytes / frame_bytes).max(1);
    let period_bytes = period_frames * frame_bytes;

    let requested_periods = { let p = iv_min(b, P_PERIODS); if p >= 2 { p } else { DEF_PERIODS } };
    let max_periods = (limits.max_buffer_bytes / period_bytes).max(2);
    let periods = requested_periods.min(max_periods);
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
    b.w32(HWP_INFO, CORE_INFO_FLAGS | info_flags);
    b.w32(HWP_MSBITS, format::msbits(fmt));
    b.w32(HWP_RATE_NUM, rate);
    b.w32(HWP_RATE_DEN, 1);
    b.w64(HWP_FIFO_SIZE, 0);

    Ok(Resolved {
        format: fmt, rate, channels, frame_bytes,
        period_frames, buffer_frames, period_bytes, buffer_bytes,
    })
}

/// Limits from the card's ops, falling back to a one-page period.
/// # C: O(1)
pub(crate) fn limits_for(owner: crate::SoundOwnerKey) -> Limits {
    match crate::ops::hw_limits(owner) {
        Some((period, buffer)) => Limits { max_period_bytes: period, max_buffer_bytes: buffer },
        None => Limits {
            max_period_bytes: hal::PAGE_SIZE_BYTES as u32,
            max_buffer_bytes: hal::PAGE_SIZE_BYTES as u32 * DEF_PERIODS,
        },
    }
}
