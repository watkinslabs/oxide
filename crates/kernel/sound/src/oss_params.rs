use crate::format::{self, RATE_HZ};
use crate::oss::oss_state::{OSS, Oss};
use crate::uapi::*;

pub(crate) const AFMT_MU_LAW: u32 = 0x0000_0001;
pub(crate) const AFMT_A_LAW: u32 = 0x0000_0002;
pub(crate) const AFMT_U8: u32 = 0x0000_0008;
pub(crate) const AFMT_S16_LE: u32 = 0x0000_0010;
pub(crate) const AFMT_S8: u32 = 0x0000_0040;
pub(crate) const AFMT_U16_LE: u32 = 0x0000_0080;

/// OSS `AFMT_*` ↔ ALSA `SNDRV_PCM_FORMAT_*`. OSS has no 24/32-bit code, so
/// those ALSA formats are simply absent from the OSS view of the card.
const AFMT_MAP: [(u32, u32); 6] = [
    (AFMT_MU_LAW, FMT_MU_LAW), (AFMT_A_LAW, FMT_A_LAW), (AFMT_S8, FMT_S8),
    (AFMT_U8, FMT_U8), (AFMT_S16_LE, FMT_S16_LE), (AFMT_U16_LE, FMT_U16_LE),
];

/// # C: O(1)
pub(crate) fn afmt_to_alsa(a: u32) -> Option<u32> {
    AFMT_MAP.iter().find(|(oss, _)| *oss == a).map(|(_, alsa)| *alsa)
}

/// # C: O(1)
pub(crate) fn alsa_to_afmt(f: u32) -> u32 {
    AFMT_MAP.iter().find(|(_, alsa)| *alsa == f).map(|(oss, _)| *oss).unwrap_or(AFMT_S16_LE)
}

/// # C: O(1)
pub(crate) fn nearest_supported_rate_enum(hz: u32, rates: u64) -> Option<u8> {
    format::nearest_supported_rate_index(hz, rates)
}

/// # C: O(1)
pub(crate) fn rate_enum_to_hz(e: u8) -> u32 { format::rate_hz(e) }

fn first_supported_format(formats: u64) -> Option<u32> {
    [FMT_S16_LE, FMT_U8, FMT_S8, FMT_U16_LE, FMT_MU_LAW, FMT_A_LAW]
        .iter()
        .copied()
        .find(|format| format::mask_has(formats, *format))
}

/// # C: O(1)
pub(crate) fn formats_to_afmt(formats: u64) -> u32 {
    let mut out = 0;
    for (oss, alsa) in AFMT_MAP {
        if format::mask_has(formats, alsa) { out |= oss; }
    }
    out
}

/// # C: O(1)
pub(crate) fn caps(owner: crate::SoundOwnerKey) -> Option<(u64, u64, u8, u8)> {
    match (crate::ops::pcm_caps(owner), crate::ops::cap_caps(owner)) {
        (Some((pf, pr, pcmin, pcmax)), Some((cf, cr, ccmin, ccmax))) => {
            let formats = pf & cf;
            let rates = pr & cr;
            let ch_min = pcmin.max(ccmin);
            let ch_max = pcmax.min(ccmax);
            if formats == 0 || rates == 0 || ch_min > ch_max { None } else { Some((formats, rates, ch_min, ch_max)) }
        }
        (Some(caps), None) | (None, Some(caps)) => Some(caps),
        (None, None) => None,
    }
}

/// Default OSS geometry: 44.1 kHz stereo S16_LE where the card allows it.
/// # C: O(1)
pub(crate) fn initial_params(owner: crate::SoundOwnerKey) -> (u8, u32, u8) {
    const DEFAULT_RATE_INDEX: u8 = 6;
    let Some((formats, rates, ch_min, ch_max)) = caps(owner) else {
        return (DEFAULT_RATE_INDEX, FMT_S16_LE, 2);
    };
    let rate = nearest_supported_rate_enum(RATE_HZ[DEFAULT_RATE_INDEX as usize], rates)
        .unwrap_or(DEFAULT_RATE_INDEX);
    let format = first_supported_format(formats).unwrap_or(FMT_S16_LE);
    let channels = 2u8.clamp(ch_min, ch_max);
    (rate, format, channels)
}

/// # C: O(1)
pub(crate) fn fragment_geometry(o: &Oss) -> Option<(u32, u32)> {
    let period = if o.fragshift != 0 {
        1u32.checked_shl(o.fragshift as u32)?
    } else {
        let base = crate::ops::period_bytes(o.owner)? as u32;
        let divisor = if o.subdivision == 0 { 1 } else { o.subdivision as u32 };
        (base / divisor).max(1)
    };
    let maxfrags = u32::from(o.maxfrags.max(2));
    Some((period, maxfrags))
}

/// # C: O(1)
pub(crate) fn oss_period_buffer(owner: crate::SoundOwnerKey) -> Option<(u32, u32)> {
    let guard = OSS.lock();
    let o = guard.iter().find(|o| o.owner == owner)?;
    let (period, maxfrags) = fragment_geometry(o)?;
    Some((period, period.checked_mul(maxfrags)?))
}
