use crate::oss::oss_state::{OSS, Oss};

pub(crate) const V_MU_LAW: u8 = 1;
pub(crate) const V_A_LAW: u8 = 2;
pub(crate) const V_S8: u8 = 3;
pub(crate) const V_U8: u8 = 4;
pub(crate) const V_S16: u8 = 5;
pub(crate) const V_U16: u8 = 6;

pub(crate) const AFMT_MU_LAW: u32 = 0x0000_0001;
pub(crate) const AFMT_A_LAW: u32 = 0x0000_0002;
pub(crate) const AFMT_U8: u32 = 0x0000_0008;
pub(crate) const AFMT_S16_LE: u32 = 0x0000_0010;
pub(crate) const AFMT_S8: u32 = 0x0000_0040;
pub(crate) const AFMT_U16_LE: u32 = 0x0000_0080;

const RATE_HZ: [u32; 14] = [5512, 8000, 11025, 16000, 22050, 32000, 44100,
                            48000, 64000, 88200, 96000, 176400, 192000, 384000];

pub(crate) fn afmt_to_virtio(a: u32) -> Option<u8> {
    match a {
        AFMT_MU_LAW => Some(V_MU_LAW), AFMT_A_LAW => Some(V_A_LAW), AFMT_S8 => Some(V_S8),
        AFMT_U8 => Some(V_U8), AFMT_S16_LE => Some(V_S16), AFMT_U16_LE => Some(V_U16), _ => None,
    }
}

pub(crate) fn virtio_to_afmt(v: u8) -> u32 {
    match v {
        V_MU_LAW => AFMT_MU_LAW, V_A_LAW => AFMT_A_LAW, V_S8 => AFMT_S8,
        V_U8 => AFMT_U8, V_U16 => AFMT_U16_LE, _ => AFMT_S16_LE,
    }
}

pub(crate) fn nearest_supported_rate_enum(hz: u32, rates: u64) -> Option<u8> {
    let mut best = None;
    let mut best_delta = u32::MAX;
    for (i, &rate_hz) in RATE_HZ.iter().enumerate() {
        if (rates & (1u64 << i)) == 0 { continue; }
        let delta = rate_hz.abs_diff(hz);
        if delta < best_delta {
            best = Some(i as u8);
            best_delta = delta;
        }
    }
    best
}

pub(crate) fn rate_enum_to_hz(e: u8) -> u32 { RATE_HZ[(e as usize).min(RATE_HZ.len() - 1)] }

fn first_supported_format(formats: u64) -> Option<u8> {
    [V_S16, V_U8, V_S8, V_U16, V_MU_LAW, V_A_LAW]
        .iter()
        .copied()
        .find(|format| (formats & (1u64 << *format)) != 0)
}

pub(crate) fn formats_to_afmt(formats: u64) -> u32 {
    let mut out = 0;
    for format in [V_MU_LAW, V_A_LAW, V_S8, V_U8, V_S16, V_U16] {
        if (formats & (1u64 << format)) != 0 {
            out |= virtio_to_afmt(format);
        }
    }
    out
}

pub(crate) fn caps(owner: u32) -> Option<(u64, u64, u8, u8)> {
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

pub(crate) fn initial_params(owner: u32) -> (u8, u8, u8) {
    let Some((formats, rates, ch_min, ch_max)) = caps(owner) else {
        return (6, V_S16, 2);
    };
    let rate = nearest_supported_rate_enum(44_100, rates).unwrap_or(6);
    let format = first_supported_format(formats).unwrap_or(V_S16);
    let channels = 2u8.clamp(ch_min, ch_max);
    (rate, format, channels)
}

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

pub(crate) fn oss_period_buffer(owner: u32) -> Option<(u32, u32)> {
    let guard = OSS.lock();
    let o = guard.iter().find(|o| o.owner == owner)?;
    let (period, maxfrags) = fragment_geometry(o)?;
    Some((period, period.checked_mul(maxfrags)?))
}
