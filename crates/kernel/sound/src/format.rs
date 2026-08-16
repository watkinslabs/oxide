// Single owner for ALSA sample-format and sample-rate math shared by the PCM
// core, the OSS emulation and every card driver. Capability masks handed to
// this core are indexed by the ALSA `SNDRV_PCM_FORMAT_*` value and by the
// `SNDRV_PCM_RATE_*` index in `RATE_HZ`; transport-private encodings stay in
// the driver that owns the transport.

use crate::uapi::*;

/// `SNDRV_PCM_RATE_*` index order. Bit `i` of a rate mask selects `RATE_HZ[i]`.
pub const RATE_HZ: [u32; 14] = [5512, 8000, 11025, 16000, 22050, 32000, 44100,
                                48000, 64000, 88200, 96000, 176400, 192000, 384000];

/// Preference order the refinement walks when the application accepts more
/// than one format: widest common denominator first.
pub const FMT_PREF: [u32; 8] = [FMT_S16_LE, FMT_S32_LE, FMT_S24_LE, FMT_U8,
                                FMT_S8, FMT_U16_LE, FMT_MU_LAW, FMT_A_LAW];

/// Preferred negotiation order for rates when several are acceptable.
pub const RATE_PREF: [u32; 8] = [44100, 48000, 22050, 32000, 16000, 11025, 8000, 96000];

/// Physical container width in bits of an ALSA format, `None` when the format
/// is outside the set this core negotiates. # C: O(1)
pub fn phys_bits(fmt: u32) -> Option<u32> {
    Some(match fmt {
        FMT_S8 | FMT_U8 | FMT_MU_LAW | FMT_A_LAW => 8,
        FMT_S16_LE | FMT_U16_LE => 16,
        FMT_S24_LE | FMT_S32_LE => 32,
        _ => return None,
    })
}

/// Significant bits carried in the container (`msbits`). # C: O(1)
pub fn msbits(fmt: u32) -> u32 {
    match fmt {
        FMT_S24_LE => 24,
        other => phys_bits(other).unwrap_or(0),
    }
}

/// Bit position of `fmt` in a capability mask, `None` when unrepresentable. # C: O(1)
pub fn mask_bit(fmt: u32) -> Option<u32> {
    if phys_bits(fmt).is_some() && fmt < 64 { Some(fmt) } else { None }
}

/// Does a capability mask advertise `fmt`? # C: O(1)
pub fn mask_has(mask: u64, fmt: u32) -> bool {
    match mask_bit(fmt) { Some(bit) => (mask >> bit) & 1 != 0, None => false }
}

/// Build a capability mask from the ALSA formats in `formats`. # C: O(formats)
pub fn mask_of(formats: &[u32]) -> u64 {
    let mut mask = 0u64;
    for &fmt in formats {
        if let Some(bit) = mask_bit(fmt) { mask |= 1u64 << bit; }
    }
    mask
}

/// Rate-mask index whose entry is closest to `hz`. # C: O(RATE_HZ)
pub fn nearest_rate_index(hz: u32) -> u8 {
    let mut best = 6u8;
    let mut best_delta = u32::MAX;
    for (idx, &rate) in RATE_HZ.iter().enumerate() {
        let delta = rate.abs_diff(hz);
        if delta < best_delta { best_delta = delta; best = idx as u8; }
    }
    best
}

/// Hz for a rate-mask index, clamped to the table. # C: O(1)
pub fn rate_hz(index: u8) -> u32 { RATE_HZ[(index as usize).min(RATE_HZ.len() - 1)] }

/// Nearest rate the mask actually advertises. # C: O(RATE_HZ)
pub fn nearest_supported_rate_index(hz: u32, rates: u64) -> Option<u8> {
    let mut best = None;
    let mut best_delta = u32::MAX;
    for (idx, &rate) in RATE_HZ.iter().enumerate() {
        if (rates >> idx) & 1 == 0 { continue; }
        let delta = rate.abs_diff(hz);
        if delta < best_delta { best_delta = delta; best = Some(idx as u8); }
    }
    best
}

/// Build a rate mask from a list of Hz values. # C: O(rates × RATE_HZ)
pub fn rate_mask_of(rates: &[u32]) -> u64 {
    let mut mask = 0u64;
    for &hz in rates {
        if let Some(idx) = RATE_HZ.iter().position(|&entry| entry == hz) { mask |= 1u64 << idx; }
    }
    mask
}

/// Frame size in bytes for a format/channel pair. # C: O(1)
pub fn frame_bytes(fmt: u32, channels: u32) -> u32 {
    phys_bits(fmt).unwrap_or(8) / 8 * channels.max(1)
}

#[cfg(test)]
#[path = "tests/format.rs"]
mod tests;
