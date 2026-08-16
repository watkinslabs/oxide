// Stream format word shared by the controller's SDxFMT register and the
// codec's SET_STREAM_FORMAT verb, plus the codec's PCM capability decode.

use crate::uapi::*;

/// `(hz, base_44k, multiplier, divisor)` — the only rates a stream format
/// can express.
const RATES: [(u32, bool, u16, u16); 11] = [
    (8000, false, 1, 6),
    (11025, true, 1, 4),
    (16000, false, 1, 3),
    (22050, true, 1, 2),
    (32000, false, 2, 3),
    (44100, true, 1, 1),
    (48000, false, 1, 1),
    (88200, true, 2, 1),
    (96000, false, 2, 1),
    (176400, true, 4, 1),
    (192000, false, 4, 1),
];

/// Rate bitmap order in a `PAR_PCM` response.
const PCM_RATE_HZ: [u32; 12] = [8000, 11025, 16000, 22050, 32000, 44100,
                                48000, 88200, 96000, 176400, 192000, 384000];

pub const SUPPCM_RATES_MASK: u32 = 0x0fff;
pub const SUPPCM_BITS_8: u32 = 1 << 16;
pub const SUPPCM_BITS_16: u32 = 1 << 17;
pub const SUPPCM_BITS_20: u32 = 1 << 18;
pub const SUPPCM_BITS_24: u32 = 1 << 19;
pub const SUPPCM_BITS_32: u32 = 1 << 20;
pub const SUPFMT_PCM: u32 = 1 << 0;

/// Encode the 16-bit stream format. `None` for a rate, width or channel
/// count the format word cannot express.
/// # C: O(rate table)
pub fn stream_format(channels: u32, bits: u32, rate: u32) -> Option<u16> {
    if channels == 0 || channels > FMT_MAX_CHANNELS { return None; }
    let (_, base_44k, mult, div) = *RATES.iter().find(|(hz, _, _, _)| *hz == rate)?;
    let bits_field = match bits {
        8 => FMT_BITS_8,
        16 => FMT_BITS_16,
        20 => FMT_BITS_20,
        24 => FMT_BITS_24,
        32 => FMT_BITS_32,
        _ => return None,
    };
    let base = if base_44k { FMT_BASE_44K } else { FMT_BASE_48K };
    Some(base | ((mult - 1) << FMT_MULT_SHIFT) | ((div - 1) << FMT_DIV_SHIFT)
         | bits_field | (channels as u16 - 1))
}

/// Rates in Hz a `PAR_PCM` response advertises, as an ALSA rate mask the
/// sound core understands. # C: O(rate table)
pub fn pcm_rate_mask(par_pcm: u32) -> u64 {
    let mut mask = 0u64;
    for (bit, hz) in PCM_RATE_HZ.iter().enumerate() {
        if (par_pcm >> bit) & 1 != 0 { mask |= sound::format::rate_mask_of(&[*hz]); }
    }
    mask
}

/// ALSA formats a `PAR_PCM` response supports. Every width above 16 bits
/// travels in a 32-bit container, so 20-, 24- and 32-bit codecs all present
/// the same ALSA format and differ only in the significant-bit count.
/// # C: O(1)
pub fn pcm_format_mask(par_pcm: u32) -> u64 {
    let mut formats: [u32; 3] = [0; 3];
    let mut count = 0;
    if par_pcm & SUPPCM_BITS_8 != 0 { formats[count] = sound::uapi::FMT_U8; count += 1; }
    if par_pcm & SUPPCM_BITS_16 != 0 { formats[count] = sound::uapi::FMT_S16_LE; count += 1; }
    if par_pcm & (SUPPCM_BITS_20 | SUPPCM_BITS_24 | SUPPCM_BITS_32) != 0 {
        formats[count] = sound::uapi::FMT_S32_LE;
        count += 1;
    }
    sound::format::mask_of(&formats[..count])
}

/// Widest significant-bit count the codec advertises above 16 bits. # C: O(1)
pub fn max_bits(par_pcm: u32) -> u32 {
    if par_pcm & SUPPCM_BITS_32 != 0 { 32 }
    else if par_pcm & SUPPCM_BITS_24 != 0 { 24 }
    else if par_pcm & SUPPCM_BITS_20 != 0 { 20 }
    else { 16 }
}

/// Bits-per-sample a stream format must carry for an ALSA format on a codec
/// with these PCM capabilities. # C: O(1)
pub fn bits_for_alsa_format(format: u32, par_pcm: u32) -> Option<u32> {
    match format {
        sound::uapi::FMT_U8 => Some(8),
        sound::uapi::FMT_S16_LE => Some(16),
        sound::uapi::FMT_S32_LE => Some(max_bits(par_pcm)),
        _ => None,
    }
}

/// Stream format word for an ALSA format/rate/channel triple. # C: O(rate table)
pub fn format_for(alsa_format: u32, rate: u32, channels: u32, par_pcm: u32) -> Option<u16> {
    stream_format(channels, bits_for_alsa_format(alsa_format, par_pcm)?, rate)
}

#[cfg(test)]
#[path = "tests/stream_fmt.rs"]
mod tests;
