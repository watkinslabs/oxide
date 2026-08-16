// Provenance: the SDxFMT / SET_STREAM_FORMAT word and the PAR_PCM capability
// response. A wrong format word plays at the wrong speed or not at all.

use super::*;

#[test]
fn the_forty_four_and_forty_eight_kilohertz_families_encode_their_base_bit() {
    // 48 kHz stereo 16-bit: base 48, mult 1, div 1, 16-bit, 2 channels.
    assert_eq!(stream_format(2, 16, 48000), Some(FMT_BASE_48K | FMT_BITS_16 | 1));
    // 44.1 kHz sets the base bit.
    assert_eq!(stream_format(2, 16, 44100), Some(FMT_BASE_44K | FMT_BITS_16 | 1));
}

#[test]
fn multipliers_and_divisors_come_from_the_rate_table() {
    // 96 kHz is 48 kHz doubled.
    assert_eq!(stream_format(2, 16, 96000), Some(FMT_BASE_48K | (1 << FMT_MULT_SHIFT) | FMT_BITS_16 | 1));
    // 8 kHz is 48 kHz divided by six.
    assert_eq!(stream_format(2, 16, 8000), Some(FMT_BASE_48K | (5 << FMT_DIV_SHIFT) | FMT_BITS_16 | 1));
    // 22.05 kHz is 44.1 kHz halved.
    assert_eq!(stream_format(2, 16, 22050), Some(FMT_BASE_44K | (1 << FMT_DIV_SHIFT) | FMT_BITS_16 | 1));
    // 32 kHz is 48 kHz times two over three.
    assert_eq!(stream_format(2, 16, 32000),
               Some(FMT_BASE_48K | (1 << FMT_MULT_SHIFT) | (2 << FMT_DIV_SHIFT) | FMT_BITS_16 | 1));
}

#[test]
fn every_sample_width_has_its_own_field_value() {
    assert_eq!(stream_format(2, 8, 48000).unwrap() & 0x70, FMT_BITS_8);
    assert_eq!(stream_format(2, 16, 48000).unwrap() & 0x70, FMT_BITS_16);
    assert_eq!(stream_format(2, 20, 48000).unwrap() & 0x70, FMT_BITS_20);
    assert_eq!(stream_format(2, 24, 48000).unwrap() & 0x70, FMT_BITS_24);
    assert_eq!(stream_format(2, 32, 48000).unwrap() & 0x70, FMT_BITS_32);
}

#[test]
fn an_unencodable_rate_width_or_channel_count_is_refused() {
    assert_eq!(stream_format(2, 16, 47000), None);
    assert_eq!(stream_format(2, 12, 48000), None);
    assert_eq!(stream_format(0, 16, 48000), None);
    assert_eq!(stream_format(17, 16, 48000), None);
    // Sixteen channels is the widest the field can express.
    assert_eq!(stream_format(16, 16, 48000).unwrap() & FMT_CHAN_MASK, 15);
}

#[test]
fn the_pcm_capability_response_becomes_alsa_masks() {
    // Bits 5 and 6 are 44.1 and 48 kHz.
    let caps = (1 << 5) | (1 << 6) | SUPPCM_BITS_16 | SUPPCM_BITS_24;
    let rates = pcm_rate_mask(caps);
    assert_eq!(rates, sound::format::rate_mask_of(&[44100, 48000]));
    let formats = pcm_format_mask(caps);
    assert!(sound::format::mask_has(formats, sound::uapi::FMT_S16_LE));
    assert!(sound::format::mask_has(formats, sound::uapi::FMT_S32_LE));
    assert!(!sound::format::mask_has(formats, sound::uapi::FMT_U8));
    // 24-bit samples travel in a 32-bit container with 24 significant bits.
    assert_eq!(max_bits(caps), 24);
    assert_eq!(bits_for_alsa_format(sound::uapi::FMT_S32_LE, caps), Some(24));
    assert_eq!(bits_for_alsa_format(sound::uapi::FMT_S16_LE, caps), Some(16));
    assert_eq!(bits_for_alsa_format(sound::uapi::FMT_S24_LE, caps), None);
}

#[test]
fn a_thirty_two_bit_codec_reports_the_full_width() {
    let caps = (1 << 6) | SUPPCM_BITS_16 | SUPPCM_BITS_20 | SUPPCM_BITS_24 | SUPPCM_BITS_32;
    assert_eq!(max_bits(caps), 32);
    assert_eq!(format_for(sound::uapi::FMT_S32_LE, 48000, 2, caps),
               Some(FMT_BASE_48K | FMT_BITS_32 | 1));
    assert_eq!(format_for(sound::uapi::FMT_S16_LE, 44100, 2, caps),
               Some(FMT_BASE_44K | FMT_BITS_16 | 1));
    // A codec with no width above 16 bits reports 16.
    assert_eq!(max_bits((1 << 6) | SUPPCM_BITS_16), 16);
}
