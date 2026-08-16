// Provenance: the ALSA format/rate contract these assertions pin is the one
// glibc's ALSA userspace negotiates against — container widths, msbits, the
// SNDRV_PCM_RATE_* index order, and nearest-rate selection.

use super::*;

#[test]
fn container_width_and_msbits_match_the_alsa_contract() {
    assert_eq!(phys_bits(FMT_S8), Some(8));
    assert_eq!(phys_bits(FMT_U8), Some(8));
    assert_eq!(phys_bits(FMT_MU_LAW), Some(8));
    assert_eq!(phys_bits(FMT_A_LAW), Some(8));
    assert_eq!(phys_bits(FMT_S16_LE), Some(16));
    assert_eq!(phys_bits(FMT_U16_LE), Some(16));
    assert_eq!(phys_bits(FMT_S24_LE), Some(32));
    assert_eq!(phys_bits(FMT_S32_LE), Some(32));
    assert_eq!(phys_bits(99), None);

    // S24_LE is 24 significant bits inside a 32-bit container; every other
    // negotiated format fills its container.
    assert_eq!(msbits(FMT_S24_LE), 24);
    assert_eq!(msbits(FMT_S32_LE), 32);
    assert_eq!(msbits(FMT_S16_LE), 16);
    assert_eq!(msbits(FMT_U8), 8);
}

#[test]
fn capability_masks_are_indexed_by_the_alsa_format_value() {
    let mask = mask_of(&[FMT_S16_LE, FMT_S32_LE]);
    assert_eq!(mask, (1u64 << FMT_S16_LE) | (1u64 << FMT_S32_LE));
    assert!(mask_has(mask, FMT_S16_LE));
    assert!(mask_has(mask, FMT_S32_LE));
    assert!(!mask_has(mask, FMT_U8));
    // An unrepresentable format is never advertised, whatever the mask says.
    assert!(!mask_has(u64::MAX, 99));
    assert_eq!(mask_bit(99), None);
    // Formats outside the negotiated set contribute no bit.
    assert_eq!(mask_of(&[99, 100]), 0);
}

#[test]
fn rate_index_order_is_the_alsa_rate_bit_order() {
    assert_eq!(RATE_HZ[0], 5512);
    assert_eq!(RATE_HZ[6], 44100);
    assert_eq!(RATE_HZ[7], 48000);
    assert_eq!(RATE_HZ[13], 384000);
    assert_eq!(rate_hz(6), 44100);
    // Out-of-range index clamps rather than panicking in a kernel path.
    assert_eq!(rate_hz(200), 384000);
    assert_eq!(rate_mask_of(&[44100, 48000]), (1 << 6) | (1 << 7));
    assert_eq!(rate_mask_of(&[44101]), 0);
}

#[test]
fn nearest_rate_selection_respects_the_advertised_mask() {
    assert_eq!(nearest_rate_index(44100), 6);
    assert_eq!(nearest_rate_index(45000), 6);
    let only_48k = rate_mask_of(&[48000]);
    assert_eq!(nearest_supported_rate_index(44100, only_48k), Some(7));
    assert_eq!(nearest_supported_rate_index(44100, 0), None);
    let both = rate_mask_of(&[8000, 48000]);
    assert_eq!(nearest_supported_rate_index(11025, both), Some(1));
}

#[test]
fn frame_bytes_follows_container_width_times_channels() {
    assert_eq!(frame_bytes(FMT_S16_LE, 2), 4);
    assert_eq!(frame_bytes(FMT_S32_LE, 2), 8);
    assert_eq!(frame_bytes(FMT_S24_LE, 1), 4);
    assert_eq!(frame_bytes(FMT_U8, 2), 2);
    // Zero channels is treated as one frame's worth, never a zero divisor.
    assert_eq!(frame_bytes(FMT_S16_LE, 0), 2);
}
