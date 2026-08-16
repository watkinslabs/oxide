// Provenance: the virtio-sound PCM format/rate enumerations and the ALSA
// format values the sound core negotiates in. A mis-indexed capability mask
// silently advertises the wrong format to userspace.

use super::*;

#[test]
fn alsa_formats_map_onto_the_device_codes() {
    assert_eq!(alsa_to_virtio(sound::uapi::FMT_S16_LE), Some(5));
    assert_eq!(alsa_to_virtio(sound::uapi::FMT_U8), Some(4));
    assert_eq!(alsa_to_virtio(sound::uapi::FMT_MU_LAW), Some(1));
    // The device has no 24/32-bit code, so those ALSA formats are unmappable.
    assert_eq!(alsa_to_virtio(sound::uapi::FMT_S32_LE), None);
    assert_eq!(alsa_to_virtio(sound::uapi::FMT_S24_LE), None);
}

#[test]
fn a_device_capability_mask_is_reindexed_onto_alsa_values() {
    // Device advertises S16 (bit 5) and U8 (bit 4) in its own numbering.
    let device = (1u64 << 5) | (1u64 << 4);
    let alsa = caps_mask_to_alsa(device);
    assert!(sound::format::mask_has(alsa, sound::uapi::FMT_S16_LE));
    assert!(sound::format::mask_has(alsa, sound::uapi::FMT_U8));
    // Bit 5 in the ALSA numbering is not a format this device offers.
    assert!(!sound::format::mask_has(alsa, sound::uapi::FMT_S32_LE));
    assert!(!sound::format::mask_has(alsa, sound::uapi::FMT_S8));
    assert_eq!(caps_mask_to_alsa(0), 0);
}

#[test]
fn rate_codes_share_the_alsa_index_order() {
    assert_eq!(hz_to_virtio_rate(44100), 6);
    assert_eq!(hz_to_virtio_rate(48000), 7);
    assert_eq!(hz_to_virtio_rate(8000), 1);
}
