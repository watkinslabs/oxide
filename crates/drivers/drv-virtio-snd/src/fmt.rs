// virtio-snd's private sample-format encoding and its mapping onto the ALSA
// format values the sound core negotiates in. The core knows only ALSA
// values; this table is the transport's own and stays here.

/// `VIRTIO_SND_PCM_FMT_*` ↔ `SNDRV_PCM_FORMAT_*`.
const FMT_MAP: [(u8, u32); 6] = [
    (1, sound::uapi::FMT_MU_LAW),
    (2, sound::uapi::FMT_A_LAW),
    (3, sound::uapi::FMT_S8),
    (4, sound::uapi::FMT_U8),
    (5, sound::uapi::FMT_S16_LE),
    (6, sound::uapi::FMT_U16_LE),
];

/// virtio format code for an ALSA format, when the device speaks it. # C: O(1)
pub fn alsa_to_virtio(format: u32) -> Option<u8> {
    FMT_MAP.iter().find(|(_, alsa)| *alsa == format).map(|(virtio, _)| *virtio)
}

/// Re-index a device format bitmap from virtio codes onto ALSA values so the
/// sound core can test it with `sound::format::mask_has`. # C: O(FMT_MAP)
pub fn caps_mask_to_alsa(virtio_mask: u64) -> u64 {
    let mut mask = 0u64;
    for (virtio, alsa) in FMT_MAP {
        if (virtio_mask >> virtio) & 1 != 0 { mask |= 1u64 << alsa; }
    }
    mask
}

/// virtio rate code for a rate in Hz. The virtio rate enum and ALSA's
/// `SNDRV_PCM_RATE_*` index share the same table order.
/// # C: O(rate table)
pub fn hz_to_virtio_rate(hz: u32) -> u8 { sound::format::nearest_rate_index(hz) }

#[cfg(test)]
#[path = "tests/fmt.rs"]
mod tests;
