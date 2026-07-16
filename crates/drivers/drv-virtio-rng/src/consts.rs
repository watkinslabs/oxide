/// Virtio device ID for entropy devices.
pub const VIRTIO_ID_RNG: u16 = 4;

/// Linux misc hwrng device identity (major 10, minor 183).
pub(crate) const HWRNG_MAJOR: u32 = 10;
pub(crate) const HWRNG_MINOR: u32 = 183;

/// Driver-model identity for virtio-rng child binding.
pub const DRIVER_ID: virtio::VirtioChildDriverId =
    virtio::VirtioChildDriverId::new("virtio-rng", VIRTIO_ID_RNG);

pub(crate) const FILL_POLL_BUDGET: u32 = 2_000_000;
pub(crate) const FILL_BUFFER_BYTES: usize = hal::PAGE_SIZE_BYTES as usize;
const WANTED_FEATURES: u64 = virtio::VIRTIO_F_VERSION_1;

pub const fn wanted_features() -> u64 {
    WANTED_FEATURES
}

pub const fn transport_profile() -> virtio::VirtioTransportProfile {
    virtio::VirtioTransportProfile::q0(wanted_features(), None)
}
