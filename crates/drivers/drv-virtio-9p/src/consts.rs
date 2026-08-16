// Device identity, feature bits, and the buffer geometry the transport frames
// requests into.

/// Virtio device ID for a 9P transport device.
pub const VIRTIO_ID_9P: u16 = 9;

/// `VIRTIO_9P_MOUNT_TAG` — the device publishes a mount tag in its
/// configuration. MANDATORY here: without a tag nothing can name the device,
/// so a device that does not offer it is one this driver does not bind.
pub const VIRTIO_9P_F_MOUNT_TAG: u64 = 1 << 0;

/// Driver-model identity for virtio-9p child binding.
pub const DRIVER_ID: virtio::VirtioChildDriverId =
    virtio::VirtioChildDriverId::new("virtio-9p", VIRTIO_ID_9P);

/// Buddy order of each DMA staging buffer: 2^5 pages.
pub(crate) const BUFFER_ORDER: pmm::Order = pmm::Order(5);
/// Bytes in one staging buffer, and therefore the largest frame this transport
/// can carry in either direction.
pub(crate) const BUFFER_BYTES: usize = (1usize << BUFFER_ORDER.0) * hal::PAGE_SIZE_BYTES as usize;

/// Spins to wait for the device to complete one request before giving up.
/// Bounded so a wedged device fails the mount instead of hanging the caller
/// forever with no diagnosis.
pub(crate) const COMPLETION_POLL_BUDGET: u32 = 20_000_000;

const WANTED_FEATURES: u64 = virtio::VIRTIO_F_VERSION_1 | VIRTIO_9P_F_MOUNT_TAG;

/// # C: O(1)
pub const fn wanted_features() -> u64 { WANTED_FEATURES }

/// One request virtqueue plus the device configuration the tag lives in.
/// # C: O(1)
pub const fn transport_profile() -> virtio::VirtioTransportProfile {
    virtio::VirtioTransportProfile::q0_device_cfg(wanted_features(), None)
}
