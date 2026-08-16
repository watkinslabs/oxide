// Device identity, queue layout, and the buffer geometry a FUSE message is
// framed into.

/// Virtio device ID for a shared-filesystem device.
pub const VIRTIO_ID_FS: u16 = 26;

/// Virtqueue carrying FORGET and INTERRUPT messages, which must not queue
/// behind ordinary requests.
pub const HIPRIO_QUEUE: u16 = 0;
/// First ordinary request virtqueue. The device may offer more; one is enough
/// to serve a mount, and a second would need its own staging buffers to be
/// worth having.
pub const REQUEST_QUEUE: u16 = 1;

/// Byte offset of the mount tag in the device configuration.
pub const CFG_OFF_TAG: u64 = 0;
/// Width of the tag field. It is NOT NUL-terminated when it is full, so the
/// field length is authoritative and a NUL is only an early end.
pub const CFG_TAG_LEN: usize = 36;
/// Byte offset of the request-queue count.
pub const CFG_OFF_NUM_REQUEST_QUEUES: u64 = CFG_OFF_TAG + CFG_TAG_LEN as u64;

/// Driver-model identity for virtio-fs child binding.
pub const DRIVER_ID: virtio::VirtioChildDriverId =
    virtio::VirtioChildDriverId::new("virtio-fs", VIRTIO_ID_FS);

/// Buddy order of each DMA staging buffer: 2^5 pages.
pub(crate) const BUFFER_ORDER: pmm::Order = pmm::Order(5);
/// Bytes in one staging buffer, and therefore the largest FUSE message this
/// transport can carry in either direction.
pub(crate) const BUFFER_BYTES: usize = (1usize << BUFFER_ORDER.0) * hal::PAGE_SIZE_BYTES as usize;

/// Spins to wait for the device to complete one request. Bounded so a wedged
/// device fails the operation instead of hanging the caller with no diagnosis.
pub(crate) const COMPLETION_POLL_BUDGET: u32 = 20_000_000;

const WANTED_FEATURES: u64 = virtio::VIRTIO_F_VERSION_1;

/// # C: O(1)
pub const fn wanted_features() -> u64 { WANTED_FEATURES }

/// Both queues plus the device configuration the tag lives in. The hiprio
/// queue is REQUIRED, not optional: without it a FORGET queues behind ordinary
/// requests and a backlog of them starves the mount. # C: O(1)
pub const fn transport_profile() -> virtio::VirtioTransportProfile {
    virtio::VirtioTransportProfile::vsock(wanted_features(), None)
}
