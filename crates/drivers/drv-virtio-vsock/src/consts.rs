/// Virtio device ID for vsock transports.
pub const VIRTIO_ID_VSOCK: u16 = 19;

/// Driver-model identity for virtio-vsock child binding.
pub const DRIVER_ID: virtio::VirtioChildDriverId =
    virtio::VirtioChildDriverId::new("virtio-vsock", VIRTIO_ID_VSOCK);

/// Number of RX buffers pre-posted on q0.
pub const RX_RING_BUFS: usize = 8;
pub(crate) const FRAME_BYTES: usize = hal::PAGE_SIZE_BYTES as usize;

pub(crate) const VSOCK_CFG_OFF_GUEST_CID: u64 = 0;
pub(crate) const TX_POLL_BUDGET: u32 = 2_000_000;
const WANTED_FEATURES: u64 = virtio::VIRTIO_F_VERSION_1;

/// Virtio-vsock record transport capability. Kept separate from
/// [`WANTED_FEATURES`]: it must only be requested once the kernel's
/// `SOCK_SEQPACKET` owner implements complete record RX/TX semantics.
pub const VIRTIO_VSOCK_F_SEQPACKET: u32 = net::vsock::VIRTIO_VSOCK_F_SEQPACKET;

pub const fn wanted_features() -> u64 {
    WANTED_FEATURES
}

pub const fn transport_profile() -> virtio::VirtioTransportProfile {
    virtio::VirtioTransportProfile::vsock(wanted_features(), Some(crate::raise_rx))
}
