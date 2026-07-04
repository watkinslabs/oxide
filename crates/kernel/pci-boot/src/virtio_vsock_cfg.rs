// virtio-vsock install glue, split out of `virtio_drv` to keep that file under
// the 1000-line cap (docs/08§7). Device-specific config parsing belongs to the
// virtio-vsock child driver; pci-boot only passes transport-owned resources.

/// Install the virtio-vsock ring engine: hand typed q0/q1 resources to
/// drv-virtio-vsock, which reads its guest CID, pre-posts RX buffers, and
/// installs the net::vsock TX hook. Returns true on success. # C: O(RX ring depth)
pub(super) fn install_vsock(
    device_key: u32,
    resources: virtio::VirtioResources,
) -> bool {
    drv_virtio_vsock::install(device_key, resources)
}
