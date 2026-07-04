// virtio-blk install/remove glue, split out of `virtio_drv` to keep that file
// under the 1000-line cap. Device-specific config parsing belongs to the
// virtio-blk child driver; pci-boot only passes transport-owned resources.

/// Hand typed queue-0 resources to the virtio-blk engine, which reads its
/// device config and serial (GET_ID), builds a
/// `BlockDevice`, and registers it under a unique name.
/// # C: O(1) + registry O(N_disks)
pub(super) fn register_blk(
    bus: u8, device: u8, function: u8,
    resources: virtio::VirtioResources,
    drv_features: u64,
) -> u32 {
    drv_virtio_blk::modern::init_blk(drv_virtio_blk::modern::BlkInit {
        bus, device, function,
        resources,
        drv_features,
    })
}

/// Remove the virtio-blk device for this PCI BDF from the block layer.
/// # C: O(N_virtio_blk + N_disks + N_devices)
pub(super) fn remove_blk(bus: u8, device: u8, function: u8) -> bool {
    drv_virtio_blk::modern::remove_blk(bus, device, function)
}

/// Quiesce the virtio-blk device for reboot/poweroff without unregistering
/// userspace-visible publication.
/// # C: O(N_virtio_blk + shutdown)
pub(super) fn shutdown_blk(bus: u8, device: u8, function: u8) -> bool {
    drv_virtio_blk::modern::shutdown_blk(bus, device, function)
}
