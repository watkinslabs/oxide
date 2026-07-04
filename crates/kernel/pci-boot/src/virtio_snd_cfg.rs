// virtio-snd install glue, split out of `virtio_drv` to keep that file under
// the 1000-line cap (docs/08§7). Device-specific config parsing belongs to the
// virtio-snd child driver; pci-boot only passes transport-owned resources.

/// Install the virtio-snd CONTROLQ engine by handing the transport-owned
/// queue resources to drv-virtio-snd. Returns the probe result (stream split)
/// for the boot line. # C: O(streams)
pub(super) fn install_snd(
    device_key: u32,
    resources: virtio::VirtioResources,
) -> Option<drv_virtio_snd::SndProbe> {
    drv_virtio_snd::install(drv_virtio_snd::SndInstall {
        device_key,
        resources,
    })
}
