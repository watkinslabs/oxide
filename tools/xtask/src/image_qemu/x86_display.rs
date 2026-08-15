use super::HardwareProfile;

/// Firmware scanout is the normal QEMU boot console. The optional virtio-GPU
/// topology has no firmware fallback while its native modeset is pending.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DisplayPlan {
    pub(super) legacy_vga: &'static str,
    pub(super) primary_virtio_gpu: bool,
}

pub(super) fn display_plan(profile: HardwareProfile, virtio_gpu_requested: bool, force_firmware_fb: bool) -> DisplayPlan {
    if profile == HardwareProfile::NativePci || force_firmware_fb || !virtio_gpu_requested {
        return DisplayPlan { legacy_vga: "std", primary_virtio_gpu: false };
    }
    DisplayPlan { legacy_vga: "none", primary_virtio_gpu: true }
}
