use crate::{
    DRM_MODE_ATOMIC_ALLOW_MODESET, DRM_MODE_ATOMIC_NONBLOCK, DRM_MODE_ATOMIC_TEST_ONLY,
};

/// `struct drm_version` Linux UAPI (88 bytes on 64-bit).
#[repr(C)]
pub(super) struct DrmVersion {
    pub(super) version_major:      i32,
    pub(super) version_minor:      i32,
    pub(super) version_patchlevel: i32,
    pub(super) name_len:           u64,
    pub(super) name:               u64, // user pointer
    pub(super) date_len:           u64,
    pub(super) date:               u64, // user pointer
    pub(super) desc_len:           u64,
    pub(super) desc:               u64, // user pointer
}

/// `struct drm_unique` Linux UAPI (16 bytes on 64-bit).
#[repr(C)]
pub(super) struct DrmUnique {
    pub(super) unique_len: u64,
    pub(super) unique:     u64, // user pointer
}

/// `struct drm_set_version` Linux UAPI (16 bytes).
#[repr(C)]
pub(super) struct DrmSetVersion {
    pub(super) drm_di_major: i32,
    pub(super) drm_di_minor: i32,
    pub(super) drm_dd_major: i32,
    pub(super) drm_dd_minor: i32,
}

/// `struct drm_mode_atomic` Linux UAPI (56 bytes on 64-bit).
#[repr(C)]
pub(super) struct DrmModeAtomic {
    pub(super) flags:           u32,
    pub(super) count_objs:      u32,
    pub(super) objs_ptr:        u64,
    pub(super) count_props_ptr: u64,
    pub(super) props_ptr:       u64,
    pub(super) prop_values_ptr: u64,
    pub(super) reserved:        u64,
}

pub(super) const DRM_IF_MAJOR: i32 = 1;
pub(super) const DRM_IF_MINOR: i32 = 4;
pub(super) const DRM_MODE_ATOMIC_SUPPORTED_FLAGS: u32 =
    DRM_MODE_ATOMIC_TEST_ONLY | DRM_MODE_ATOMIC_NONBLOCK | DRM_MODE_ATOMIC_ALLOW_MODESET;

// Fallback strings used when no DrmDriver is registered (e.g.
// QEMU launched without -device virtio-gpu-pci).
pub(super) const FALLBACK_NAME: &str = "oxide";
pub(super) const FALLBACK_DATE: &str = "20260509";
pub(super) const FALLBACK_DESC: &str = "Oxide DRM (no GPU)";
pub(super) const FALLBACK_UNIQUE: &str = "platform:oxide-drm";
