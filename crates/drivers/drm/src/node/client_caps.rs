use syscall::errno::Errno;
use vfs::File;

use super::auth::valid_user_range;

/// Handle `DRM_IOCTL_SET_CLIENT_CAP`. Capability state is per open DRM file,
/// matching Linux's `drm_file::universal_planes` / `atomic` state.
pub(super) fn set_client_cap(file: &File, arg: u64) -> i64 {
    if !valid_user_range(arg, 16) {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: arg..arg+16 was validated above and is the fixed UAPI layout.
    let capability = unsafe { core::ptr::read_volatile(arg as *const u64) };
    // SAFETY: same validated UAPI structure, value is the second u64.
    let value = unsafe { core::ptr::read_volatile((arg + 8) as *const u64) };
    if value > 1 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let bit = match capability {
        crate::DRM_CLIENT_CAP_UNIVERSAL_PLANES | crate::DRM_CLIENT_CAP_ATOMIC
        | crate::DRM_CLIENT_CAP_CURSOR_PLANE_HOTSPOT => 1u64 << capability,
        // Atomic state is now parsed, validated, testable, and committed through
        // the one canonical scanout owner. Other optional capabilities still
        // need their independent hardware semantics before they are advertised.
        crate::DRM_CLIENT_CAP_STEREO_3D
        | crate::DRM_CLIENT_CAP_ASPECT_RATIO
        | crate::DRM_CLIENT_CAP_WRITEBACK_CONNECTORS => {
            #[cfg(feature = "debug-boot")]
            {
                klog::write_raw(b"[DRMCAP reject cap=");
                klog::write_dec_u64(capability);
                klog::write_raw(b" val=");
                klog::write_dec_u64(value);
                klog::write_raw(b"]\n");
            }
            return -(Errno::Eopnotsupp.as_i32() as i64);
        }
        _ => return -(Errno::Einval.as_i32() as i64),
    };
    let mut state = file.private_data();
    if value != 0 { state |= bit; } else { state &= !bit; }
    file.set_private_data(state);
    #[cfg(feature = "debug-boot")]
    {
        klog::write_raw(b"[DRMCAP accept cap=");
        klog::write_dec_u64(capability);
        klog::write_raw(b" val=");
        klog::write_dec_u64(value);
        klog::write_raw(b"]\n");
    }
    0
}
