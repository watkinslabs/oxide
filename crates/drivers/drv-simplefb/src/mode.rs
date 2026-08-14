use drm::{DrmModeModeinfo, DRM_MODE_TYPE_DRIVER, DRM_MODE_TYPE_PREFERRED};

const FIRMWARE_REFRESH_HZ: u32 = 60;

/// Fixed mode reported for a firmware framebuffer that supplied geometry but
/// no timing or display-identification data.  The refresh is the generic
/// firmware-display convention; equal timing edges deliberately assert no
/// blanking or sync interval that the handoff did not provide.
/// # C: O(1)
pub(crate) fn firmware_mode(width: u32, height: u32) -> DrmModeModeinfo {
    let mut mode = drm::mode_from_rect(width, height);
    let (hdisplay, vdisplay) = (width as u16, height as u16);
    mode.clock = ((u64::from(width) * u64::from(height) * u64::from(FIRMWARE_REFRESH_HZ)) / 1_000) as u32;
    mode.hdisplay = hdisplay;
    mode.hsync_start = hdisplay;
    mode.hsync_end = hdisplay;
    mode.htotal = hdisplay;
    mode.vdisplay = vdisplay;
    mode.vsync_start = vdisplay;
    mode.vsync_end = vdisplay;
    mode.vtotal = vdisplay;
    mode.vrefresh = FIRMWARE_REFRESH_HZ;
    mode.flags = 0;
    mode.ty = DRM_MODE_TYPE_DRIVER | DRM_MODE_TYPE_PREFERRED;
    mode
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firmware_geometry_does_not_invent_display_timing() {
        let mode = firmware_mode(1920, 1080);
        assert_eq!(mode.clock, 124_416);
        assert_eq!((mode.hdisplay, mode.hsync_start, mode.hsync_end, mode.htotal), (1920, 1920, 1920, 1920));
        assert_eq!((mode.vdisplay, mode.vsync_start, mode.vsync_end, mode.vtotal), (1080, 1080, 1080, 1080));
        assert_eq!(mode.vrefresh, FIRMWARE_REFRESH_HZ);
        assert_eq!(mode.flags, 0);
        assert_eq!(mode.ty, DRM_MODE_TYPE_DRIVER | DRM_MODE_TYPE_PREFERRED);
        assert_eq!(&mode.name[..10], b"1920x1080\0");
    }
}
