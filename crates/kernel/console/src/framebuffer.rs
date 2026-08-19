use tty::pty::Winsize;

/// Translate committed framebuffer geometry into the VT winsize ABI.
///
/// The VT exposes text cells plus scanline height. The horizontal pixel field
/// stays zero, which preserves the VT ioctl contract instead of inventing a
/// second pixel-width source beside fbcon's authoritative text grid.
/// # C: O(1)
pub(crate) const fn winsize(rows: u16, cols: u16, ypixel: u16) -> Winsize {
    Winsize { rows, cols, xpixel: 0, ypixel }
}

#[cfg(test)]
mod tests {
    use super::winsize;

    #[test]
    fn native_framebuffer_geometry_replaces_the_early_winsize() {
        let firmware = winsize(30, 80, 480);
        let native = winsize(50, 160, 800);
        assert_ne!(native, firmware, "the native mode must replace the firmware report");
        assert_eq!(native.rows, 50);
        assert_eq!(native.cols, 160);
        assert_eq!(native.xpixel, 0);
        assert_eq!(native.ypixel, 800);
    }
}
