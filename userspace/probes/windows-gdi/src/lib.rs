//! Native userspace gdi32 façade over the tagged NT GDI ABI.

mod client;
mod damage;
mod raster;
pub use client::{Gdi, GdiError, Font, Rect, TextExtent, TextMetrics};
pub use damage::{DamageError, DamageRegion};
pub use raster::{RasterError, RasterFont, RasterSurface, FontMeasurement, TextOutputError, ETO_CLIPPED, ETO_OPAQUE};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_gdi_records_have_fixed_64_bit_layouts() {
        assert_eq!(std::mem::size_of::<Font>(), 16);
        assert_eq!(std::mem::size_of::<TextMetrics>(), 24);
        assert_eq!(std::mem::size_of::<TextExtent>(), 8);
        assert_eq!(std::mem::size_of::<Rect>(), 16);
    }

    #[test]
    fn selectors_are_stable_tagged_entries() {
        assert_eq!(syscall::nt::NtService::CreateCompatibleDc.entry(), 0x4e54_0000_0000_0201);
        assert_eq!(syscall::nt::NtService::GetGdiTextExtent.entry(), 0x4e54_0000_0000_0206);
        assert_eq!(syscall::nt::NtService::FillGdiRect.entry(), 0x4e54_0000_0000_020f);
        assert_eq!(syscall::nt::NtService::BlitGdiSurface.entry(), 0x4e54_0000_0000_0210);
        assert_eq!(syscall::nt::NtService::BitBltGdiSurface.entry(), 0x4e54_0000_0000_0222);
        assert_eq!(syscall::nt::NtService::PresentGdiSurface.entry(), 0x4e54_0000_0000_0211);
        assert_eq!(syscall::nt::NtService::PresentGdiWindow.entry(), 0x4e54_0000_0000_0212);
        assert_eq!(syscall::nt::NtService::PresentGdiWindowRegion.entry(), 0x4e54_0000_0000_0220);
    }

    #[test]
    fn malformed_window_damage_is_rejected_before_entering_the_native_service() {
        let gdi = Gdi::new();
        let result = gdi.present_window_region(0xdead, 0xbeef, Rect { left: 8, top: 4, right: 8, bottom: 10 });
        assert!(matches!(result, Err(GdiError::Host(error)) if error.raw_os_error() == Some(libc::EINVAL)));
        let result = gdi.present_window_region(0xdead, 0xbeef, Rect { left: 8, top: 4, right: 7, bottom: 10 });
        assert!(matches!(result, Err(GdiError::Host(error)) if error.raw_os_error() == Some(libc::EINVAL)));
    }

    #[test]
    fn failed_native_presentation_does_not_consume_pending_damage() {
        let gdi = Gdi::new();
        let mut damage = DamageRegion::from_rect(Rect { left: 1, top: 2, right: 7, bottom: 9 }).unwrap();
        assert!(gdi.present_window_damage(0xdead, 0xbeef, &mut damage).is_err());
        assert_eq!(damage.get(), Some(Rect { left: 1, top: 2, right: 7, bottom: 9 }));
    }
}
