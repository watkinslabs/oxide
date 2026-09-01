//! Native userspace gdi32 façade over the tagged NT GDI ABI.

mod client;
mod raster;
pub use client::{Gdi, GdiError, Font, Rect, TextExtent, TextMetrics};
pub use raster::{RasterError, RasterFont, RasterSurface, TextOutputError, ETO_CLIPPED, ETO_OPAQUE};

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
        assert_eq!(syscall::nt::NtService::PresentGdiSurface.entry(), 0x4e54_0000_0000_0211);
        assert_eq!(syscall::nt::NtService::PresentGdiWindow.entry(), 0x4e54_0000_0000_0212);
    }
}
