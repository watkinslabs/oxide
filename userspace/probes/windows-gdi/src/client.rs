use std::io;
use syscall::nt::{NtGdiFont, NtGdiTextExtent, NtGdiTextMetrics, NtService};

const STATUS_FAILURE_MASK: u64 = 0x8000_0000;

#[derive(Debug)]
pub enum GdiError { Status(u64), Host(io::Error) }

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Font { pub height: i32, pub width: i32, pub weight: i32, pub italic: u32 }

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TextMetrics { pub height: i32, pub ascent: i32, pub descent: i32, pub average_width: i32, pub max_width: i32, pub character_width: i32 }

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TextExtent { pub width: i32, pub height: i32 }

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Rect { pub left: i32, pub top: i32, pub right: i32, pub bottom: i32 }

pub struct Gdi;

impl Gdi {
    /// Construct a stateless façade over the current NT process. # C: O(1)
    pub const fn new() -> Self { Self }

    /// Create a memory device context. # C: O(1) plus kernel service
    pub fn create_compatible_dc(&self, width: i32, height: i32) -> Result<u64, GdiError> {
        invoke(NtService::CreateCompatibleDc, [width as u64, height as u64, 0, 0, 0, 0])
    }

    /// Delete a GDI device context or font. # C: O(N_objects) plus kernel service
    pub fn delete_object(&self, handle: u64) -> Result<(), GdiError> {
        invoke(NtService::DeleteGdiObject, [handle, 0, 0, 0, 0, 0]).map(|_| ())
    }

    /// Create one logical font from its fixed ABI description. # C: O(1) plus usercopy
    pub fn create_font_indirect(&self, font: &Font) -> Result<u64, GdiError> {
        let native = NtGdiFont { height: font.height, width: font.width, weight: font.weight, italic: font.italic };
        invoke(NtService::CreateFontIndirect, [(&native as *const NtGdiFont) as u64, 0, 0, 0, 0, 0])
    }

    /// Select one font into one device context and return the previous handle. # C: O(N_objects) plus kernel service
    pub fn select_font(&self, dc: u64, font: u64) -> Result<u64, GdiError> {
        invoke(NtService::SelectGdiFont, [dc, font, 0, 0, 0, 0])
    }

    /// Read the selected font's text metrics. # C: O(N_objects) plus usercopy
    pub fn get_text_metrics(&self, dc: u64) -> Result<TextMetrics, GdiError> {
        let mut native = NtGdiTextMetrics { height: 0, ascent: 0, descent: 0, average_width: 0, max_width: 0, character_width: 0 };
        invoke(NtService::GetGdiTextMetrics, [dc, (&mut native as *mut NtGdiTextMetrics) as u64, 0, 0, 0, 0])?;
        Ok(TextMetrics { height: native.height, ascent: native.ascent, descent: native.descent, average_width: native.average_width, max_width: native.max_width, character_width: native.character_width })
    }

    /// Measure a UTF-16 string without taking ownership of its buffer. # C: O(N_text) plus usercopy
    pub fn get_text_extent(&self, dc: u64, text: &[u16]) -> Result<TextExtent, GdiError> {
        let mut native = NtGdiTextExtent { width: 0, height: 0 };
        invoke(NtService::GetGdiTextExtent, [dc, text.as_ptr() as u64, text.len() as u64, (&mut native as *mut NtGdiTextExtent) as u64, 0, 0])?;
        Ok(TextExtent { width: native.width, height: native.height })
    }

    /// Fill a clipped device-context rectangle with one XRGB color. # C: O(width*height) plus kernel service
    pub fn fill_rect(&self, dc: u64, rect: Rect, color: u32) -> Result<(), GdiError> {
        invoke(NtService::FillGdiRect, [dc, rect.left as u64, rect.top as u64, rect.right as u64, rect.bottom as u64, color as u64]).map(|_| ())
    }

    /// Upload a row-major XRGB raster into a device context. # C: O(width*height) plus kernel service
    pub fn blit_surface(&self, dc: u64, x: i32, y: i32, width: u32, height: u32, stride: u32, pixels: &[u32]) -> Result<(), GdiError> {
        let Some(words) = (height as usize).checked_mul(stride as usize) else { return Err(GdiError::Host(io::Error::from_raw_os_error(libc::EINVAL))); };
        if width == 0 || height == 0 || stride < width || pixels.len() < words { return Err(GdiError::Host(io::Error::from_raw_os_error(libc::EINVAL))); }
        let packed = (x as u64 & 0xffff_ffff) | ((y as u64 & 0xffff_ffff) << 32);
        invoke(NtService::BlitGdiSurface, [dc, pixels.as_ptr() as u64, width as u64, height as u64, stride as u64, packed]).map(|_| ())
    }

    /// Copy one source DC into a destination DC using the supported SRCCOPY operation. # C: O(width*height) plus kernel service
    pub fn bitblt(&self, dst: u64, dst_x: i32, dst_y: i32, src: u64, src_x: i32, src_y: i32, width: i32, height: i32) -> Result<(), GdiError> {
        let dst_origin = (dst_x as u64 & 0xffff_ffff) | ((dst_y as u64 & 0xffff_ffff) << 32);
        let src_origin = (src_x as u64 & 0xffff_ffff) | ((src_y as u64 & 0xffff_ffff) << 32);
        invoke(NtService::BitBltGdiSurface, [dst, src, dst_origin, src_origin, width as u64, height as u64]).map(|_| ())
    }

    /// Submit one userspace-rasterized text tile to its native device context. # C: O(width*height) plus kernel service
    pub fn draw_raster(&self, dc: u64, x: i32, y: i32, surface: &crate::RasterSurface) -> Result<(), GdiError> {
        self.blit_surface(dc, x, y, surface.width, surface.height, surface.width, &surface.pixels)
    }

    /// Present a device context at screen coordinates through the native display owner. # C: O(width*height) plus kernel service
    pub fn present(&self, dc: u64, x: i32, y: i32) -> Result<(), GdiError> {
        invoke(NtService::PresentGdiSurface, [dc, x as u64, y as u64, 0, 0, 0]).map(|_| ())
    }

    /// Present a visible HWND's selected native surface at its canonical window rectangle. # C: O(width*height) plus kernel service
    pub fn present_window(&self, hwnd: u64, dc: u64) -> Result<(), GdiError> {
        invoke(NtService::PresentGdiWindow, [hwnd, dc, 0, 0, 0, 0]).map(|_| ())
    }

    /// Present one dirty client rectangle at the window's canonical screen position. # C: O(region_pixels) plus kernel service
    pub fn present_window_region(&self, hwnd: u64, dc: u64, rect: Rect) -> Result<(), GdiError> {
        let region = crate::DamageRegion::from_rect(rect).map_err(|_| GdiError::Host(io::Error::from_raw_os_error(libc::EINVAL)))?;
        let rect = region.get().unwrap();
        invoke(NtService::PresentGdiWindowRegion, [hwnd, dc, rect.left as u64, rect.top as u64, rect.right as u64, rect.bottom as u64]).map(|_| ())
    }

    /// Present and consume one coalesced client damage region. # C: O(region_pixels) plus kernel service
    pub fn present_window_damage(&self, hwnd: u64, dc: u64, damage: &mut crate::DamageRegion) -> Result<(), GdiError> {
        let Some(rect) = damage.get() else { return Ok(()); };
        self.present_window_region(hwnd, dc, rect)?;
        let _ = damage.take();
        Ok(())
    }

    /// Submit only the intersection of a raster tile and an `ETO_CLIPPED` rectangle. # C: O(width*height) plus kernel service
    pub fn draw_raster_clipped(&self, dc: u64, x: i32, y: i32, surface: &crate::RasterSurface, clip: Rect) -> Result<(), GdiError> {
        let left = clip.left.max(x).min(x.saturating_add(surface.width as i32));
        let top = clip.top.max(y).min(y.saturating_add(surface.height as i32));
        let right = clip.right.max(left).min(x.saturating_add(surface.width as i32));
        let bottom = clip.bottom.max(top).min(y.saturating_add(surface.height as i32));
        if right <= left || bottom <= top { return Ok(()); }
        let width = (right - left) as usize;
        let height = (bottom - top) as usize;
        let source_x = (left - x) as usize;
        let source_y = (top - y) as usize;
        let mut pixels = Vec::with_capacity(width * height);
        for row in 0..height { pixels.extend_from_slice(&surface.pixels[(source_y + row) * surface.width as usize + source_x..(source_y + row) * surface.width as usize + source_x + width]); }
        self.blit_surface(dc, left, top, width as u32, height as u32, width as u32, &pixels)
    }
}

fn invoke(service: NtService, args: [u64; 6]) -> Result<u64, GdiError> {
    // SAFETY: the tagged NT selector and six register-sized arguments are the stable userspace ABI; pointers remain valid for this synchronous call.
    let result = unsafe { libc::syscall(service.entry() as libc::c_long, args[0], args[1], args[2], args[3], args[4], args[5]) };
    if result == -1 { return Err(GdiError::Host(io::Error::last_os_error())); }
    let result = result as u64;
    if result & STATUS_FAILURE_MASK != 0 { Err(GdiError::Status(result)) } else { Ok(result) }
}
