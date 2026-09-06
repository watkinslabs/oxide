//! Pure GDI object state used by the native NT GUI layer.

use alloc::vec::Vec;
#[path = "win32_gdi/text_state.rs"]
mod text_state;
#[path = "win32_gdi/resize.rs"]
mod resize;
#[path = "win32_gdi/position.rs"]
mod position;
#[path = "win32_gdi/backing.rs"]
mod backing;
pub use backing::PaintBacking;
#[path = "win32_gdi/output.rs"]
mod output;
pub use output::{OutputToken, PendingOutput};
#[path = "win32_gdi/dc_lease.rs"]
mod dc_lease;
pub use dc_lease::{DcLease, DcLeaseRequest, LeaseOwner, dc_lease_flags, DCX_WINDOW, DCX_CACHE, DCX_NORESETATTRS, DCX_CLIPCHILDREN, DCX_CLIPSIBLINGS, DCX_PARENTCLIP, DCX_EXCLUDERGN, DCX_INTERSECTRGN, DCX_USESTYLE};
#[path = "win32_gdi/nonclient.rs"]
mod nonclient;
pub use nonclient::{nonclient_defaults, system_metric_default};
#[path = "win32_gdi/visibility.rs"]
mod visibility;
pub use visibility::rect_visible_in_clip;
#[path = "win32_gdi/blend.rs"]
mod blend;
#[path = "win32_gdi/handles.rs"]
mod handles;
#[path = "win32_gdi/projection.rs"]
mod projection;
#[path = "win32_gdi/clip.rs"]
mod clip;
pub use clip::{CLIP_ERROR, NULL_REGION, SIMPLE_REGION, COMPLEX_REGION};
#[path = "win32_gdi/region.rs"]
mod region;
pub use region::TYPE_REGION;
#[path = "win32_gdi/stock.rs"]
mod stock;
#[path = "win32_gdi/bitmap.rs"]
mod bitmap;
pub use bitmap::{Bitmap, BitmapPattern, MAX_BITMAP_BYTES, TYPE_BITMAP, bitmap_stride, dib_stride, normalize_bpp};
#[path = "win32_gdi/brush.rs"]
mod brush;
#[path = "win32_gdi/system_brush.rs"]
mod system_brush;
#[path = "win32_gdi/scrollbar.rs"]
mod scrollbar;
pub use scrollbar::{ScrollMetrics, ScrollColors, ScrollPart, ScrollDrawOutcome, ScrollLayout, scrollbar_layout};
pub use system_brush::{SystemBrushes, SystemColor};
#[path = "win32_gdi/font.rs"]
mod font;
pub use font::{FontRecord, FontQuery, LOGFONTW_BYTES};
#[cfg(test)]
#[path = "win32_gdi/tests/font_lifetime.rs"]
mod font_lifetime_tests;
pub use stock::{stock_object, stock_by_handle, StockDescription, StockObject, StockFont, StockBrush, StockPen, StockStyle, DEFAULT_DC_FONT_HANDLE};
pub use brush::{Brush, BrushStyle, SharedDcColors, TYPE_BRUSH};
#[path = "win32_gdi/pen.rs"]
mod pen;
pub use pen::{Pen, PenRasterState, TYPE_PEN, DEFAULT_DC_PEN_HANDLE};
pub use handles::{FIRST_DYNAMIC_SLOT, SLOT_LIMIT, SLOT_MASK, TYPE_DC, TYPE_FONT};
pub use text_state::{TextAttribute, TextAttributes, TextState};

pub const MM_TEXT: u32 = 1;
const DEFAULT_HEIGHT: i32 = 16;
const DEFAULT_DESCENT: i32 = 4;
const DEFAULT_WIDTH: i32 = 8;
pub const MENU_CHAR_WIDTH: i32 = DEFAULT_WIDTH;
pub const MENU_CHAR_HEIGHT: i32 = DEFAULT_HEIGHT;
pub const MENU_BAR_HEIGHT: i32 = 19;
const MAX_SURFACE_PIXELS: usize = 16 * 1024 * 1024;
/// Every device-context surface word is one 32-bit XRGB pixel, so that is the
/// colour depth a Win32 client reads back from any device context here.
pub const SURFACE_BITS_PER_PIXEL: u32 = 32;


#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Font { pub height: i32, pub width: i32, pub weight: i32, pub italic: bool }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TextMetrics { pub height: i32, pub ascent: i32, pub descent: i32, pub average_width: i32, pub max_width: i32, pub character_width: i32 }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TextExtent { pub width: i32, pub height: i32 }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Rect { pub left: i32, pub top: i32, pub right: i32, pub bottom: i32 }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum GdiError { NoSuchObject, InvalidDimensions, InvalidText, HandleLimit }

#[derive(Debug, Eq, PartialEq)]
struct DeviceContext { width: i32, height: i32, map_mode: u32, font: Option<u32>, brush: Option<u32>, dc_brush_color: u32, pen: u32, dc_pen_color: u32, text: TextAttributes, clip: Option<Rect>, paint_clip: Option<crate::win32_window::PaintRegion>, pixels: Vec<u32>, lease: Option<DcLease>, pending_output: PendingOutput }

pub struct GdiManager { next: u32, dcs: Vec<(u32, DeviceContext)>, fonts: Vec<(u32, FontRecord)>, brushes: Vec<(u32, Brush)>, bitmaps: Vec<(u32, Bitmap)>, pens: Vec<(u32, Pen)>, system_brushes: SystemBrushes, window_dcs: Vec<(u32, u32)>, regions: Vec<(u32, crate::win32_window::PaintRegion)> }

impl Default for GdiManager { fn default() -> Self { Self::new() } }

impl GdiManager {
    /// Construct an empty process-local GDI object owner. # C: O(1)
    pub fn new() -> Self { Self { next: FIRST_DYNAMIC_SLOT, dcs: Vec::new(), fonts: Vec::new(), brushes: Vec::new(), bitmaps: Vec::new(), pens: Vec::new(), system_brushes: SystemBrushes::default(), window_dcs: Vec::new(), regions: Vec::new() } }

    /// Create a memory device context with bounded positive dimensions. # C: O(1)
    pub fn create_dc(&mut self, width: i32, height: i32) -> Result<u32, GdiError> {
        if width <= 0 || height <= 0 { return Err(GdiError::InvalidDimensions); }
        self.create_storage_dc(width, height)
    }

    /// Return the stable display DC associated with one canonical HWND. # C: O(N_windows)
    pub fn acquire_window_dc(&mut self, hwnd: u32, width: i32, height: i32) -> Result<u32, GdiError> {
        if let Some(dc) = self.window_dcs.iter().find(|(window, _)| *window == hwnd).map(|(_, dc)| *dc) {
            self.resize_dc(dc, width, height)?;
            return Ok(dc);
        }
        self.window_dcs.try_reserve(1).map_err(|_| GdiError::HandleLimit)?;
        let dc = self.create_storage_dc(width, height)?;
        self.window_dcs.push((hwnd, dc));
        Ok(dc)
    }

    /// Release a GetDC lease without destroying its canonical window DC. # C: O(N_windows)
    pub fn release_window_dc(&self, hwnd: u32, dc: u32) -> Result<(), GdiError> {
        if self.window_dcs.iter().any(|(window, candidate)| *window == hwnd && *candidate == dc) { Ok(()) } else { Err(GdiError::NoSuchObject) }
    }

    /// Remove a window association and its DC during HWND destruction. # C: O(N_windows + N_objects)
    pub fn destroy_window_dc(&mut self, hwnd: u32) -> Result<(), GdiError> {
        self.revoke_window_leases(hwnd);
        let Some(index) = self.window_dcs.iter().position(|(window, _)| *window == hwnd) else { return Err(GdiError::NoSuchObject); };
        let (_, dc) = self.window_dcs.remove(index);
        self.delete_object(dc)
    }

    /// Delete a device context or font object. # C: O(N_objects)
    pub fn delete_object(&mut self, handle: u32) -> Result<(), GdiError> {
        if self.is_system_brush(handle) { return Ok(()); }
        if self.stock_description(handle).is_some() { return Ok(()); }
        if self.brushes.iter().any(|(candidate, _)| *candidate == handle) { return self.delete_brush(handle); }
        if self.pens.iter().any(|(candidate, _)| *candidate == handle) { return self.delete_pen(handle); }
        if self.dcs.iter().any(|(candidate, _)| *candidate == handle) { return self.delete_dc_object(handle); }
        if self.fonts.iter().any(|(candidate, _)| *candidate == handle) { return self.delete_font(handle); }
        if self.regions.iter().any(|(candidate, _)| *candidate == handle) { return self.delete_region(handle); }
        if self.bitmaps.iter().any(|(candidate, _)| *candidate == handle) { return self.delete_bitmap(handle); }
        Err(GdiError::NoSuchObject)
    }

    /// Return text metrics for the selected font or the stock font. # C: O(N_objects)
    pub fn text_metrics(&self, dc: u32) -> Result<TextMetrics, GdiError> {
        let font = self.font_for(dc)?;
        let height = metric_height(font);
        let width = metric_width(font, height);
        Ok(TextMetrics { height, ascent: height - DEFAULT_DESCENT, descent: DEFAULT_DESCENT, average_width: width, max_width: width, character_width: width })
    }

    /// Return the stock dialog base units used by the native GUI owner. # C: O(1)
    pub fn dialog_base_units(&self) -> (i32, i32) { (DEFAULT_WIDTH, DEFAULT_HEIGHT) }

    /// Measure UTF-16 code units using the selected logical font. # C: O(N_text)
    pub fn text_extent(&self, dc: u32, count: u32) -> Result<TextExtent, GdiError> {
        if count > i32::MAX as u32 { return Err(GdiError::InvalidText); }
        let font = self.font_for(dc)?;
        let height = metric_height(font);
        let width = metric_width(font, height).checked_mul(count as i32).ok_or(GdiError::InvalidText)?;
        Ok(TextExtent { width, height })
    }

    /// Fill a clipped device-context rectangle with one XRGB color. # C: O(width*height)
    pub fn fill_rect(&mut self, dc: u32, rect: Rect, color: u32) -> Result<(), GdiError> {
        self.raster_fill_rect(dc, rect, color)
    }

    /// Copy a row-major XRGB raster into a clipped device-context surface. # C: O(width*height)
    pub fn blit_pixels(&mut self, dc: u32, x: i32, y: i32, width: i32, height: i32, stride: i32, pixels: &[u32]) -> Result<(), GdiError> {
        self.raster_blit_pixels(dc, x, y, width, height, stride, pixels)
    }

    /// Copy a clipped source rectangle into a destination context without aliasing either context. # C: O(width*height)
    pub fn bitblt(&mut self, dst: u32, dst_x: i32, dst_y: i32, src: u32, src_x: i32, src_y: i32, width: i32, height: i32) -> Result<(), GdiError> {
        self.raster_bitblt(dst, dst_x, dst_y, src, src_x, src_y, width, height)
    }

    /// Read the rendered row-major XRGB surface for one device context. # C: O(1)
    pub fn pixels(&self, dc: u32) -> Option<&[u32]> { self.dc_storage_surface(dc).map(|(_, _, pixels)| pixels) }

    /// Return one DC's dimensions and canonical raster for the display owner. # C: O(N_objects)
    pub fn surface(&self, dc: u32) -> Option<(i32, i32, &[u32])> {
        self.dc_storage_surface(dc)
    }

}

fn metric_height(font: Option<Font>) -> i32 { font.map(|font| font.height.abs().max(1)).unwrap_or(DEFAULT_HEIGHT) }
fn metric_width(font: Option<Font>, height: i32) -> i32 { font.map(|font| font.width.abs().max(1)).unwrap_or((height / 2).max(DEFAULT_WIDTH)) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dc_font_selection_and_metrics_share_one_owner() {
        let mut gdi = GdiManager::new();
        let dc = gdi.create_dc(800, 600).unwrap();
        let font = gdi.create_font(Font { height: 20, width: 10, weight: 400, italic: false }).unwrap();
        assert_eq!(gdi.select_font(dc, font), Ok(DEFAULT_DC_FONT_HANDLE));
        assert_eq!(gdi.text_metrics(dc).unwrap().height, 20);
        assert_eq!(gdi.text_extent(dc, 4), Ok(TextExtent { width: 40, height: 20 }));
    }

    #[test]
    fn deleting_selected_font_preserves_metrics_until_deselection() {
        let mut gdi = GdiManager::new();
        let dc = gdi.create_dc(10, 10).unwrap();
        let font = gdi.create_font(Font { height: 12, width: 0, weight: 400, italic: false }).unwrap();
        gdi.select_font(dc, font).unwrap();
        gdi.delete_object(font).unwrap();
        assert_eq!(gdi.text_metrics(dc).unwrap().height, 12);
        assert_eq!(gdi.select_font(dc, DEFAULT_DC_FONT_HANDLE), Ok(font));
        assert_eq!(gdi.text_metrics(dc).unwrap().height, DEFAULT_HEIGHT);
        assert!(!gdi.contains_object(font));
    }

    #[test]
    fn invalid_dimensions_and_handles_are_rejected() {
        let mut gdi = GdiManager::new();
        assert_eq!(gdi.create_dc(0, 10), Err(GdiError::InvalidDimensions));
        assert_eq!(gdi.delete_object(99), Err(GdiError::NoSuchObject));
    }

    #[test]
    fn fill_rect_clips_to_the_native_surface() {
        let mut gdi = GdiManager::new();
        let dc = gdi.create_dc(4, 3).unwrap();
        gdi.fill_rect(dc, Rect { left: -1, top: 1, right: 3, bottom: 4 }, 0x0011_2233).unwrap();
        let px = gdi.pixels(dc).unwrap();
        assert_eq!(px[0], 0);
        assert_eq!(px[4], 0x0011_2233);
        assert_eq!(px[10], 0x0011_2233);
        assert_eq!(px[11], 0);
    }

    #[test]
    fn blit_pixels_clips_source_raster_without_aliasing_surface_state() {
        let mut gdi = GdiManager::new();
        let dc = gdi.create_dc(3, 2).unwrap();
        let source = [0x11, 0x22, 0x33, 0xaa, 0xbb, 0xcc];
        gdi.blit_pixels(dc, -1, 0, 3, 2, 3, &source).unwrap();
        assert_eq!(gdi.pixels(dc).unwrap(), &[0x22, 0x33, 0, 0xbb, 0xcc, 0]);
    }

    #[test]
    fn bitblt_copies_clipped_pixels_and_handles_overlap_from_one_snapshot() {
        let mut gdi = GdiManager::new();
        let src = gdi.create_dc(3, 2).unwrap();
        let dst = gdi.create_dc(4, 2).unwrap();
        gdi.blit_pixels(src, 0, 0, 3, 2, 3, &[1, 2, 3, 4, 5, 6]).unwrap();
        gdi.bitblt(dst, -1, 0, src, 0, 0, 3, 2).unwrap();
        assert_eq!(gdi.pixels(dst).unwrap(), &[2, 3, 0, 0, 5, 6, 0, 0]);
        gdi.bitblt(dst, 1, 0, dst, 0, 0, 3, 2).unwrap();
        assert_eq!(gdi.pixels(dst).unwrap(), &[2, 2, 3, 0, 5, 5, 6, 0]);
    }

    #[test]
    fn bitblt_rejects_empty_or_unknown_contexts_without_mutation() {
        let mut gdi = GdiManager::new();
        let dc = gdi.create_dc(2, 2).unwrap();
        assert_eq!(gdi.bitblt(dc, 0, 0, dc, 0, 0, 0, 1), Err(GdiError::InvalidDimensions));
        assert_eq!(gdi.bitblt(dc, 0, 0, 99, 0, 0, 1, 1), Err(GdiError::NoSuchObject));
        assert_eq!(gdi.pixels(dc).unwrap(), &[0, 0, 0, 0]);
    }

    #[test]
    fn window_dc_is_stable_and_release_does_not_destroy_surface() {
        let mut gdi = GdiManager::new();
        let first = gdi.acquire_window_dc(7, 20, 10).unwrap();
        gdi.fill_rect(first, Rect { left: 0, top: 0, right: 1, bottom: 1 }, 0x0012_3456).unwrap();
        assert_eq!(gdi.acquire_window_dc(7, 20, 10), Ok(first));
        assert_eq!(gdi.release_window_dc(7, first), Ok(()));
        assert_eq!(gdi.pixels(first).unwrap()[0], 0x0012_3456);
        assert_eq!(gdi.release_window_dc(8, first), Err(GdiError::NoSuchObject));
    }

    #[test]
    fn destroying_window_dc_removes_only_its_association_and_object() {
        let mut gdi = GdiManager::new();
        let window_dc = gdi.acquire_window_dc(7, 20, 10).unwrap();
        let memory_dc = gdi.create_dc(20, 10).unwrap();
        assert_eq!(gdi.destroy_window_dc(7), Ok(()));
        assert!(gdi.pixels(window_dc).is_none());
        assert!(gdi.pixels(memory_dc).is_some());
        assert_eq!(gdi.destroy_window_dc(7), Err(GdiError::NoSuchObject));
    }

    #[test]
    fn subtree_cleanup_can_release_each_window_dc_without_releasing_memory_objects() {
        let mut gdi = GdiManager::new();
        let parent_dc = gdi.acquire_window_dc(7, 20, 10).unwrap();
        let child_dc = gdi.acquire_window_dc(8, 20, 10).unwrap();
        let memory_dc = gdi.create_dc(20, 10).unwrap();
        assert_eq!(gdi.destroy_window_dc(8), Ok(()));
        assert_eq!(gdi.destroy_window_dc(7), Ok(()));
        assert!(gdi.pixels(parent_dc).is_none());
        assert!(gdi.pixels(child_dc).is_none());
        assert!(gdi.pixels(memory_dc).is_some());
    }
}
