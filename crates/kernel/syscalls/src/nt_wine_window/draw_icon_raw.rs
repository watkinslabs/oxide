//! Icon and cursor drawing: the passes one request performs, the extent each
//! pass covers and the raster code each pass uses.

/// `NtUserDrawIconEx`.
pub(crate) const DRAW_ICON_EX: u64 = 0x139a;

/// Draw the frame's mask.
pub(crate) const DI_MASK: u32 = 0x0001;
/// Draw the frame's image.
pub(crate) const DI_IMAGE: u32 = 0x0002;
/// Size an omitted extent from the system icon metric rather than the frame.
pub(crate) const DI_DEFAULTSIZE: u32 = 0x0008;
/// System icon extents, which `DI_DEFAULTSIZE` selects.
pub(crate) const SM_CXICON: i32 = 11;
pub(crate) const SM_CYICON: i32 = 12;

/// Which bitmap the image pass reads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ImageSource {
    /// The frame's colour bitmap, read from its origin.
    Color,
    /// A frame with no colour bitmap carries its image in the lower half of
    /// the mask, one frame height below the mask's own origin.
    MaskLowerHalf,
}

/// The passes one draw request performs, in order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IconPlan {
    /// The frame carries per-pixel alpha and the request wants the image, so
    /// one blend covers the whole draw. The mask and image passes stay in the
    /// plan because a blend that cannot run leaves them to do the work.
    pub(crate) alpha: bool,
    /// Raster code of the mask pass, absent when the request omits `DI_MASK`.
    pub(crate) mask: Option<u32>,
    /// Source and raster code of the image pass, absent without `DI_IMAGE`.
    pub(crate) image: Option<(ImageSource, u32)>,
}

/// A pass that lands on an untouched destination copies; a pass that lands on
/// a mask already drawn combines with it instead — the mask pass ANDs the
/// image away, the image pass inverts the mask back out.
/// # C: O(1)
pub(crate) fn icon_plan(flags: u32, has_alpha: bool, has_color: bool) -> IconPlan {
    let (want_mask, want_image) = (flags & DI_MASK != 0, flags & DI_IMAGE != 0);
    let mask = want_mask.then(|| if want_image { ipc::win32_gdi::SRCAND } else { ipc::win32_gdi::SRCCOPY });
    let image = want_image.then(|| {
        let code = if want_mask { ipc::win32_gdi::SRCINVERT } else { ipc::win32_gdi::SRCCOPY };
        (if has_color { ImageSource::Color } else { ImageSource::MaskLowerHalf }, code)
    });
    IconPlan { alpha: has_alpha && want_image, mask, image }
}

/// An omitted extent takes the system icon metric when the request asks for a
/// default size and the frame's own extent otherwise. # C: O(1)
pub(crate) const fn draw_extent(requested: i32, flags: u32, frame: i32, system: i32) -> i32 {
    if requested != 0 { return requested; }
    if flags & DI_DEFAULTSIZE != 0 { system } else { frame }
}

/// A brush argument names an offscreen bitmap the icon is drawn onto over a
/// brush fill, then copied to the caller's device context; the icon itself
/// then draws at the offscreen origin rather than the requested point.
/// # C: O(1)
pub(crate) const fn offscreen_origin(offscreen: bool, x: i32, y: i32) -> (i32, i32) {
    if offscreen { (0, 0) } else { (x, y) }
}

/// A handle names a brush when its type tag is the brush tag. # C: O(1)
pub(crate) const fn is_brush(handle: u64) -> bool {
    handle != 0 && (handle as u32) & !ipc::win32_gdi::SLOT_MASK == ipc::win32_gdi::TYPE_BRUSH
        && handle <= u32::MAX as u64
}

/// The brush fill covers a square of the destination width, which is the
/// extent the reference fills before the icon is drawn over it. # C: O(1)
pub(crate) const fn brush_fill_extent(width: i32) -> (i32, i32) { (width, width) }

/// Text and background colours every icon pass runs under, so a monochrome
/// mask expands to black-on-white regardless of the caller's own colours.
/// # C: O(1)
pub(crate) fn icon_colors(colors: ipc::win32_gdi::SharedDcColors) -> ipc::win32_gdi::SharedDcColors {
    ipc::win32_gdi::SharedDcColors { text: ICON_FOREGROUND, background: ICON_BACKGROUND, ..colors }
}

/// Black foreground and white background, as canonical surface words.
const ICON_FOREGROUND: u32 = 0x0000_0000;
const ICON_BACKGROUND: u32 = 0x00ff_ffff;
/// A blend that scales the source by nothing but its own alpha channel.
const OPAQUE_ALPHA: u8 = 255;

/// The composite one alpha-carrying frame draws with: source over the
/// destination, at full constant alpha, reading the frame's own premultiplied
/// alpha channel. # C: O(1)
pub(crate) fn icon_blend() -> ipc::win32_gdi::BlendFunction {
    ipc::win32_gdi::BlendFunction { op: ipc::win32_gdi::AC_SRC_OVER, flags: 0,
        source_constant_alpha: OPAQUE_ALPHA, alpha_format: ipc::win32_gdi::AC_SRC_ALPHA }
}

#[cfg(test)]
#[path = "tests/draw_icon_raw.rs"]
mod tests;
