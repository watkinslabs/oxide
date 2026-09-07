//! Bitmap, DIB, blit, pixel and palette ingress; the canonical owner performs
//! every raster operation. The typed shape lives in the crate-root contract
//! module the admission table also consults.
pub(crate) use crate::nt_gdi_bitmap_shape::{Operation, Rect, decode};

#[cfg(target_os = "oxide-kernel")]
#[path = "gdi_bitmap_raw/kernel.rs"]
pub(crate) mod kernel;
