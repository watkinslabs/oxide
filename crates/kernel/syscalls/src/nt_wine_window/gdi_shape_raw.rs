//! Module manifest: win32u path, region-shape and region-clipping ordinals.
//! `ordinals` carries the admitted numbers and argument counts, `decode` the
//! typed request form, `encode` the bounded output images, `kernel` the owner calls.

#[path = "gdi_shape_raw/ordinals.rs"]
pub(crate) mod ordinals;
#[path = "gdi_shape_raw/decode.rs"]
pub(crate) mod decode;
#[path = "gdi_shape_raw/encode.rs"]
pub(crate) mod encode;
#[cfg(target_os = "oxide-kernel")]
#[path = "gdi_shape_raw/kernel.rs"]
pub(crate) mod kernel;

