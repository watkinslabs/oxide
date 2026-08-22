// User-memory access + layout decisions for the `sys_ioctl` shim.
//
// Module manifest:
//   `copy`   — every read/write of a caller address the ioctl stage performs.
//   `layout` — the ABI offsets and payload-size bounds those copies use.
//
// Ungated on purpose: `016_ioctl` and all of its children are
// `#[cfg(target_os = "oxide-kernel")]`, so a test written beside them compiles
// to nothing and reports ok (`53`). The decisions live here where a hosted
// `cargo test` can fail on them.

mod copy;
mod layout;

// The consumers (`016_ioctl` and its children) are kernel-gated, so a hosted
// build re-exports these without a user.
#[cfg_attr(not(target_os = "oxide-kernel"), allow(unused_imports))]
pub(crate) use copy::{EFAULT, get_bytes, get_into, get_i32, get_u8, get_u16, get_u32,
                      put_bytes, put_i32, put_i64, put_u8, put_u16, put_u32, put_u64};
#[cfg_attr(not(target_os = "oxide-kernel"), allow(unused_imports))]
pub(crate) use layout::{DEDUPE_MAX_LEN, FIEMAP_EXTENT_BYTES, FONT_GLYPH_STRIDE, TIOCL_PARAM,
                        TIOCL_PARAM32, TIOCL_SUBCODE, UNIMAP_PAIR_BYTES, dedupe_payload_bytes,
                        fiemap_extent_span, font_get_fits, font_glyph_bytes, tiocl_sel_field,
                        unimap_span};

#[cfg(test)]
mod tests;
