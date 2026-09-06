//! Raw bitmap, pattern-brush and display-DC ingress; canonical owner creates the objects.
pub(crate) const CREATE_BITMAP: u64 = 0x10a7;
pub(crate) const CREATE_PATTERN_BRUSH: u64 = 0x10b9;
pub(crate) const OPEN_DC_W: u64 = 0x1246;

/// A non-display device context needs a printer or metafile driver to supply
/// its device functions; without one the call has no driver and answers NULL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Operation {
    CreateBitmap { width: i32, height: i32, planes: u32, bpp: u32, bits: u64 },
    CreatePatternBrush { bitmap: u32 },
    OpenDisplayDc,
    NoDriverDc,
}

/// Windows scalars are 32 bits wide; the register halves above them belong to
/// the caller and are never read. # C: O(1)
pub(crate) fn decode(ordinal: u64, args: &[u64]) -> Option<Operation> {
    Some(match ordinal {
        CREATE_BITMAP if args.len() >= 5 => Operation::CreateBitmap { width: args[0] as u32 as i32, height: args[1] as u32 as i32,
            planes: args[2] as u32, bpp: args[3] as u32, bits: args[4] },
        CREATE_PATTERN_BRUSH if args.len() >= 3 => Operation::CreatePatternBrush { bitmap: args[0] as u32 },
        OPEN_DC_W if args.len() >= 5 => if args[4] as u32 != 0 { Operation::OpenDisplayDc } else { Operation::NoDriverDc },
        _ => return None,
    })
}

/// Bytes the caller supplies for one bitmap: rows at the 16-bit-aligned stride,
/// bounded by the same storage budget the owner enforces. Returns none when the
/// request is inadmissible or carries no bits. # C: O(1)
pub(crate) fn caller_bits_len(width: i32, height: i32, planes: u32, bpp: u32, bits: u64) -> Option<usize> {
    if bits == 0 || planes != 1 { return None; }
    let (width, height) = (width.checked_abs()?, height.checked_abs()?);
    let bpp = ipc::win32_gdi::normalize_bpp(bpp)?;
    let stride = ipc::win32_gdi::bitmap_stride(width, bpp)?;
    let len = i64::from(stride).checked_mul(i64::from(height))?;
    if len <= 0 || len > ipc::win32_gdi::MAX_BITMAP_BYTES { return None; }
    Some(len as usize)
}

#[cfg(target_os = "oxide-kernel")]
#[path = "bitmap_raw/kernel.rs"]
pub(crate) mod kernel;

#[cfg(test)]
#[path = "tests/bitmap_raw.rs"]
mod tests;
