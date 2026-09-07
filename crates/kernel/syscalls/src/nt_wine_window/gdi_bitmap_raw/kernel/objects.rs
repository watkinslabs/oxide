//! Object creation, palette entry transfer and bitmap bit transfer.
use alloc::vec::Vec;
use ipc::win32_gdi::{PaletteEntry, Rgb, CLR_INVALID, SYSPAL_ERROR};
use super::super::Operation;

/// One palette entry occupies four bytes: red, green, blue, flags.
const PALETTE_ENTRY_BYTES: usize = 4;
/// A logical palette carries its version and entry count before its entries.
const LOGPALETTE_HEADER_BYTES: usize = 4;
/// Colour table entries in a device-context transfer are four bytes each.
const RGBQUAD_BYTES: usize = 4;
/// Selectors the palette multiplexer names.
const ANIMATE_PALETTE: u32 = 0;
const SET_PALETTE_ENTRIES: u32 = 1;
const GET_PALETTE_ENTRIES: u32 = 2;
const GET_SYSTEM_PALETTE_ENTRIES: u32 = 3;
const GET_DIB_COLOR_TABLE: u32 = 4;
const SET_DIB_COLOR_TABLE: u32 = 5;
/// Entries one transfer may name, bounding the kernel buffer it needs.
const MAX_TRANSFER_ENTRIES: u32 = 4096;
/// This device is direct colour, so it has no palette to report or program.
const DEVICE_HAS_PALETTE: bool = false;

pub(super) fn dispatch(operation: Operation) -> u64 {
    match operation {
        Operation::CreateCompatibleBitmap { dc, width, height } => {
            let Ok(dc) = u32::try_from(dc) else { return 0; };
            let device = super::raster::device();
            crate::nt_gdi::create_compatible_bitmap_for_current(dc, width, height, device.0, device.1).unwrap_or(0) as u64
        }
        Operation::CreateHatchBrush { style, color } =>
            u64::from(crate::nt_gdi::create_hatch_brush_for_current(style, colorref_xrgb(color)).unwrap_or(0)),
        Operation::CreatePalette { logpalette, count } => create_palette(logpalette, count),
        Operation::CreateHalftonePalette => u64::from(crate::nt_gdi::create_halftone_palette_for_current().unwrap_or(0)),
        Operation::SelectBitmap { dc, bitmap } => u64::from(crate::nt_gdi::select_bitmap_for_current(dc, bitmap).unwrap_or(0)),
        Operation::SelectPalette { dc, palette, background } => select_palette(dc, palette, background),
        Operation::RealizePalette { dc } => {
            let Ok(dc) = u32::try_from(dc) else { return 0; };
            u64::from(crate::nt_gdi::with_gdi(|state| state.realize_palette(dc)).unwrap_or(0))
        }
        Operation::UnrealizeObject { handle } => {
            let Ok(handle) = u32::try_from(handle) else { return 0; };
            u64::from(crate::nt_gdi::with_gdi(|state| Ok(state.unrealize_object(handle))).unwrap_or(false))
        }
        Operation::ResizePalette { palette, count } => {
            let Ok(palette) = u32::try_from(palette) else { return 0; };
            u64::from(crate::nt_gdi::with_gdi(|state| Ok(state.resize_palette(palette, count))).unwrap_or(false))
        }
        Operation::DoPalette { handle, start, count, entries, function, .. } => do_palette(handle, start, count, entries, function),
        Operation::GetNearestColor { dc, color } => {
            let Ok(dc) = u32::try_from(dc) else { return u64::from(CLR_INVALID); };
            match crate::nt_gdi::with_gdi(|state| state.nearest_color(dc, color, DEVICE_HAS_PALETTE)) {
                Ok(color) => u64::from(color), Err(_) => u64::from(CLR_INVALID),
            }
        }
        Operation::GetNearestPaletteIndex { palette, color } => {
            let Ok(palette) = u32::try_from(palette) else { return 0; };
            u64::from(crate::nt_gdi::with_gdi(|state| Ok(state.nearest_palette_index(palette, color))).unwrap_or(0))
        }
        Operation::GetSystemPaletteUse => u64::from(crate::nt_gdi::with_gdi(|state| Ok(state.system_palette_use())).unwrap_or(SYSPAL_ERROR)),
        Operation::SetSystemPaletteUse { value } =>
            u64::from(crate::nt_gdi::with_gdi(|state| Ok(state.set_system_palette_use(value, DEVICE_HAS_PALETTE))).unwrap_or(SYSPAL_ERROR)),
        // The device reports no palette size, so there are no mapped colours
        // to remap and nothing to invalidate.
        Operation::UpdateColors { .. } => 0,
        Operation::GetBitmapBits { bitmap, count, bits } => get_bitmap_bits(bitmap, count, bits),
        Operation::SetBitmapBits { bitmap, count, bits } => set_bitmap_bits(bitmap, count, bits),
        Operation::GetBitmapDimension { bitmap, size } => {
            let Ok(bitmap) = u32::try_from(bitmap) else { return 0; };
            let Ok((x, y)) = crate::nt_gdi::with_gdi(|state| state.bitmap_dimension(bitmap)) else { return 0; };
            u64::from(write_size(size, x, y))
        }
        Operation::SetBitmapDimension { bitmap, x, y, previous } => {
            let Ok(bitmap) = u32::try_from(bitmap) else { return 0; };
            let Ok((old_x, old_y)) = crate::nt_gdi::with_gdi(|state| state.set_bitmap_dimension(bitmap, x, y)) else { return 0; };
            if previous == 0 { return 1; }
            u64::from(write_size(previous, old_x, old_y))
        }
        // A brush with no device-independent pattern has no record to report.
        Operation::IcmBrushInfo { .. } => 0,
        // The reference draws no stream and programs no magic colours; the
        // first reports failure and the second success.
        Operation::DrawStream => 0,
        Operation::SetMagicColors => 1,
        _ => 0,
    }
}

fn colorref_xrgb(color: u32) -> u32 { ((color & 0xff) << 16) | (color & 0xff00) | ((color >> 16) & 0xff) }

fn write_size(address: u64, x: i32, y: i32) -> bool {
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&x.to_le_bytes());
    bytes[4..].copy_from_slice(&y.to_le_bytes());
    uaccess::copy_to_user(address, &bytes).is_ok()
}

fn create_palette(address: u64, count: u32) -> u64 {
    if address == 0 || count > MAX_TRANSFER_ENTRIES { return 0; }
    let Ok(version) = uaccess::get_user_u16(address) else { return 0; };
    let Some(entries) = read_entries(address + LOGPALETTE_HEADER_BYTES as u64, count) else { return 0; };
    u64::from(crate::nt_gdi::create_palette_for_current(version, &entries).unwrap_or(0))
}

fn read_entries(address: u64, count: u32) -> Option<Vec<PaletteEntry>> {
    let mut bytes = Vec::new();
    let len = (count as usize).checked_mul(PALETTE_ENTRY_BYTES)?;
    bytes.try_reserve(len).ok()?;
    bytes.resize(len, 0);
    uaccess::copy_from_user(&mut bytes, address).ok()?;
    let mut entries = Vec::new();
    entries.try_reserve_exact(count as usize).ok()?;
    for chunk in bytes.chunks_exact(PALETTE_ENTRY_BYTES) {
        entries.push(PaletteEntry { red: chunk[0], green: chunk[1], blue: chunk[2], flags: chunk[3] });
    }
    Some(entries)
}

fn write_entries(address: u64, entries: &[PaletteEntry]) -> bool {
    let mut bytes = Vec::new();
    if bytes.try_reserve(entries.len() * PALETTE_ENTRY_BYTES).is_err() { return false; }
    for entry in entries { bytes.extend_from_slice(&[entry.red, entry.green, entry.blue, entry.flags]); }
    uaccess::copy_to_user(address, &bytes).is_ok()
}

fn select_palette(dc: u64, palette: u64, background: bool) -> u64 {
    let (Ok(dc), Ok(palette)) = (u32::try_from(dc), u32::try_from(palette)) else { return 0; };
    // Only a foreground selection of a real palette can claim the process
    // primary palette; the stock default palette never does.
    let primary = !background && palette != ipc::win32_gdi::DEFAULT_PALETTE_HANDLE;
    u64::from(crate::nt_gdi::with_gdi(|state| state.select_palette(dc, palette, primary)).unwrap_or(0))
}

fn do_palette(handle: u64, start: u32, count: u32, address: u64, function: u32) -> u64 {
    let Ok(handle) = u32::try_from(handle) else { return 0; };
    if count > MAX_TRANSFER_ENTRIES { return 0; }
    match function {
        GET_PALETTE_ENTRIES => {
            if address == 0 || count == 0 {
                return u64::from(crate::nt_gdi::with_gdi(|state| Ok(state.get_palette_entries(handle, start, 0, &mut []))).unwrap_or(0));
            }
            let mut out = Vec::new();
            if out.try_reserve_exact(count as usize).is_err() { return 0; }
            out.resize(count as usize, PaletteEntry::default());
            let Ok(copied) = crate::nt_gdi::with_gdi(|state| Ok(state.get_palette_entries(handle, start, count, &mut out))) else { return 0; };
            if copied == 0 { return 0; }
            if !write_entries(address, &out[..copied as usize]) { return 0; }
            u64::from(copied)
        }
        SET_PALETTE_ENTRIES | ANIMATE_PALETTE => {
            let Some(entries) = read_entries(address, count) else { return 0; };
            if function == ANIMATE_PALETTE {
                return u64::from(crate::nt_gdi::with_gdi(|state| Ok(state.animate_palette(handle, start, count, &entries))).unwrap_or(false));
            }
            u64::from(crate::nt_gdi::with_gdi(|state| Ok(state.set_palette_entries(handle, start, count, &entries))).unwrap_or(0))
        }
        // The device driver reports no system palette entries at all.
        GET_SYSTEM_PALETTE_ENTRIES => 0,
        GET_DIB_COLOR_TABLE => {
            if address == 0 || count == 0 { return 0; }
            let mut out = Vec::new();
            if out.try_reserve_exact(count as usize).is_err() { return 0; }
            out.resize(count as usize, Rgb::default());
            let Ok(copied) = crate::nt_gdi::with_gdi(|state| Ok(state.get_dib_color_table(handle, start, count, &mut out))) else { return 0; };
            if copied == 0 { return 0; }
            let mut bytes = Vec::new();
            if bytes.try_reserve(copied as usize * RGBQUAD_BYTES).is_err() { return 0; }
            for entry in &out[..copied as usize] { bytes.extend_from_slice(&[entry.blue, entry.green, entry.red, 0]); }
            if uaccess::copy_to_user(address, &bytes).is_err() { return 0; }
            u64::from(copied)
        }
        SET_DIB_COLOR_TABLE => {
            let Some(colors) = read_color_table(address, count) else { return 0; };
            u64::from(crate::nt_gdi::with_gdi(|state| Ok(state.set_dib_color_table(handle, start, count, &colors))).unwrap_or(0))
        }
        _ => 0,
    }
}

/// A colour table entry is stored blue, green, red, reserved. # C: O(count)
pub(super) fn read_color_table(address: u64, count: u32) -> Option<Vec<Rgb>> {
    if address == 0 { return None; }
    let mut bytes = Vec::new();
    let len = (count as usize).checked_mul(RGBQUAD_BYTES)?;
    bytes.try_reserve(len).ok()?;
    bytes.resize(len, 0);
    uaccess::copy_from_user(&mut bytes, address).ok()?;
    let mut table = Vec::new();
    table.try_reserve_exact(count as usize).ok()?;
    for chunk in bytes.chunks_exact(RGBQUAD_BYTES) { table.push(Rgb { blue: chunk[0], green: chunk[1], red: chunk[2] }); }
    Some(table)
}

fn get_bitmap_bits(bitmap: u64, count: i64, address: u64) -> u64 {
    let Ok(bitmap) = u32::try_from(bitmap) else { return 0; };
    let Ok(max) = crate::nt_gdi::with_gdi(|state| state.bitmap_bits_len(bitmap)) else { return 0; };
    if address == 0 { return max.max(0) as u64; }
    let wanted = if count < 0 || count > max { max } else { count };
    if wanted <= 0 || wanted > ipc::win32_gdi::MAX_BITMAP_BYTES { return 0; }
    let mut out = Vec::new();
    if out.try_reserve(wanted as usize).is_err() { return 0; }
    out.resize(wanted as usize, 0);
    let Ok(copied) = crate::nt_gdi::with_gdi(|state| state.get_bitmap_bits(bitmap, wanted, &mut out)) else { return 0; };
    if uaccess::copy_to_user(address, &out[..copied as usize]).is_err() { return 0; }
    copied as u64
}

fn set_bitmap_bits(bitmap: u64, count: i64, address: u64) -> u64 {
    let Ok(bitmap) = u32::try_from(bitmap) else { return 0; };
    if address == 0 { return 0; }
    let Ok(max) = crate::nt_gdi::with_gdi(|state| state.bitmap_bits_len(bitmap)) else { return 0; };
    let Some(wanted) = count.checked_abs().map(|count| count.min(max)) else { return 0; };
    if wanted <= 0 || wanted > ipc::win32_gdi::MAX_BITMAP_BYTES { return 0; }
    let mut bits = Vec::new();
    if bits.try_reserve(wanted as usize).is_err() { return 0; }
    bits.resize(wanted as usize, 0);
    if uaccess::copy_from_user(&mut bits, address).is_err() { return 0; }
    crate::nt_gdi::with_gdi(|state| state.set_bitmap_bits(bitmap, wanted, &bits)).unwrap_or(0) as u64
}
