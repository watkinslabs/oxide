//! Device-independent bitmap ingress: fetch the caller's header, colour table
//! and bits, then let the canonical owner build or transfer the image.
use alloc::vec::Vec;
use ipc::win32_gdi::{DibHeader, Rgb, BI_BITFIELDS, BITFIELD_BYTES, CORE_HEADER_BYTES,
    INFO_HEADER_BYTES, RGBQUAD_BYTES, RGBTRIPLE_BYTES, SRCCOPY};
use super::super::{Operation, Rect};

/// The bitmap the caller initialises is written at creation.
const CBM_INIT: u32 = 4;
/// Colour tables never exceed the eight-bit depth's range.
const MAX_COLOR_TABLE: u32 = 256;

/// One caller header and the colour table or channel masks behind it.
struct Info { header: DibHeader, table: Vec<Rgb>, masks: [u32; 3] }

/// Read and sanitize a caller `BITMAPINFO`. The header shape decides both the
/// colour-table entry width and where the table starts. # C: O(entries)
fn read_info(address: u64) -> Option<Info> {
    if address == 0 { return None; }
    let mut header_bytes = [0u8; INFO_HEADER_BYTES as usize];
    let size = uaccess::get_user_u32(address).ok()?;
    let span = if size == CORE_HEADER_BYTES { CORE_HEADER_BYTES } else { INFO_HEADER_BYTES } as usize;
    uaccess::copy_from_user(&mut header_bytes[..span], address).ok()?;
    let header = DibHeader::parse(&header_bytes[..span])?;
    let tail = address.checked_add(u64::from(size.max(CORE_HEADER_BYTES)))?;
    let mut masks = [0u32; 3];
    if header.compression == BI_BITFIELDS {
        let mut bytes = [0u8; BITFIELD_BYTES];
        uaccess::copy_from_user(&mut bytes, tail).ok()?;
        for (index, mask) in masks.iter_mut().enumerate() {
            let at = index * 4;
            *mask = u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
        }
        return Some(Info { header, table: Vec::new(), masks });
    }
    let entries = header.supplied_colors().min(MAX_COLOR_TABLE);
    let width = if size == CORE_HEADER_BYTES { RGBTRIPLE_BYTES } else { RGBQUAD_BYTES };
    let mut bytes = Vec::new();
    bytes.try_reserve(entries as usize * width).ok()?;
    bytes.resize(entries as usize * width, 0);
    if entries > 0 { uaccess::copy_from_user(&mut bytes, tail).ok()?; }
    let mut table = Vec::new();
    table.try_reserve_exact(entries as usize).ok()?;
    for chunk in bytes.chunks_exact(width) { table.push(Rgb { blue: chunk[0], green: chunk[1], red: chunk[2] }); }
    Some(Info { header, table, masks })
}

/// Bytes one image occupies at the header's own stride. # C: O(1)
fn image_bytes(header: &DibHeader) -> Option<usize> {
    let size = header.image_size()?;
    if i64::from(size) > ipc::win32_gdi::MAX_BITMAP_BYTES { return None; }
    Some(size as usize)
}

fn read_bits(address: u64, len: usize) -> Option<Vec<u8>> {
    if address == 0 || len == 0 { return None; }
    let mut bytes = Vec::new();
    bytes.try_reserve(len).ok()?;
    bytes.resize(len, 0);
    uaccess::copy_from_user(&mut bytes, address).ok()?;
    Some(bytes)
}

pub(super) fn dispatch(operation: Operation) -> u64 {
    match operation {
        Operation::CreateDibSection { section, info, usage, bits_out, .. } => {
            // A caller-supplied section is a mapped view this owner does not
            // hand out; the object always owns its own storage.
            if section != 0 { return 0; }
            let Some(info) = read_info(info) else { return 0; };
            let Ok(handle) = crate::nt_gdi::create_dib_section_for_current(info.header, usage, &info.table, info.masks) else { return 0; };
            if bits_out != 0 && uaccess::put_user_u64(bits_out, 0).is_err() { return u64::from(handle); }
            u64::from(handle)
        }
        Operation::CreateDibitmap { dc, width, height, init, bits, info, usage } =>
            create_dibitmap(dc, width, height, init, bits, info, usage),
        Operation::CreateDibBrush { data, usage } => create_dib_brush(data, usage),
        Operation::GetDiBits { dc, bitmap, start, lines, bits, info, usage } =>
            get_dibits(dc, bitmap, start, lines, bits, info, usage),
        Operation::SetDiBitsToDevice { dc, dst, src_x, src_y, start, lines, bits, info, usage } =>
            set_dibits_to_device(dc, dst, src_x, src_y, start, lines, bits, info, usage),
        Operation::StretchDiBits { dc, dst, src, bits, info, usage, code } =>
            stretch_dibits(dc, dst, src, bits, info, usage, code),
        _ => 0,
    }
}

/// A device-independent image becomes a bitmap the reference device can
/// select, then takes the caller's bits. # C: O(width*height)
fn create_dibitmap(dc: u64, width: i32, height: i32, init: u32, bits: u64, info: u64, usage: u32) -> u64 {
    if usage > ipc::win32_gdi::DIB_PAL_INDICES || width < 0 { return 0; }
    let height = height.saturating_abs();
    let handle = if dc == 0 {
        crate::nt_gdi::create_bitmap_for_current(width, height, 1, 1, None).unwrap_or(0)
    } else {
        let Ok(dc) = u32::try_from(dc) else { return 0; };
        let device = super::raster::device();
        crate::nt_gdi::create_compatible_bitmap_for_current(dc, width, height, device.0, device.1).unwrap_or(0)
    };
    if handle == 0 { return 0; }
    if init & CBM_INIT == 0 { return u64::from(handle); }
    if set_di_bits(handle, 0, height as u32, bits, info) == 0 {
        let _ = crate::nt_gdi::delete_paint_dc_current(handle);
        return 0;
    }
    u64::from(handle)
}

/// Store caller rows into an existing bitmap. Answers the row count stored.
/// # C: O(rows*width)
fn set_di_bits(bitmap: u32, start: u32, lines: u32, bits: u64, info: u64) -> u64 {
    let Some(info) = read_info(info) else { return 0; };
    // Run-length rows are not stored rows; refuse rather than read them as raster.
    if !info.header.is_valid(false) { return 0; }
    let Some(len) = image_bytes(&info.header) else { return 0; };
    let Some(source) = read_bits(bits, len) else { return 0; };
    let Ok(stored) = crate::nt_gdi::with_gdi(|state| state.put_dib_rows(bitmap, &info.header, &info.table, info.masks, &source, start, lines)) else { return 0; };
    u64::from(stored)
}

fn create_dib_brush(data: u64, usage: u32) -> u64 {
    let Some(info) = read_info(data) else { return 0; };
    if !info.header.is_valid(false) { return 0; }
    let Some(len) = image_bytes(&info.header) else { return 0; };
    let header_span = if info.header.compression == BI_BITFIELDS { BITFIELD_BYTES }
        else { info.header.supplied_colors() as usize * RGBQUAD_BYTES };
    let Some(bits) = data.checked_add(INFO_HEADER_BYTES as u64 + header_span as u64) else { return 0; };
    let Some(source) = read_bits(bits, len) else { return 0; };
    let Ok(handle) = crate::nt_gdi::create_dib_section_for_current(info.header, usage, &info.table, info.masks) else { return 0; };
    let stored = crate::nt_gdi::with_gdi(|state| state.put_dib_rows(handle, &info.header, &info.table, info.masks,
        &source, 0, info.header.height.unsigned_abs()));
    if stored.is_err() { let _ = crate::nt_gdi::delete_paint_dc_current(handle); return 0; }
    let brush = crate::nt_gdi::create_pattern_brush_for_current(handle).unwrap_or(0);
    let _ = crate::nt_gdi::delete_paint_dc_current(handle);
    u64::from(brush)
}

fn get_dibits(dc: u64, bitmap: u64, start: u32, lines: u32, bits: u64, info: u64, usage: u32) -> u64 {
    let (Ok(_), Ok(bitmap)) = (u32::try_from(dc), u32::try_from(bitmap)) else { return 0; };
    if usage > ipc::win32_gdi::DIB_PAL_COLORS { return 0; }
    let Some(request) = read_info(info) else { return 0; };
    // A request with no depth and no destination asks for the bitmap's own
    // shape; the owner fills the header in and reports it.
    if bits == 0 || lines == 0 {
        let Ok(header) = crate::nt_gdi::with_gdi(|state| state.dib_query_header(bitmap)) else { return 0; };
        if request.header.bit_count != 0 { return 1; }
        return u64::from(write_header(info, &header));
    }
    if !request.header.is_valid(false) { return 0; }
    let Some(len) = image_bytes(&request.header) else { return 0; };
    let mut out = Vec::new();
    if out.try_reserve(len).is_err() { return 0; }
    out.resize(len, 0);
    let Ok(rows) = crate::nt_gdi::with_gdi(|state| state.take_dib_rows(bitmap, &request.header, &request.table,
        request.masks, &mut out, start, lines)) else { return 0; };
    if rows == 0 { return 0; }
    if uaccess::copy_to_user(bits, &out).is_err() { return 0; }
    u64::from(rows)
}

/// Write back the header fields a shape query answers. # C: O(1)
fn write_header(address: u64, header: &DibHeader) -> bool {
    let mut bytes = [0u8; INFO_HEADER_BYTES as usize];
    bytes[0..4].copy_from_slice(&INFO_HEADER_BYTES.to_le_bytes());
    bytes[4..8].copy_from_slice(&header.width.to_le_bytes());
    bytes[8..12].copy_from_slice(&header.height.to_le_bytes());
    bytes[12..14].copy_from_slice(&header.planes.to_le_bytes());
    bytes[14..16].copy_from_slice(&header.bit_count.to_le_bytes());
    bytes[16..20].copy_from_slice(&header.compression.to_le_bytes());
    bytes[20..24].copy_from_slice(&header.size_image.to_le_bytes());
    bytes[32..36].copy_from_slice(&header.clr_used.to_le_bytes());
    uaccess::copy_to_user(address, &bytes).is_ok()
}

fn set_dibits_to_device(dc: u64, dst: Rect, src_x: i32, src_y: i32, start: u32, lines: u32, bits: u64, info: u64, usage: u32) -> u64 {
    let Ok(handle) = u32::try_from(dc) else { return 0; };
    if usage > ipc::win32_gdi::DIB_PAL_INDICES { return 0; }
    let Some(request) = read_info(info) else { return 0; };
    // Run-length rows are not stored rows; refuse rather than read them as raster.
    if !request.header.is_valid(false) { return 0; }
    let Some(len) = image_bytes(&request.header) else { return 0; };
    let Some(source) = read_bits(bits, len) else { return 0; };
    let Ok((colors, _)) = crate::nt_gdi::colors_for(dc) else { return 0; };
    let source_rect = ipc::win32_gdi::BltCoords { x: src_x, y: src_y, width: dst.width, height: dst.height };
    let target = ipc::win32_gdi::BltCoords { x: dst.x, y: dst.y, width: dst.width, height: dst.height };
    crate::nt_gdi::with_gdi(|state| state.draw_dib(handle, target, source_rect, &request.header, &request.table,
        request.masks, &source, start, lines, SRCCOPY, colors, ipc::win32_gdi::COLORONCOLOR)).unwrap_or(0) as u64
}

fn stretch_dibits(dc: u64, dst: Rect, src: Rect, bits: u64, info: u64, usage: u32, code: u32) -> u64 {
    let Ok(handle) = u32::try_from(dc) else { return 0; };
    if usage > ipc::win32_gdi::DIB_PAL_INDICES { return 0; }
    let Some(request) = read_info(info) else { return 0; };
    // Run-length rows are not stored rows; refuse rather than read them as raster.
    if !request.header.is_valid(false) { return 0; }
    let Some(len) = image_bytes(&request.header) else { return 0; };
    let Some(source) = read_bits(bits, len) else { return 0; };
    let Ok((colors, mode)) = crate::nt_gdi::colors_for(dc) else { return 0; };
    let source_rect = ipc::win32_gdi::BltCoords { x: src.x, y: src.y, width: src.width, height: src.height };
    let target = ipc::win32_gdi::BltCoords { x: dst.x, y: dst.y, width: dst.width, height: dst.height };
    let lines = request.header.height.unsigned_abs();
    crate::nt_gdi::with_gdi(|state| state.draw_dib(handle, target, source_rect, &request.header, &request.table,
        request.masks, &source, 0, lines, code, colors, mode)).unwrap_or(0) as u64
}
