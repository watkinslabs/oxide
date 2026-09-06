//! Execution of typed raw win32u GDI operations.
//!
//! The parent raw router owns ABI admission and calls this child after
//! gdi_raw::decode. This module owns no GDI table: object operations use
//! nt_gdi::dispatch, text attributes use the canonical DC wrappers, and
//! glyph rasterization leaves through the registered native callback.

use super::{Operation, SET_BK_COLOR, SET_BK_MODE, SET_TEXT_ALIGN, SET_TEXT_COLOR};
use syscall::{nt::{NtCall, NtService}, nt_native_gdi::{self as text_abi, TextRequest, MeasureRequest}, SyscallArgs};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const DEFAULT_DC_WIDTH: i32 = 800;
const DEFAULT_DC_HEIGHT: i32 = 600;
const TEB_LAST_ERROR_OFFSET: u64 = 0x68;
const SET_DC_BRUSH_COLOR: u32 = 103;

/// Execute one admitted raw operation against canonical owners.
/// # C: bounded usercopy plus canonical GDI operation cost
pub(crate) fn dispatch(operation: Operation) -> u64 {
    match operation {
        Operation::CreateCompatibleDc { source } => create_dc(source),
        Operation::DeleteObject { handle } => bool_status(native(NtService::DeleteGdiObject, [handle, 0, 0, 0, 0, 0])),
        Operation::HfontCreate { logfont, size, font_type, flags, data } => create_font(logfont, size, font_type, flags, data),
        Operation::SelectFont { dc, font } => handle_result(native(NtService::SelectGdiFont, [dc, font, 0, 0, 0, 0])),
        Operation::SetDcDword { dc, method, value, previous } => set_dc_dword(dc, method, value, previous),
        Operation::MoveTo { dc, x, y, previous } => move_to(dc, x, y, previous),
        Operation::GetTextMetricsW { dc, metrics, flags } => get_text_metrics(dc, metrics, flags),
        Operation::GetTextExtentExW { dc, text, count, max_extent, nfit, dx, extent, flags } => get_text_extent(dc, text, count, max_extent, nfit, dx, extent, flags),
        Operation::ExtTextOutW { dc, x, y, flags, rect, text, count, dx, code_page } => ext_text_out(dc, x, y, flags, rect, text, count, dx, code_page),
    }
}

fn native(service: NtService, args: [u64; 6]) -> u64 {
    crate::nt_gdi::dispatch(NtCall { service, args: SyscallArgs { a0: args[0], a1: args[1], a2: args[2], a3: args[3], a4: args[4], a5: args[5] } }).unwrap_or(STATUS_INVALID_PARAMETER)
}

fn bool_status(status: u64) -> u64 { (status == STATUS_SUCCESS) as u64 }
fn handle_result(status: u64) -> u64 {
    let value = status as u32;
    if value & 0xc000_0000 == 0xc000_0000 { 0 } else { status }
}

fn create_dc(source: u64) -> u64 {
    let (width, height) = if source == 0 { (DEFAULT_DC_WIDTH, DEFAULT_DC_HEIGHT) } else {
        let Ok(source) = u32::try_from(source) else { return 0; };
        let Ok(state) = crate::nt_gdi::text_snapshot_for_current(source as u64) else { return 0; };
        (state.width, state.height)
    };
    handle_result(native(NtService::CreateCompatibleDc, [width as u64, height as u64, 0, 0, 0, 0]))
}

fn create_font(logfont: u64, size: u32, font_type: u32, flags: u32, data: u64) -> u64 {
    if let Err(error) = super::super::object_raw::validate_hfont_create(logfont, size) {
        if let Some(error) = error.last_error() {
            if let Some(task) = sched::live::current() {
                if task.nt_teb() != 0 {
                    if let Some(address) = task.nt_teb().checked_add(TEB_LAST_ERROR_OFFSET) { let _ = uaccess::put_user_u32(address, error); }
                }
            }
        }
        return 0;
    }
    let mut bytes = [0u8; ipc::win32_gdi::LOGFONTW_BYTES];
    if uaccess::copy_from_user(&mut bytes, logfont).is_err() { return 0; }
    let _ = (font_type, flags, data);
    crate::nt_gdi::create_font_record_for_current(bytes).map(|handle| handle as u64).unwrap_or(0)
}

fn set_dc_dword(dc: u64, method: u32, value: u32, previous: u64) -> u64 {
    use crate::nt_gdi_text_policy::{set_dword_result, OldValueEncoding};
    if method == SET_DC_BRUSH_COLOR {
        return set_dword_result(previous, crate::nt_gdi::set_dc_brush_color_for_current(dc, value), OldValueEncoding::RawDword,
            |pointer, old| uaccess::put_user_u32(pointer, old).is_ok());
    }
    let attribute = match method {
        SET_BK_COLOR => ipc::win32_gdi::TextAttribute::Background,
        SET_BK_MODE => ipc::win32_gdi::TextAttribute::BackgroundMode,
        SET_TEXT_COLOR => ipc::win32_gdi::TextAttribute::Foreground,
        SET_TEXT_ALIGN => ipc::win32_gdi::TextAttribute::Alignment,
        _ => return 0,
    };
    let encoding = if method == SET_BK_COLOR || method == SET_TEXT_COLOR { OldValueEncoding::Xrgb } else { OldValueEncoding::RawDword };
    set_dword_result(previous, crate::nt_gdi::set_text_attribute_for_current(dc, attribute, value), encoding,
        |pointer, old| uaccess::put_user_u32(pointer, old).is_ok())
}

fn move_to(dc: u64, x: i32, y: i32, previous: u64) -> u64 {
    crate::nt_gdi_text_policy::move_to_result(previous,
        crate::nt_gdi::text_snapshot_for_current(dc).map(|state| state.attributes.current_position),
        |pointer, bytes| uaccess::copy_to_user(pointer, bytes).is_ok(),
        || crate::nt_gdi::set_text_position_for_current(dc, (x, y)).is_ok())
}

fn get_text_metrics(dc: u64, pointer: u64, flags: u32) -> u64 {
    let Some(mut request) = measure_request(dc, text_abi::MEASURE_METRICS) else { return 0; };
    request.metrics = pointer;
    request.flags = flags;
    crate::nt_native_gdi::begin_measure(request)
}

fn get_text_extent(dc: u64, text: u64, count: i32, max_extent: i32, nfit: u64, dx: u64, extent: u64, flags: u32) -> u64 {
    if count < 0 { return 0; }
    let Some(mut request) = measure_request(dc, text_abi::MEASURE_EXTENT) else { return 0; };
    request.text = text;
    request.count = count as u32;
    request.max_extent = max_extent;
    request.fit = nfit;
    request.cumulative = dx;
    request.extent = extent;
    request.flags = flags;
    crate::nt_native_gdi::begin_measure(request)
}

fn measure_request(dc: u64, kind: u32) -> Option<MeasureRequest> {
    let state = crate::nt_gdi::text_snapshot_for_current(dc).ok()?;
    let stock = crate::nt_gdi::text_metrics_for_current(dc).ok()?;
    let (height, width, weight, italic) = state.font.map(|font| (font.height, font.width, font.weight, font.italic as u32))
        .unwrap_or((stock.height, 0, 0, 0));
    Some(MeasureRequest { version: text_abi::VERSION, size: core::mem::size_of::<MeasureRequest>() as u32,
        dc, kind, count: 0, height, width, weight, italic, max_extent: 0, flags: 0,
        text: 0, metrics: 0, extent: 0, fit: 0, cumulative: 0 })
}

fn ext_text_out(dc: u64, x: i32, y: i32, flags: u32, rect: u64, text: u64, count: u32, dx: u64, code_page: u32) -> u64 {
    let Ok(state) = crate::nt_gdi::text_snapshot_for_current(dc) else { return 0; };
    let Ok(input) = super::text_output::validate(flags, rect, text, count, dx, code_page) else { return 0; };
    let metrics = match crate::nt_gdi::text_metrics_for_current(dc) { Ok(metrics) => metrics, Err(_) => return 0 };
    let (height, width, weight, italic) = state.font.map(|font| (font.height, font.width, font.weight, font.italic as u32))
        .unwrap_or((metrics.height, 0, 0, 0));
    let has_rect = input.rect.is_some();
    let mut raw_rect = [0u8; 16];
    if let Some(rect) = input.rect { if uaccess::copy_from_user(&mut raw_rect, rect).is_err() { return 0; } }
    let mut request_rect = [0i32; 4];
    for (index, slot) in request_rect.iter_mut().enumerate() { *slot = i32::from_le_bytes(raw_rect[index * 4..index * 4 + 4].try_into().unwrap()); }
    let request = TextRequest { version: syscall::nt_native_gdi::VERSION, size: core::mem::size_of::<TextRequest>() as u32,
        dc, x, y, flags: input.flags, count: input.count, text: input.text, advances: input.advances.unwrap_or(0), rect: request_rect, height,
        width, weight, italic, foreground: state.attributes.foreground,
        background: state.attributes.background, has_rect: has_rect as u32, reserved: 0,
        background_mode: state.attributes.background_mode, alignment: state.attributes.alignment,
        current_x: state.attributes.current_position.0, current_y: state.attributes.current_position.1 };
    crate::nt_native_gdi::begin(request)
}
