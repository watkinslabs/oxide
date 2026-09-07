//! Module manifest: `legacy` owns the code-selected tail; this file owns the
//! walk and the family-to-router binding. Both ordinal entries call `route`.
use super::super::*;
use super::{Family, MAX_ARGS, ORDER};

#[path = "legacy.rs"]
mod legacy;

/// Normalized Windows-order arguments. Index `n` holds Windows argument `n`;
/// words past the ordinal's admitted count are zero.
pub(crate) type Args = [u64; MAX_ARGS];
type Route = fn(u64, &Args) -> Option<u64>;

/// Walk the one chain. The first family that claims the ordinal answers it.
/// # C: O(len(ORDER))
pub(crate) fn route(ordinal: u64, args: &Args) -> Option<u64> {
    for family in ORDER {
        if let Some(result) = binding(*family)(ordinal, args) { return Some(result); }
    }
    None
}

/// The exhaustive family-to-router binding: a new family cannot reach either
/// entry without an arm here, and a removed arm fails the kernel build.
/// # C: O(1)
fn binding(family: Family) -> Route {
    match family {
        Family::CaretRaw => (|o, a: &Args| caret_raw::dispatch(o, [a[0], a[1], a[2], a[3]])) as Route,
        Family::HwndCall => (|o, a: &Args| hwnd_call::kernel::route(o, a)) as Route,
        Family::MsgFilter => (|o, _a: &Args| msg_filter::route(o, || false)) as Route,
        Family::TwoParam => (|o, a: &Args| two_param::kernel::route(o, a)) as Route,
        Family::DpiContext => (|o, a: &Args| dpi_context::kernel::route(o, a)) as Route,
        Family::InputContext => (|o, a: &Args| input_context::kernel::route(o, a)) as Route,
        Family::QueryWindow => (|o, a: &Args| query_window::kernel::route(o, a)) as Route,
        Family::AccelRaw => (|o, a: &Args| accel_raw::kernel::route(o, a)) as Route,
        Family::ClipboardRaw => (|o, a: &Args| clipboard_raw::kernel::route(o, a)) as Route,
        Family::AtomRaw => (|o, a: &Args| atom_raw::kernel::route(o, a)) as Route,
        Family::HookRaw => (|o, a: &Args| hook_raw::kernel::route(o, a)) as Route,
        Family::StationRaw => (|o, a: &Args| station_raw::kernel::route(o, a)) as Route,
        Family::WindowRaw => (|o, a: &Args| window_raw::kernel::route(o, a)) as Route,
        Family::Scroll => (|o, a: &Args| crate::nt_window::scroll::dispatch(o, [a[0], a[1], a[2], a[3]])) as Route,
        Family::MessageQueue => (|o, a: &Args| crate::nt_window::message_queue::route(o, a)) as Route,
        Family::Timer => (|o, a: &Args| crate::nt_window::timer::dispatch(o, [a[0], a[1], a[2], a[3], a[4]])) as Route,
        Family::UpdateRegion => (|o, a: &Args| crate::nt_window::update_region::route(o, [a[0], a[1], a[2]])) as Route,
        Family::Caption => (|o, a: &Args| crate::nt_window::caption::route(o, a)) as Route,
        Family::SysColors => (|o, a: &Args| crate::nt_window::sys_colors::route(o, a)) as Route,
        Family::ScrollBar => (|o, a: &Args| crate::nt_window::scroll::bar_live::route(o, [a[0], a[1], a[2], a[3]])) as Route,
        Family::ScrollDc => (|o, a: &Args| crate::nt_window::scroll::dc_live::route(o, a)) as Route,
        Family::MenuRaw => (|o, a: &Args| crate::nt_window::menu_raw::route(o, a)) as Route,
        Family::Display => (|o, a: &Args| crate::nt_window::display::route(o, a)) as Route,
        Family::Drag => (|o, a: &Args| crate::nt_window::drag::route(o, a)) as Route,
        Family::DrawIcon => (|o, a: &Args| crate::nt_window::draw_icon::route(o, a)) as Route,
        Family::VisibilityRaw => (|o, a: &Args| crate::nt_visibility_raw::kernel::route(o, a)) as Route,
        Family::RegionRaw => (|o, a: &Args| crate::nt_region_raw::kernel::route(o, a)) as Route,
        Family::DcQueryRaw => (|o, a: &Args| crate::nt_dc_query_raw::kernel::route(o, a)) as Route,
        Family::PenRaw => (|o, a: &Args| crate::nt_pen_raw::kernel::route(o, a)) as Route,
        Family::SetRectRgnRaw => (|o, a: &Args| crate::nt_set_rect_rgn_raw::kernel::route(o, a)) as Route,
        Family::DcRaw => (|o, a: &Args| crate::nt_dc_raw::kernel::route(o, a)) as Route,
        Family::DcStateRaw => (|o, a: &Args| crate::nt_dc_state_raw::kernel::route(o, a)) as Route,
        Family::XformRaw => (|o, a: &Args| crate::nt_xform_raw::kernel::route(o, a)) as Route,
        Family::DrawRaw => (|o, a: &Args| crate::nt_draw_raw::kernel::route(o, a)) as Route,
        Family::PrintRaw => (|o, a: &Args| crate::nt_print_raw::kernel::route(o, a)) as Route,
        Family::Redraw => (|o, a: &Args| (o == crate::nt_window::redraw::ORDINAL)
            .then(|| crate::nt_window::redraw::for_current(a[0], a[1], a[2], a[3] as u32))) as Route,
        Family::SystemColorRaw => (|o, a: &Args| crate::nt_system_color_raw::route(o, a, crate::nt_gdi::system_color_brush_for_current)) as Route,
        Family::NonclientRaw => (|o, a: &Args| crate::nt_nonclient_raw::route(o, a,
            |pointer| uaccess::get_user_u32(pointer).ok(), crate::nt_native_gdi::begin_nonclient)) as Route,
        Family::FontQuery => (|o, a: &Args| crate::nt_wine_font_query_contract::route(o, a,
            |dc| crate::nt_gdi::text_snapshot_for_current(dc).ok().and_then(|state| state.font),
            crate::nt_native_gdi::begin_query)) as Route,
        Family::FontFamily => (|o, a: &Args| crate::nt_wine_font_family_contract::kernel::route(o, a)) as Route,
        Family::PropertyRaw => (|o, a: &Args| property_raw::dispatch(o, [a[0], a[1], a[2]])) as Route,
        Family::DcObject => (|o, a: &Args| (o == object_raw::GET_DC_OBJECT)
            .then(|| crate::nt_gdi::selected_object_current(a[0], a[1] as u32))) as Route,
        Family::LongRaw => (|o, a: &Args| long_raw::dispatch(o, [a[0], a[1], a[2], a[3]])) as Route,
        Family::ClassSet => (|o, a: &Args| class_raw::dispatch_set(o, [a[0], a[1], a[2], a[3]])) as Route,
        Family::CursorRaw => (|o, a: &Args| cursor_raw::route(o, a)) as Route,
        Family::CursorIconRaw => (|o, a: &Args| cursor_icon_raw::kernel::route(o, a)) as Route,
        Family::InputRaw => (|o, a: &Args| input_raw::kernel::route(o, a)) as Route,
        Family::KeyboardRaw => (|o, a: &Args| keyboard_raw::kernel::route(o, a)) as Route,
        Family::RawInputRaw => (|o, a: &Args| rawinput_raw::kernel::route(o, a)) as Route,
        Family::HwndParam => hwnd_param_route as Route,
        Family::GdiRoute => (|o, a: &Args| gdi_route::descriptor(o, a)) as Route,
        Family::ObjectRaw => (|o, a: &Args| object_raw::decode(o, a).map(object_raw::kernel::dispatch)) as Route,
        Family::BitmapRaw => (|o, a: &Args| bitmap_raw::kernel::route(o, a)) as Route,
        Family::GdiBitmapRaw => (|o, a: &Args| gdi_bitmap_raw::kernel::descriptor(o, a)) as Route,
        Family::DeviceCaps => (|o, a: &Args| device_caps::kernel::route(o, a)) as Route,
        Family::BrushRaw => (|o, a: &Args| brush_raw::decode(o, a).map(brush_raw::kernel::dispatch)) as Route,
        Family::ClipRaw => (|o, a: &Args| clip_raw::decode(o, a).map(clip_raw::kernel::dispatch)) as Route,
        Family::GdiShape => (|o, a: &Args| crate::nt_wine_gdi_shape::decode::decode(o, a)
            .map(crate::nt_wine_gdi_shape::kernel::dispatch)) as Route,
        Family::KeyboardQuery => (|o, a: &Args| keyboard_query(o, a[0])) as Route,
        Family::Legacy => legacy::route as Route,
    }
}

/// `NtUserCallHwndParam` multiplexes three requests behind one ordinal.
/// # C: O(1) plus the selected request's own cost
fn hwnd_param_route(ordinal: u64, a: &Args) -> Option<u64> {
    if ordinal != hwnd_param::ORDINAL { return None; }
    if let Some(hwnd_param::Request::GetWindowLong { offset, width }) = hwnd_param::decode_request(a[2] as u32, a[1]) {
        return Some(long_raw::get(a[0], offset, width));
    }
    if a[2] as u32 == hwnd_param::GET_WINDOW_RECTS { return Some(hwnd_param::dispatch_get_window_rects(a[0], a[1])); }
    class_raw::decode_get(a[2] as u32, a[0], a[1]).map(class_raw::get)
}
