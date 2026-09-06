//! Pure projection of existing text-owner attributes into raw DWORD query results.
use ipc::win32_gdi::TextAttributes;
const GET_BACKGROUND_COLOR:u32=1;
const GET_BACKGROUND_MODE:u32=2;
const GET_TEXT_COLOR:u32=9;

/// Query only represented text attributes; conversion uses the shared client codec. # C: O(1)
pub(crate) fn dc_query_value(method:u32,attributes:TextAttributes)->Option<u32> {
    match method {
        GET_BACKGROUND_COLOR=>syscall::nt_gdi_client::xrgb_to_colorref(attributes.background).ok(),
        GET_BACKGROUND_MODE=>Some(attributes.background_mode),
        GET_TEXT_COLOR=>syscall::nt_gdi_client::xrgb_to_colorref(attributes.foreground).ok(),
        _=>None,
    }
}
