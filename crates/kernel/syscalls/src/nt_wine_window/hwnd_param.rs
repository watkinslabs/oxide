//! ABI and child-window helpers for raw `NtUserCallHwndParam`.
//!
//! The dispatcher owns syscall admission and user-copy policy. This module
//! owns the frozen method/parameter contract so the dispatcher cannot drift
//! from Wine's generated ABI.

pub(crate) const ORDINAL: u64 = 0x1336;
pub(crate) const GET_WINDOW_LONG_A: u32 = 9;
pub(crate) const GET_WINDOW_LONG_W: u32 = 10;
pub(crate) const GET_WINDOW_LONG_PTR_A: u32 = 11;
pub(crate) const GET_WINDOW_LONG_PTR_W: u32 = 12;
pub(crate) const GET_WINDOW_RECTS: u32 = 13;
pub(crate) const PARAM_BYTES: usize = 16;
pub(crate) const WS_CHILD: u32 = 0x4000_0000;
pub(crate) const WS_POPUP: u32 = 0x8000_0000;

/// Method decoding only. The LongPtr getter is deliberately not backed by a
/// second window table; the dispatcher passes its offset to Bernoulli's
/// canonical extra-bytes/long-ptr owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Request {
    GetWindowLong { offset: i32, width: usize },
    GetWindowRects { params: u64 },
}

pub(crate) const fn decode_request(method: u32, param: u64) -> Option<Request> {
    match method {
        GET_WINDOW_LONG_A | GET_WINDOW_LONG_W => Some(Request::GetWindowLong { offset: param as i32, width: 4 }),
        GET_WINDOW_LONG_PTR_A | GET_WINDOW_LONG_PTR_W => Some(Request::GetWindowLong { offset: param as i32, width: 8 }),
        GET_WINDOW_RECTS => Some(Request::GetWindowRects { params: param }),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GetWindowRectsParams {
    pub rect: u64,
    pub client: u32,
    pub dpi: u32,
}

impl GetWindowRectsParams {
    pub(crate) fn decode(bytes: [u8; PARAM_BYTES]) -> Self {
        let u64_at = |offset| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        let u32_at = |offset| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        Self { rect: u64_at(0), client: u32_at(8), dpi: u32_at(12) }
    }

    pub(crate) fn encode(self) -> [u8; PARAM_BYTES] {
        let mut bytes = [0u8; PARAM_BYTES];
        bytes[0..8].copy_from_slice(&self.rect.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.client.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.dpi.to_le_bytes());
        bytes
    }
}

/// POPUP wins over CHILD, matching the frozen effective-child rule.
pub(crate) const fn is_effective_child(style: u32) -> bool {
    style & WS_CHILD != 0 && style & WS_POPUP == 0
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreateMenuValue {
    None,
    ChildControlId(u64),
    MenuHandle(u64),
}

/// A child hMenu is a pointer-width control ID, never an HMENU to validate.
pub(crate) const fn classify_create_menu(style: u32, value: u64) -> CreateMenuValue {
    if value == 0 { CreateMenuValue::None }
    else if is_effective_child(style) { CreateMenuValue::ChildControlId(value) }
    else { CreateMenuValue::MenuHandle(value) }
}

/// Execute method 13 after raw dispatch has validated the ordinal. The
/// canonical window owner remains the only source of geometry.
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn dispatch_get_window_rects(hwnd: u64, params_ptr: u64) -> u64 {
    if hwnd > u32::MAX as u64 || params_ptr == 0 { return 0; }
    let mut bytes = [0u8; PARAM_BYTES];
    if uaccess::copy_from_user(&mut bytes, params_ptr).is_err() { return 0; }
    let params = GetWindowRectsParams::decode(bytes);
    if params.rect == 0 { return 0; }
    let Some(rect) = crate::nt_window::rect_query::query_current(hwnd as u32, params.client != 0, params.dpi) else {
        return 0;
    };
    let fields = [rect.left, rect.top, rect.right, rect.bottom];
    let mut output = [0u8; PARAM_BYTES];
    for (index, field) in fields.into_iter().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&field.to_le_bytes());
    }
    if uaccess::copy_to_user(params.rect, &output).is_err() { return 0; }
    1
}

#[cfg(test)]
#[path = "tests/hwnd_param.rs"]
mod tests;
