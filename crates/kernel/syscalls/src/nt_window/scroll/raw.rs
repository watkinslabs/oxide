//! Raw NtUser scroll ABI.  This layer only decodes fixed-width arguments;
//! live state mutation remains in `live.rs`.

pub(crate) const GET_SCROLL_INFO_METHOD: u32 = 7;
pub(crate) const HWND_PARAM_ORDINAL: u64 = 0x1336;
pub(crate) const SET_SCROLL_INFO_ORDINAL: u64 = 0x1581;
pub(crate) const SBM_SETSCROLLINFO: u32 = 0x00e9;
pub(crate) const GET_PARAMS_BYTES: usize = 16;
pub(crate) const SCROLLINFO_BYTES: usize = 28;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct GetScrollInfoParams { pub bar: i32, pub info: u64 }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct SetScrollInfoArgs { pub hwnd: u64, pub bar: i32, pub info: u64, pub redraw: bool }

impl SetScrollInfoArgs {
    pub(crate) const fn decode(args: [u64; 4]) -> Self {
        Self { hwnd: args[0], bar: args[1] as i32, info: args[2], redraw: args[3] != 0 }
    }
}

impl GetScrollInfoParams {
    pub(crate) fn decode(bytes: [u8; GET_PARAMS_BYTES]) -> Self {
        Self { bar: i32::from_le_bytes(bytes[0..4].try_into().unwrap()), info: u64::from_le_bytes(bytes[8..16].try_into().unwrap()) }
    }

    pub(crate) fn encode(self) -> [u8; GET_PARAMS_BYTES] {
        let mut bytes = [0; GET_PARAMS_BYTES];
        bytes[0..4].copy_from_slice(&self.bar.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.info.to_le_bytes());
        bytes
    }
}

pub(crate) fn decode_scroll_info(bytes: [u8; SCROLLINFO_BYTES]) -> ipc::win32_window::ScrollInfo {
    ipc::win32_window::ScrollInfo {
        cb_size: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        mask: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
        min: i32::from_le_bytes(bytes[8..12].try_into().unwrap()),
        max: i32::from_le_bytes(bytes[12..16].try_into().unwrap()),
        page: u32::from_le_bytes(bytes[16..20].try_into().unwrap()),
        pos: i32::from_le_bytes(bytes[20..24].try_into().unwrap()),
        track_pos: i32::from_le_bytes(bytes[24..28].try_into().unwrap()),
    }
}

pub(crate) fn encode_scroll_info(info: ipc::win32_window::ScrollInfo) -> [u8; SCROLLINFO_BYTES] {
    let mut bytes = [0; SCROLLINFO_BYTES];
    bytes[0..4].copy_from_slice(&info.cb_size.to_le_bytes());
    bytes[4..8].copy_from_slice(&info.mask.to_le_bytes());
    bytes[8..12].copy_from_slice(&info.min.to_le_bytes());
    bytes[12..16].copy_from_slice(&info.max.to_le_bytes());
    bytes[16..20].copy_from_slice(&info.page.to_le_bytes());
    bytes[20..24].copy_from_slice(&info.pos.to_le_bytes());
    bytes[24..28].copy_from_slice(&info.track_pos.to_le_bytes());
    bytes
}
