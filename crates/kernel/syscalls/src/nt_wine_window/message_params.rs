//! Native user32 dispatch parameter layout and publish-last HWND readiness.
pub(crate) const BYTES: usize = 72;
const HWND_OFFSET: usize = 8;
pub(crate) const SEND_MESSAGE: u64 = 0x02b1;
pub(crate) const GET_DISPATCH_PARAMS: u64 = 0x3001;
pub(crate) const MAP_SEND: u32 = 1;
pub(crate) const MAP_DISPATCH: u32 = 4;

#[derive(Clone, Copy)]
pub(crate) struct Params {
    pub procedure: u64, pub hwnd: u64, pub message: u32, pub wparam: u64,
    pub lparam: u64, pub ansi: bool, pub ansi_dst: bool, pub mapping: u32,
    pub dpi_context: u32,
}

pub(crate) fn encode(params: Params) -> [u8; BYTES] {
    let mut bytes = [0; BYTES];
    for (offset, value) in [(0, params.procedure), (HWND_OFFSET, params.hwnd),
        (24, params.wparam), (32, params.lparam), (56, params.procedure), (64, params.procedure)] {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    for (offset, value) in [(16, params.message), (40, params.ansi as u32),
        (44, params.ansi_dst as u32), (48, params.mapping), (52, params.dpi_context)] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

pub(crate) fn publish(pointer: u64, params: Params, mut write: impl FnMut(u64, &[u8]) -> bool) -> bool {
    if pointer == 0 || pointer.checked_add(BYTES as u64).is_none() { return false; }
    let bytes = encode(params);
    write(pointer + HWND_OFFSET as u64, &[0; 8]) && write(pointer, &bytes[..HWND_OFFSET]) &&
        write(pointer + 16, &bytes[16..]) && write(pointer + HWND_OFFSET as u64, &bytes[HWND_OFFSET..16])
}

#[cfg(test)]
#[path = "tests/message_params.rs"]
mod tests;
