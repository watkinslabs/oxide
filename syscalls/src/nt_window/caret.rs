//! Raw caret syscall ABI constants and argument codecs. Main owns wiring.

pub const CREATE_CARET_ORDINAL: u64 = 0x1360;
pub const DESTROY_CARET_ORDINAL: u64 = 0x137e;
pub const HIDE_CARET_ORDINAL: u64 = 0x146c;
pub const SET_CARET_POS_ORDINAL: u64 = 0x153c;
pub const SHOW_CARET_ORDINAL: u64 = 0x15b7;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CaretPos { pub x: i32, pub y: i32 }

impl CaretPos {
    pub fn decode(bytes: [u8; 8]) -> Self { Self { x: i32::from_le_bytes(bytes[0..4].try_into().unwrap()), y: i32::from_le_bytes(bytes[4..8].try_into().unwrap()) } }
    pub fn encode(self) -> [u8; 8] { let mut bytes = [0; 8]; bytes[0..4].copy_from_slice(&self.x.to_le_bytes()); bytes[4..8].copy_from_slice(&self.y.to_le_bytes()); bytes }
}

#[cfg(test)]
#[path = "tests/caret.rs"]
mod tests;
