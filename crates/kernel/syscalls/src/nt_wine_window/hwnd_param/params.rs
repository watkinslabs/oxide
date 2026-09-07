//! Parameter records the client passes behind one pointer, decoded from their
//! frozen layouts. Trailing padding is part of the layout: a field read from a
//! padding offset reads whatever the client left there.

/// `{ RECT *rect; UINT dpi; }`, padded to pointer alignment.
pub(crate) const WINDOW_RECTS_BYTES: usize = 16;
/// `{ HWND hwnd_to; POINT *points; UINT count; UINT dpi; }`.
pub(crate) const MAP_POINTS_BYTES: usize = 24;
/// `{ UINT offset; UINT size; }`.
pub(crate) const GET_PRIVATE_BYTES: usize = 8;
/// `{ UINT offset; UINT size; LONG64 value; }`.
pub(crate) const SET_PRIVATE_BYTES: usize = 16;
/// `{ UINT flags; BOOL whole; RECT rect; }`.
pub(crate) const EXPOSE_BYTES: usize = 24;
/// `{ RECT rect; UINT flags; BOOL internal; }`.
pub(crate) const RAW_WINDOW_POS_BYTES: usize = 24;
/// `{ UINT flags; const INPUT *input; LPARAM lparam; }`, the pointer pair
/// following the flags word's alignment padding.
pub(crate) const HARDWARE_INPUT_BYTES: usize = 24;
/// A `RECT` is four 32-bit edges.
pub(crate) const RECT_BYTES: usize = 16;
/// A `POINT` is two 32-bit coordinates.
pub(crate) const POINT_BYTES: usize = 8;

fn u32_at(bytes: &[u8], offset: usize) -> u32 { u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) }
fn u64_at(bytes: &[u8], offset: usize) -> u64 { u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()) }
fn i32_at(bytes: &[u8], offset: usize) -> i32 { i32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) }

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Rect { pub left: i32, pub top: i32, pub right: i32, pub bottom: i32 }

impl Rect {
    /// # C: O(1)
    pub(crate) fn decode(bytes: &[u8]) -> Self {
        Self { left: i32_at(bytes, 0), top: i32_at(bytes, 4), right: i32_at(bytes, 8), bottom: i32_at(bytes, 12) }
    }
    /// # C: O(1)
    pub(crate) fn encode(self) -> [u8; RECT_BYTES] {
        let mut out = [0u8; RECT_BYTES];
        for (index, field) in [self.left, self.top, self.right, self.bottom].into_iter().enumerate() {
            out[index * 4..index * 4 + 4].copy_from_slice(&field.to_le_bytes());
        }
        out
    }
}

/// The rectangle queries' shared parameter record. The dpi word is the only
/// field beside the destination pointer: which rectangle is wanted is the
/// method, never a flag inside this record.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct WindowRects { pub rect: u64, pub dpi: u32 }

impl WindowRects {
    /// # C: O(1)
    pub(crate) fn decode(bytes: [u8; WINDOW_RECTS_BYTES]) -> Self { Self { rect: u64_at(&bytes, 0), dpi: u32_at(&bytes, 8) } }
    /// # C: O(1)
    pub(crate) fn encode(self) -> [u8; WINDOW_RECTS_BYTES] {
        let mut out = [0u8; WINDOW_RECTS_BYTES];
        out[0..8].copy_from_slice(&self.rect.to_le_bytes());
        out[8..12].copy_from_slice(&self.dpi.to_le_bytes());
        out
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct MapPoints { pub hwnd_to: u64, pub points: u64, pub count: u32, pub dpi: u32 }

impl MapPoints {
    /// # C: O(1)
    pub(crate) fn decode(bytes: [u8; MAP_POINTS_BYTES]) -> Self {
        Self { hwnd_to: u64_at(&bytes, 0), points: u64_at(&bytes, 8), count: u32_at(&bytes, 16), dpi: u32_at(&bytes, 20) }
    }
    /// # C: O(1)
    pub(crate) fn encode(self) -> [u8; MAP_POINTS_BYTES] {
        let mut out = [0u8; MAP_POINTS_BYTES];
        out[0..8].copy_from_slice(&self.hwnd_to.to_le_bytes());
        out[8..16].copy_from_slice(&self.points.to_le_bytes());
        out[16..20].copy_from_slice(&self.count.to_le_bytes());
        out[20..24].copy_from_slice(&self.dpi.to_le_bytes());
        out
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PrivateData { pub offset: u32, pub size: u32, pub value: u64 }

impl PrivateData {
    /// # C: O(1)
    pub(crate) fn decode_get(bytes: [u8; GET_PRIVATE_BYTES]) -> Self {
        Self { offset: u32_at(&bytes, 0), size: u32_at(&bytes, 4), value: 0 }
    }
    /// # C: O(1)
    pub(crate) fn decode_set(bytes: [u8; SET_PRIVATE_BYTES]) -> Self {
        Self { offset: u32_at(&bytes, 0), size: u32_at(&bytes, 4), value: u64_at(&bytes, 8) }
    }
    /// # C: O(1)
    pub(crate) fn encode_set(self) -> [u8; SET_PRIVATE_BYTES] {
        let mut out = [0u8; SET_PRIVATE_BYTES];
        out[0..4].copy_from_slice(&self.offset.to_le_bytes());
        out[4..8].copy_from_slice(&self.size.to_le_bytes());
        out[8..16].copy_from_slice(&self.value.to_le_bytes());
        out
    }
}

/// A whole-surface exposure carries no rectangle; the record's own rectangle
/// field is then unread.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Expose { pub flags: u32, pub whole: bool, pub rect: Rect }

impl Expose {
    /// # C: O(1)
    pub(crate) fn decode(bytes: [u8; EXPOSE_BYTES]) -> Self {
        Self { flags: u32_at(&bytes, 0), whole: u32_at(&bytes, 4) != 0, rect: Rect::decode(&bytes[8..24]) }
    }
    /// # C: O(1)
    pub(crate) fn encode(self) -> [u8; EXPOSE_BYTES] {
        let mut out = [0u8; EXPOSE_BYTES];
        out[0..4].copy_from_slice(&self.flags.to_le_bytes());
        out[4..8].copy_from_slice(&u32::from(self.whole).to_le_bytes());
        out[8..24].copy_from_slice(&self.rect.encode());
        out
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RawWindowPos { pub rect: Rect, pub flags: u32, pub internal: bool }

impl RawWindowPos {
    /// # C: O(1)
    pub(crate) fn decode(bytes: [u8; RAW_WINDOW_POS_BYTES]) -> Self {
        Self { rect: Rect::decode(&bytes[0..16]), flags: u32_at(&bytes, 16), internal: u32_at(&bytes, 20) != 0 }
    }
    /// # C: O(1)
    pub(crate) fn encode(self) -> [u8; RAW_WINDOW_POS_BYTES] {
        let mut out = [0u8; RAW_WINDOW_POS_BYTES];
        out[0..16].copy_from_slice(&self.rect.encode());
        out[16..20].copy_from_slice(&self.flags.to_le_bytes());
        out[20..24].copy_from_slice(&u32::from(self.internal).to_le_bytes());
        out
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct HardwareInput { pub flags: u32, pub input: u64, pub lparam: u64 }

impl HardwareInput {
    /// # C: O(1)
    pub(crate) fn decode(bytes: [u8; HARDWARE_INPUT_BYTES]) -> Self {
        Self { flags: u32_at(&bytes, 0), input: u64_at(&bytes, 8), lparam: u64_at(&bytes, 16) }
    }
    /// # C: O(1)
    pub(crate) fn encode(self) -> [u8; HARDWARE_INPUT_BYTES] {
        let mut out = [0u8; HARDWARE_INPUT_BYTES];
        out[0..4].copy_from_slice(&self.flags.to_le_bytes());
        out[8..16].copy_from_slice(&self.input.to_le_bytes());
        out[16..24].copy_from_slice(&self.lparam.to_le_bytes());
        out
    }
}

#[cfg(test)]
#[path = "tests/params.rs"]
mod tests;
