//! Messages whose parameters carry pointers, which a posted message cannot
//! marshal. The bitmap is indexed by message number, thirty-two per word, and
//! covers messages below `MESSAGE_LIMIT`; anything above is not a pointer message.

/// One bit per message; word `n` covers messages `32n..32n+32`.
const POINTER_FLAGS: [u32; 25] = [
    0x0c00_3002, 0x0200_3810, 0x0008_04c0, 0x3000_0000, 0x0000_008a,
    0x001d_0000, 0x0000_0814, 0x0000_0e08, 0x0000_0000, 0x0000_0000,
    0x0104_3529, 0x0000_0010, 0x0146_b203, 0x0000_0004, 0x0000_0000,
    0x0000_0000, 0x0258_0000, 0x0000_ee01, 0x0000_0000, 0x0000_0000,
    0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_1000,
];
/// Messages at or above this number are never pointer messages.
pub(crate) const MESSAGE_LIMIT: u32 = (POINTER_FLAGS.len() as u32) * 32;
/// A device-change notification carries a pointer only with this wparam bit set.
const WM_DEVICECHANGE: u32 = 0x0219;
const DBT_POINTER_PAYLOAD: u64 = 0x8000;

/// # C: O(1)
pub(crate) const fn is_pointer_message(message: u32, wparam: u64) -> bool {
    if message >= MESSAGE_LIMIT { return false; }
    if message == WM_DEVICECHANGE && wparam & DBT_POINTER_PAYLOAD == 0 { return false; }
    POINTER_FLAGS[(message / 32) as usize] & (1 << (message % 32)) != 0
}

#[cfg(test)]
#[path = "../tests/queue_pointer.rs"]
mod tests;
