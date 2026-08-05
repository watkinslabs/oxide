// Coredump socket request/ack wire ABI.

/// First published request and acknowledgement size.
pub const WIRE_SIZE_V0: usize = 16;
pub const WIRE_SIZE_V0_U32: u32 = WIRE_SIZE_V0 as u32;

pub const MODE_KERNEL: u64 = 1 << 0;
pub const MODE_USERSPACE: u64 = 1 << 1;
pub const MODE_REJECT: u64 = 1 << 2;
pub const MODE_WAIT: u64 = 1 << 3;
pub const MODE_PRIMARY: u64 = MODE_KERNEL | MODE_USERSPACE | MODE_REJECT;
pub const MODE_SUPPORTED: u64 = MODE_PRIMARY | MODE_WAIT;

/// Response marker sent after validating an acknowledgement.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Mark {
    RequestAck = 0,
    MinSize = 1,
    MaxSize = 2,
    Unsupported = 3,
    Conflicting = 4,
}

/// Encode the version-zero request in native UAPI byte order. # C: O(1)
pub fn request_bytes() -> [u8; WIRE_SIZE_V0] {
    let mut out = [0u8; WIRE_SIZE_V0];
    out[0..4].copy_from_slice(&WIRE_SIZE_V0_U32.to_ne_bytes());
    out[4..8].copy_from_slice(&WIRE_SIZE_V0_U32.to_ne_bytes());
    out[8..16].copy_from_slice(&MODE_SUPPORTED.to_ne_bytes());
    out
}

/// Encode one response marker in native UAPI byte order. # C: O(1)
pub fn mark_bytes(mark: Mark) -> [u8; core::mem::size_of::<u32>()] {
    (mark as u32).to_ne_bytes()
}
