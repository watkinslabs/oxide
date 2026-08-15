//! Loop-device ABI: ioctl numbers, wire structs and flag bits.
//!
//! Numbers and layouts only. Every decision taken from them lives in
//! `config`, `size` or `control`; nothing here validates, allocates or
//! mutates state.

/// Backing-file name field width, both name fields.
pub const LO_NAME_SIZE: usize = 64;
/// Encryption-key field width. The transformations that used it were removed
/// upstream; the field remains because the struct is ABI.
pub const LO_KEY_SIZE: usize = 32;

pub const LO_FLAGS_READ_ONLY: u32 = 1;
pub const LO_FLAGS_AUTOCLEAR: u32 = 4;
pub const LO_FLAGS_PARTSCAN: u32 = 8;
pub const LO_FLAGS_DIRECT_IO: u32 = 16;

/// Flags `LOOP_SET_STATUS`/`LOOP_SET_STATUS64` may turn ON.
pub const LOOP_SET_STATUS_SETTABLE_FLAGS: u32 = LO_FLAGS_AUTOCLEAR | LO_FLAGS_PARTSCAN;
/// Flags `LOOP_SET_STATUS`/`LOOP_SET_STATUS64` may turn OFF.
pub const LOOP_SET_STATUS_CLEARABLE_FLAGS: u32 = LO_FLAGS_AUTOCLEAR;
/// Flags `LOOP_CONFIGURE` accepts in its initial configuration.
pub const LOOP_CONFIGURE_SETTABLE_FLAGS: u32 =
    LO_FLAGS_READ_ONLY | LO_FLAGS_AUTOCLEAR | LO_FLAGS_PARTSCAN | LO_FLAGS_DIRECT_IO;

/// The one encryption type still accepted. Every other value is refused,
/// including the two whose transformations were removed.
pub const LO_CRYPT_NONE: u32 = 0;
pub const LO_CRYPT_XOR: u32 = 1;
pub const LO_CRYPT_CRYPTOAPI: u32 = 18;

pub const LOOP_SET_FD: u32 = 0x4C00;
pub const LOOP_CLR_FD: u32 = 0x4C01;
pub const LOOP_SET_STATUS: u32 = 0x4C02;
pub const LOOP_GET_STATUS: u32 = 0x4C03;
pub const LOOP_SET_STATUS64: u32 = 0x4C04;
pub const LOOP_GET_STATUS64: u32 = 0x4C05;
pub const LOOP_CHANGE_FD: u32 = 0x4C06;
pub const LOOP_SET_CAPACITY: u32 = 0x4C07;
pub const LOOP_SET_DIRECT_IO: u32 = 0x4C08;
pub const LOOP_SET_BLOCK_SIZE: u32 = 0x4C09;
pub const LOOP_CONFIGURE: u32 = 0x4C0A;

pub const LOOP_CTL_ADD: u32 = 0x4C80;
pub const LOOP_CTL_REMOVE: u32 = 0x4C81;
pub const LOOP_CTL_GET_FREE: u32 = 0x4C82;

/// Block-device major of `/dev/loopN`.
pub const LOOP_MAJOR: u32 = 7;
/// `/dev/loop-control` is a misc character device at this fixed minor.
pub const MISC_MAJOR: u32 = 10;
pub const LOOP_CTRL_MINOR: u32 = 237;

/// `struct loop_info64`.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LoopInfo64 {
    pub lo_device: u64,
    pub lo_inode: u64,
    pub lo_rdevice: u64,
    pub lo_offset: u64,
    pub lo_sizelimit: u64,
    pub lo_number: u32,
    pub lo_encrypt_type: u32,
    pub lo_encrypt_key_size: u32,
    pub lo_flags: u32,
    pub lo_file_name: [u8; LO_NAME_SIZE],
    pub lo_crypt_name: [u8; LO_NAME_SIZE],
    pub lo_encrypt_key: [u8; LO_KEY_SIZE],
    pub lo_init: [u64; 2],
}

impl Default for LoopInfo64 {
    fn default() -> Self {
        Self {
            lo_device: 0, lo_inode: 0, lo_rdevice: 0, lo_offset: 0, lo_sizelimit: 0,
            lo_number: 0, lo_encrypt_type: LO_CRYPT_NONE, lo_encrypt_key_size: 0, lo_flags: 0,
            lo_file_name: [0; LO_NAME_SIZE], lo_crypt_name: [0; LO_NAME_SIZE],
            lo_encrypt_key: [0; LO_KEY_SIZE], lo_init: [0; 2],
        }
    }
}

/// `struct loop_config` — the whole setup in one ioctl.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LoopConfig {
    pub fd: u32,
    pub block_size: u32,
    pub info: LoopInfo64,
    pub reserved: [u64; 8],
}

/// `struct loop_info` — the pre-64-bit layout `LOOP_SET_STATUS`/`GET_STATUS`
/// still carry. `lo_offset` and the key size are signed 32-bit there, which is
/// why the conversion to [`LoopInfo64`] is a decision and not a cast.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LoopInfo {
    pub lo_number: i32,
    pub lo_device: u64,
    pub lo_inode: u64,
    pub lo_rdevice: u64,
    pub lo_offset: i32,
    pub lo_encrypt_type: i32,
    pub lo_encrypt_key_size: i32,
    pub lo_flags: i32,
    pub lo_name: [u8; LO_NAME_SIZE],
    pub lo_encrypt_key: [u8; LO_KEY_SIZE],
    pub lo_init: [u64; 2],
    pub reserved: [u8; 4],
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The settable/clearable masks are subsets of the flags that exist, and
    /// the configure mask is the widest of the three. A mask naming a bit no
    /// flag defines would let a value through that nothing consumes.
    #[test]
    fn flag_masks_are_subsets_of_the_defined_flags() {
        const ALL: u32 = LO_FLAGS_READ_ONLY | LO_FLAGS_AUTOCLEAR | LO_FLAGS_PARTSCAN | LO_FLAGS_DIRECT_IO;
        assert_eq!(LOOP_SET_STATUS_SETTABLE_FLAGS & !ALL, 0);
        assert_eq!(LOOP_SET_STATUS_CLEARABLE_FLAGS & !LOOP_SET_STATUS_SETTABLE_FLAGS, 0);
        assert_eq!(LOOP_CONFIGURE_SETTABLE_FLAGS, ALL);
    }

    /// Read-only is not settable through `SET_STATUS`: the reference fixes it
    /// at bind time from the backing file's own access mode.
    #[test]
    fn read_only_cannot_be_flipped_by_set_status() {
        assert_eq!(LOOP_SET_STATUS_SETTABLE_FLAGS & LO_FLAGS_READ_ONLY, 0);
        assert_eq!(LOOP_SET_STATUS_CLEARABLE_FLAGS & LO_FLAGS_READ_ONLY, 0);
    }

    /// Wire sizes are ABI. A field added or widened here silently changes what
    /// `losetup` reads back.
    #[test]
    fn wire_structs_have_their_abi_sizes() {
        assert_eq!(core::mem::size_of::<LoopInfo64>(), 232);
        assert_eq!(core::mem::size_of::<LoopConfig>(), 8 + 232 + 64);
    }

    /// The device ioctls occupy one contiguous command block and the control
    /// ioctls another, so a dispatcher can range-check before decoding.
    #[test]
    fn ioctl_numbers_form_two_blocks() {
        for (i, cmd) in [LOOP_SET_FD, LOOP_CLR_FD, LOOP_SET_STATUS, LOOP_GET_STATUS,
                         LOOP_SET_STATUS64, LOOP_GET_STATUS64, LOOP_CHANGE_FD,
                         LOOP_SET_CAPACITY, LOOP_SET_DIRECT_IO, LOOP_SET_BLOCK_SIZE,
                         LOOP_CONFIGURE].into_iter().enumerate() {
            assert_eq!(cmd, 0x4C00 + i as u32);
        }
        for (i, cmd) in [LOOP_CTL_ADD, LOOP_CTL_REMOVE, LOOP_CTL_GET_FREE].into_iter().enumerate() {
            assert_eq!(cmd, 0x4C80 + i as u32);
        }
    }
}
