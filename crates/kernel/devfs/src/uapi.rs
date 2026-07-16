//! Linux character-device UAPI values owned by devfs.

pub const MEM_MAJOR: u32 = 1;
pub const MISC_MAJOR: u32 = 10;
pub const MEM_NULL: (u32, u32) = (MEM_MAJOR, 3);
pub const MEM_ZERO: (u32, u32) = (MEM_MAJOR, 5);
pub const MEM_FULL: (u32, u32) = (MEM_MAJOR, 7);
pub const MEM_RANDOM: (u32, u32) = (MEM_MAJOR, 8);
pub const MEM_URANDOM: (u32, u32) = (MEM_MAJOR, 9);
pub const MEM_KMSG: (u32, u32) = (MEM_MAJOR, 11);
pub const MISC_HWRNG: (u32, u32) = (MISC_MAJOR, 183);
pub const MISC_AUTOFS: (u32, u32) = (MISC_MAJOR, 235);
pub const DEV_MEM_NULL: u32 = 0x0103;
pub const DEV_MEM_ZERO: u32 = 0x0105;
pub const DEV_MEM_FULL: u32 = 0x0107;
pub const DEV_MEM_RANDOM: u32 = 0x0108;
pub const DEV_MEM_URANDOM: u32 = 0x0109;
pub const DEV_MEM_KMSG: u32 = 0x010b;
pub const DEV_MISC_HWRNG: u32 = 0x0ab7;
pub const DEV_MISC_AUTOFS: u32 = 0x0aec;

pub const INO_NULL: u64 = 0x2000_0001;
pub const INO_ZERO: u64 = 0x2000_0002;
pub const INO_FULL: u64 = 0x2000_0003;
pub const INO_RANDOM: u64 = 0x2000_0004;
pub const INO_HWRNG: u64 = 0x2000_0005;
pub const INO_AUTOFS: u64 = 0x2000_0006;
pub const INO_URANDOM: u64 = 0x2000_0007;
pub const INO_KMSG: u64 = 0x2000_000a;
pub const INO_STDIN: u64 = 0x2000_0010;
pub const INO_STDOUT: u64 = 0x2000_0011;
pub const INO_STDERR: u64 = 0x2000_0012;
pub const INO_FD: u64 = 0x2000_0013;
