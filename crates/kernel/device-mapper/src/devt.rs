//! Device-number packing for dependency and status replies.

/// Pack a device number in Linux's large `dev_t` representation. # C: O(1)
pub fn pack(major: u32, minor: u32) -> u64 { vfs::huge_encode_dev(vfs::mkdev(major, minor)) }
