// `union bpf_attr` extensible-struct size protocol and the per-command
// zero-tail check every command runs before anything else.

use syscall::errno::Errno;

use super::super::uapi;

/// Zero-filled staging copy of `union bpf_attr`. `__sys_bpf()` memsets
/// its on-stack union then copies only `min(size, sizeof(attr))` bytes,
/// so short attrs read as zeros rather than as EINVAL.
#[derive(Copy, Clone)]
pub struct Attr { pub bytes: [u8; uapi::ATTR_SIZE] }

impl Attr {
    pub const fn zeroed() -> Self { Attr { bytes: [0u8; uapi::ATTR_SIZE] } }
    /// # C: O(1)
    pub fn u32_at(&self, off: usize) -> u32 {
        u32::from_ne_bytes([self.bytes[off], self.bytes[off + 1], self.bytes[off + 2], self.bytes[off + 3]])
    }
    /// # C: O(1)
    pub fn u64_at(&self, off: usize) -> u64 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.bytes[off..off + 8]);
        u64::from_ne_bytes(b)
    }
    /// # C: O(ATTR_SIZE - from)
    pub fn tail_is_zero(&self, from: usize) -> bool {
        from >= uapi::ATTR_SIZE || self.bytes[from..].iter().all(|b| *b == 0)
    }
}

/// Size-protocol arithmetic for the extensible `union bpf_attr`. Returns
/// `(copy_len, tail_len)`: copy `copy_len` bytes into a zeroed [`Attr`],
/// and require the `tail_len` bytes past `ATTR_SIZE` to be all zero.
/// `-E2BIG` for a "silly large" size, checked *before* any capability or
/// per-command check. # C: O(1)
pub fn size_protocol(size: u32) -> Result<(usize, usize), Errno> {
    let actual = size as usize;
    if actual > uapi::ATTR_MAX_USER_SIZE { return Err(Errno::E2big); }
    let copy = if actual < uapi::ATTR_SIZE { actual } else { uapi::ATTR_SIZE };
    Ok((copy, actual - copy))
}

/// Verdict for the trailing bytes past `sizeof(union bpf_attr)`:
/// non-zero means userspace asked for a field this kernel does not
/// know → `-E2BIG`. # C: O(1)
pub fn tail_verdict(all_zero: bool) -> Result<(), Errno> {
    if all_zero { Ok(()) } else { Err(Errno::E2big) }
}

/// Every byte past the command's last field must be zero, else `-EINVAL`.
/// # C: O(ATTR_SIZE)
pub fn check_attr(a: &Attr, last_end: usize) -> Result<(), Errno> {
    if a.tail_is_zero(last_end) { Ok(()) } else { Err(Errno::Einval) }
}

/// Command dispatch reach: commands actually implemented vs the
/// `default: -EINVAL` arm. A command number at or above the known-command
/// count is `-EINVAL`. # C: O(1)
pub fn cmd_is_known(cmd: u32) -> bool { cmd < uapi::cmd::MAX }
