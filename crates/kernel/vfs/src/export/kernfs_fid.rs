// The file handle a kernfs-backed pseudo-filesystem (cgroup2, sysfs) mints.
//
// Linux's kernfs export op encodes exactly ONE 64-bit value — the kernfs node
// id — into two `__u32` of payload, and tags it `FILEID_KERNFS`. Userspace
// depends on that width, not just on the round trip: the cgroup-id reader in
// the service manager calls `name_to_handle_at` with `handle_bytes` already set
// to `sizeof(uint64_t)` and does NOT run the grow-and-retry protocol, so an
// encoder that needs more than 8 bytes fails every caller with EOVERFLOW and
// the cgroup id becomes unreadable. The generic `(ino, generation)` FID is 12
// bytes, which is why cgroupfs cannot use it.
//
// On a 64-bit inode number the kernfs id IS the inode number (the split id —
// generation in the high half — exists only where `ino_t` is 32 bits), so the
// payload doubles as the cgroup id userspace reads out of `f_handle`, and it
// matches what `stat(2)` reports for the same directory. Decode therefore
// carries no generation: [`super::GENERATION_ANY`] is the wildcard, and the
// filesystem's own `fh_to_dentry` decides whether the id still names anything.

use syscall::errno::Errno;

use super::fid::Fid;
use super::GENERATION_ANY;

/// `FILEID_KERNFS` — `handle_type` of a kernfs node id handle.
pub const HANDLE_TYPE_KERNFS: i32 = 0xfe;
/// Encoded payload length: one u64.
pub const KERNFS_FID_LEN: u32 = 8;

/// Serialise `id` (the kernfs node id, i.e. the inode number) little-endian,
/// returning `(bytes, handle_type)`. `buf` must hold [`KERNFS_FID_LEN`].
/// # C: O(1)
pub fn encode_kernfs_fid(id: u64, buf: &mut [u8]) -> (u32, i32) {
    buf[..KERNFS_FID_LEN as usize].copy_from_slice(&id.to_le_bytes());
    (KERNFS_FID_LEN, HANDLE_TYPE_KERNFS)
}

/// Parse a kernfs payload. ESTALE for a wrong length — the same rule the
/// generic codec follows, because an undecodable-but-well-formed handle is
/// staleness, not a malformed argument.
/// # C: O(1)
pub fn decode_kernfs_fid(bytes: &[u8]) -> Result<Fid, Errno> {
    if bytes.len() != KERNFS_FID_LEN as usize { return Err(Errno::Estale); }
    let id = u64::from_le_bytes(bytes[..8].try_into().map_err(|_| Errno::Estale)?);
    Ok(Fid { ino: id, generation: GENERATION_ANY, parent: None })
}

#[cfg(test)]
#[path = "kernfs_fid/tests.rs"] mod tests;
