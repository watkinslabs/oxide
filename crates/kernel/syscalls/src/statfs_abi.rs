// statfs(2) wire ABI — `struct statfs` encoding + the kernel-flag → statvfs
// `ST_*` mapping. Pure logic, no user-memory access and no target gate, so the
// layout and the flag mapping are hosted-testable (`docs/53` §0: the shim owns
// encode, the subsystem owns the values).

use vfs::SbStatFs;

/// `sizeof(struct statfs)` — identical LP64 layout on x86_64 and aarch64
/// (`include/uapi/asm-generic/statfs.h`; x86_64's `asm/statfs.h` keeps the
/// generic definition for the 64-bit ABI): 11 `__kernel_long_t` fields, a
/// 2×`int` `__kernel_fsid_t`, and `f_spare[4]`.
pub const STATFS_BYTES: usize = 120;

/// Field byte offsets in `struct statfs` (LP64).
pub const OFF_TYPE:    usize = 0;
pub const OFF_BSIZE:   usize = 8;
pub const OFF_BLOCKS:  usize = 16;
pub const OFF_BFREE:   usize = 24;
pub const OFF_BAVAIL:  usize = 32;
pub const OFF_FILES:   usize = 40;
pub const OFF_FFREE:   usize = 48;
pub const OFF_FSID:    usize = 56;
pub const OFF_NAMELEN: usize = 64;
pub const OFF_FRSIZE:  usize = 72;
pub const OFF_FLAGS:   usize = 80;
/// `f_spare[4]` — always zero, the tail Linux `memset`s.
pub const OFF_SPARE:   usize = 88;

// statvfs(3) `ST_*` mount flags (sys/statvfs.h) reported in statfs `f_flags`.
// These are a SEPARATE bit-space from the kernel `MNT_*`/`SB_*` bits and are
// mapped BY NAME below (e.g. `MNT_RELATIME`=1<<21 → `ST_RELATIME`=1<<12 — same
// concept, different bit), exactly as Linux `calculate_f_flags` does.
pub const ST_RDONLY:      u64 = 1;
pub const ST_NOSUID:      u64 = 2;
pub const ST_NODEV:       u64 = 4;
pub const ST_NOEXEC:      u64 = 8;
pub const ST_SYNCHRONOUS: u64 = 0x0010;
/// `ST_VALID` — "f_flags support is implemented". Linux `calculate_f_flags`
/// sets it UNCONDITIONALLY, and glibc's `statvfs` reads it to decide whether
/// `f_flags` carries meaning at all; omitting it makes every mount look like a
/// kernel too old to report mount flags.
pub const ST_VALID:       u64 = 0x0020;
pub const ST_MANDLOCK:    u64 = 0x0040;
pub const ST_NOATIME:     u64 = 0x0400;
pub const ST_NODIRATIME:  u64 = 0x0800;
pub const ST_RELATIME:    u64 = 0x1000;
pub const ST_NOSYMFOLLOW: u64 = 0x2000;

/// Map per-mount `MNT_*` bits + superblock `SB_*` bits to statvfs `ST_*`
/// (Linux `calculate_f_flags` = `flags_by_mnt` | `flags_by_sb`). Bit-for-bit
/// name mapping — never a raw integer copy. # C: O(1)
pub fn st_flags(mnt: u64, sb: u64) -> u64 {
    use vfs::mount::{MNT_NOATIME, MNT_NODEV, MNT_NODIRATIME, MNT_NOEXEC, MNT_NOSUID, MNT_NOSYMFOLLOW, MNT_RDONLY, MNT_RELATIME};
    use vfs::superblock::{SB_MANDLOCK, SB_RDONLY, SB_SYNCHRONOUS};
    // `calculate_f_flags` starts from ST_VALID, unconditionally.
    let mut f = ST_VALID;
    if mnt & MNT_NOSYMFOLLOW != 0 { f |= ST_NOSYMFOLLOW; }
    if mnt & MNT_RDONLY     != 0 { f |= ST_RDONLY; }
    if mnt & MNT_NOSUID     != 0 { f |= ST_NOSUID; }
    if mnt & MNT_NODEV      != 0 { f |= ST_NODEV; }
    if mnt & MNT_NOEXEC     != 0 { f |= ST_NOEXEC; }
    if mnt & MNT_NOATIME    != 0 { f |= ST_NOATIME; }
    if mnt & MNT_NODIRATIME != 0 { f |= ST_NODIRATIME; }
    if mnt & MNT_RELATIME   != 0 { f |= ST_RELATIME; }
    if sb  & SB_SYNCHRONOUS != 0 { f |= ST_SYNCHRONOUS; }
    if sb  & SB_MANDLOCK    != 0 { f |= ST_MANDLOCK; }
    if sb  & SB_RDONLY      != 0 { f |= ST_RDONLY; }
    f
}

/// Encode one `kstatfs` into the `struct statfs` wire image the caller copies
/// out. Every field carries the backend's own value — no synthetic capacity is
/// substituted for a zero count, because Linux reports zeros for a filesystem
/// that has no block accounting. # C: O(1)
pub fn encode_statfs(st: &SbStatFs) -> [u8; STATFS_BYTES] {
    let mut b = [0u8; STATFS_BYTES];
    let mut put = |off: usize, v: u64| b[off..off + 8].copy_from_slice(&v.to_le_bytes());
    put(OFF_TYPE,    st.f_type);
    put(OFF_BSIZE,   st.f_bsize as u64);
    put(OFF_BLOCKS,  st.f_blocks);
    put(OFF_BFREE,   st.f_bfree);
    put(OFF_BAVAIL,  st.f_bavail);
    put(OFF_FILES,   st.f_files);
    put(OFF_FFREE,   st.f_ffree);
    put(OFF_FSID,    st.f_fsid);
    put(OFF_NAMELEN, st.f_namelen);
    put(OFF_FRSIZE,  st.f_frsize as u64);
    put(OFF_FLAGS,   st.f_flags);
    b
}

#[cfg(test)]
#[path = "statfs_abi/tests.rs"]
mod tests;
