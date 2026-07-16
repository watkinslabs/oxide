// statfs shared helpers — used by ≥2 statfs handlers (docs/53 §0).
//
// `f_type`/`f_bsize`/usage derive from the resolved mounted-instance
// SuperBlock, the Linux source of truth — NOT a hardcoded path-prefix magic
// table. Every production mount carries a real filled `SuperBlock`, so the `s_magic`/
// `s_op::statfs` reported here is the instance's own identity.

#![cfg(target_os = "oxide-kernel")]

use vfs::SbStatFs;

// struct statfs `f_type` magic for the on-disk rootfs (linux/magic.h) — the
// usage-shape default for a fs whose `SuperOps::statfs` reports no block
// accounting yet. Real per-fs accounting layers on via per-fs `SuperOps`.
pub(crate) const M_EXT4: u64 = ext4::superblock::EXT4_SUPER_MAGIC as u64;
// tmpfs magic — the reported fs for an anon/pathless fd whose dentry name is
// not an absolute path (memfd, pipe-like) and supplies no `statfs_magic`.
pub(crate) const M_TMPFS: u64 = vfs::uapi::TMPFS_SUPER_MAGIC;

// statvfs(3) `ST_*` mount flags (sys/statvfs.h) reported in statfs `f_flags`.
// These are a SEPARATE bit-space from the kernel `MNT_*`/`SB_*` bits and are
// mapped BY NAME below (e.g. `MNT_RELATIME`=1<<21 → `ST_RELATIME`=1<<12 — same
// concept, different bit), exactly as Linux `calculate_f_flags` does.
const ST_RDONLY:      u64 = 1;
const ST_NOSUID:      u64 = 2;
const ST_NODEV:       u64 = 4;
const ST_NOEXEC:      u64 = 8;
const ST_SYNCHRONOUS: u64 = 16;
const ST_MANDLOCK:    u64 = 64;
const ST_NOATIME:     u64 = 1024;
const ST_NODIRATIME:  u64 = 2048;
const ST_RELATIME:    u64 = 4096;

/// Map per-mount `MNT_*` bits + superblock `SB_*` bits to statvfs `ST_*`
/// (Linux `calculate_f_flags` = `flags_by_mnt` | `flags_by_sb`). Bit-for-bit
/// name mapping — never a raw integer copy. # C: O(1)
fn st_flags(mnt: u64, sb: u64) -> u64 {
    use vfs::mount::{MNT_NOATIME, MNT_NODEV, MNT_NODIRATIME, MNT_NOEXEC, MNT_NOSUID, MNT_RDONLY, MNT_RELATIME};
    use vfs::superblock::{SB_MANDLOCK, SB_RDONLY, SB_SYNCHRONOUS};
    let mut f = 0u64;
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

/// `kstatfs` read directly from a known owning `Mount` (its `SuperBlock` +
/// per-mount `MNT_*` flags). Used by `fstatfs` to report the fd's real backing
/// mount/superblock rather than re-classifying by the dentry name string. # C: O(1)
pub(crate) fn statfs_for_mount(m: &vfs::mount::Mount) -> SbStatFs {
    let mut st = SbStatFs::default();
    if let Ok(s) = m.sb().statfs() { st = s; }
    // `f_flags` is the per-MOUNT statvfs `ST_*` view (Linux `calculate_f_flags`),
    // not an `s_op->statfs` output.
    st.f_flags = st_flags(m.flags(), m.sb().s_flags());
    fill_usage(&mut st);
    st
}

/// `kstatfs` for an anonymous/pathless inode that supplies its own
/// superblock magic via `Inode::statfs_magic` (pidfd, eventfd-like). # C: O(1)
pub(crate) fn statfs_for_magic(magic: u64) -> SbStatFs {
    let mut st = SbStatFs { f_type: magic, ..Default::default() };
    fill_usage(&mut st);
    st
}

/// Default the block-accounting + bsize fields so `df` keeps the row (df
/// drops entries with `f_blocks == 0`). Real per-fs `SuperOps::statfs`
/// accounting (ext4 on-disk superblock counts) overrides these once wired.
/// # C: O(1)
fn fill_usage(st: &mut SbStatFs) {
    if st.f_bsize == 0 { st.f_bsize = 4096; }
    if st.f_blocks == 0 {
        if st.f_type == M_EXT4 {
            // 32 MiB rootfs image (xtask builder); half-free is plausible
            // until real on-disk accounting lands in ext4's `SuperOps`.
            st.f_blocks = 8192; st.f_bfree = 4096; st.f_bavail = 4096;
            st.f_files = 8192;  st.f_ffree = 4096;
        } else {
            st.f_blocks = 1; st.f_bfree = 0; st.f_bavail = 0;
            st.f_files = 1;  st.f_ffree = 0;
        }
    }
}

/// Fill a 120-byte `struct statfs` (identical LP64 layout on x86_64 and
/// aarch64) from a `SbStatFs`. # C: O(1)
pub(crate) fn write_statfs(buf: u64, st: &SbStatFs) {
    // SAFETY: caller validated the full 120-byte user output span as writable.
    unsafe {
        for off in (0..120u64).step_by(8) {
            core::ptr::write_unaligned((buf + off) as *mut u64, 0);
        }
        core::ptr::write_unaligned( buf        as *mut u64, st.f_type);          // f_type   @0
        core::ptr::write_unaligned((buf +  8)  as *mut u64, st.f_bsize as u64);  // f_bsize  @8
        core::ptr::write_unaligned((buf + 16)  as *mut u64, st.f_blocks);        // f_blocks @16
        core::ptr::write_unaligned((buf + 24)  as *mut u64, st.f_bfree);         // f_bfree  @24
        core::ptr::write_unaligned((buf + 32)  as *mut u64, st.f_bavail);        // f_bavail @32
        core::ptr::write_unaligned((buf + 40)  as *mut u64, st.f_files);         // f_files  @40
        core::ptr::write_unaligned((buf + 48)  as *mut u64, st.f_ffree);         // f_ffree  @48
        core::ptr::write_unaligned((buf + 56)  as *mut u64, st.f_fsid);          // f_fsid   @56 (__fsid_t)
        core::ptr::write_unaligned((buf + 64)  as *mut u64, 255);                // f_namelen@64 (NAME_MAX)
        core::ptr::write_unaligned((buf + 72)  as *mut u64, st.f_bsize as u64);  // f_frsize @72
        core::ptr::write_unaligned((buf + 80)  as *mut u64, st.f_flags);         // f_flags  @80 (ST_*)
    }
}
