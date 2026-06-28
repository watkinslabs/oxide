// statfs shared helpers — used by ≥2 statfs handlers (docs/53 §0).
//
// `f_type`/`f_bsize`/usage now derive from the mounted-instance SuperBlock
// (`vfs::mount::resolve_mount(path).sb().statfs()`), the Linux source of
// truth — NOT a hardcoded path-prefix magic table. Every production mount
// carries a real `SuperBlock` (built by `SuperBlock::for_backend` in the
// mount engine), so the `s_magic`/`s_op::statfs` reported here is the
// instance's own identity.

#![cfg(target_os = "oxide-kernel")]

use vfs::SbStatFs;

// struct statfs `f_type` magic for the on-disk rootfs (linux/magic.h) — the
// usage-shape fallback for a fs whose `SuperOps::statfs` reports no block
// accounting yet. Real per-fs accounting layers on via per-fs `SuperOps`.
pub(crate) const M_EXT4: u64 = 0xEF53;
// tmpfs magic — the reported fs for an anon/pathless fd whose dentry name is
// not an absolute path (memfd, pipe-like) and supplies no `statfs_magic`.
pub(crate) const M_TMPFS: u64 = 0x0102_1994;

/// `kstatfs` for the filesystem backing absolute `path`, read from that
/// mount's SuperBlock (`s_magic` → `f_type`, `s_blocksize` → `f_bsize`,
/// `SuperOps::statfs` → usage). `resolve_mount` returns the owning mount by
/// dentry-identity crossing (root mount for paths not under a distinct
/// mount), so there is no path-prefix guesswork. # C: O(N_mounts)
pub(crate) fn statfs_for_path(path: &str) -> SbStatFs {
    let mut st = vfs::mount::resolve_mount(path)
        .and_then(|(m, _)| m.sb().statfs().ok())
        .unwrap_or_default();
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
    // SAFETY: caller validated 120-byte user buf < USER_VA_END, 8-aligned; CPL=0 writes through caller's AS.
    unsafe {
        for off in (0..120u64).step_by(8) {
            core::ptr::write_volatile((buf + off) as *mut u64, 0);
        }
        core::ptr::write_volatile( buf        as *mut u64, st.f_type);          // f_type   @0
        core::ptr::write_volatile((buf +  8)  as *mut u64, st.f_bsize as u64);  // f_bsize  @8
        core::ptr::write_volatile((buf + 16)  as *mut u64, st.f_blocks);        // f_blocks @16
        core::ptr::write_volatile((buf + 24)  as *mut u64, st.f_bfree);         // f_bfree  @24
        core::ptr::write_volatile((buf + 32)  as *mut u64, st.f_bavail);        // f_bavail @32
        core::ptr::write_volatile((buf + 40)  as *mut u64, st.f_files);         // f_files  @40
        core::ptr::write_volatile((buf + 48)  as *mut u64, st.f_ffree);         // f_ffree  @48
        core::ptr::write_volatile((buf + 56)  as *mut u64, st.f_fsid);          // f_fsid   @56 (__fsid_t)
        core::ptr::write_volatile((buf + 64)  as *mut u64, 255);                // f_namelen@64 (NAME_MAX)
        core::ptr::write_volatile((buf + 72)  as *mut u64, st.f_bsize as u64);  // f_frsize @72
    }
}
