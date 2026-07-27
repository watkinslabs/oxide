// statfs shared helpers — used by ≥2 statfs handlers (docs/53 §0).
//
// `f_type`/`f_bsize`/usage derive from the resolved mounted-instance
// SuperBlock, the Linux source of truth — NOT a hardcoded path-prefix magic
// table. Every production mount carries a real filled `SuperBlock`, so the `s_magic`/
// `s_op::statfs` reported here is the instance's own identity.
//
// The ABI encoder lives in `statfs_abi`, which is hosted-testable.

#![cfg(target_os = "oxide-kernel")]

use vfs::SbStatFs;

pub(crate) use crate::statfs_abi::STATFS_BYTES;

/// Copy the encoded `struct statfs` image into the caller's validated buffer.
/// # C: O(1)
pub(crate) fn write_statfs(buf: u64, st: &SbStatFs) {
    let img = crate::statfs_abi::encode_statfs(st);
    // SAFETY: caller validated the full `STATFS_BYTES` user output span writable
    // for `sys_statfs`/`sys_fstatfs`; byte writes need no alignment.
    unsafe {
        for (i, byte) in img.iter().enumerate() {
            core::ptr::write_unaligned((buf + i as u64) as *mut u8, *byte);
        }
    }
}

// tmpfs magic — the reported fs for an anon/pathless fd that belongs to no
// superblock at all (Linux `anon_inode` families live on their own pseudo-fs).
pub(crate) const M_TMPFS: u64 = vfs::uapi::TMPFS_SUPER_MAGIC;

/// `kstatfs` read directly from a known owning `Mount` (its `SuperBlock` +
/// per-mount `MNT_*` flags). Used by `fstatfs` to report the fd's real backing
/// mount/superblock rather than re-classifying by the dentry name string. # C: O(1)
pub(crate) fn statfs_for_mount(m: &vfs::mount::Mount) -> SbStatFs {
    statfs_for_sb_at_mount(&m.sb(), m.flags())
}

/// Linux `vfs_statfs(&path)`: the SUPERBLOCK supplies the fs accounting
/// (`s_op->statfs` + the `statfs_by_dentry` defaults) and the MOUNT supplies
/// `f_flags` (`calculate_f_flags`). Split from [`statfs_for_mount`] so
/// `fstatfs` can report an open file's own superblock even when its owning
/// mount lookup is the only thing that fails. # C: O(1)
pub(crate) fn statfs_for_sb_at_mount(sb: &vfs::SuperBlock, mnt_flags: u64) -> SbStatFs {
    let mut st = sb.statfs().unwrap_or_default();
    st.f_flags = crate::statfs_abi::st_flags(mnt_flags, sb.s_flags());
    st
}

/// `kstatfs` for an anonymous/pathless inode that belongs to no superblock and
/// so supplies only a magic. Linux reports zero block/inode accounting for such
/// pseudo filesystems (`simple_statfs`), and so do we — a fabricated non-zero
/// row would make `df` invent capacity that does not exist. # C: O(1)
pub(crate) fn statfs_for_magic(magic: u64) -> SbStatFs {
    SbStatFs {
        f_type: magic,
        f_bsize: hal::PAGE_SIZE_BYTES as u32,
        f_frsize: hal::PAGE_SIZE_BYTES as u32,
        f_namelen: vfs::path::NAME_MAX as u64,
        ..Default::default()
    }
}
