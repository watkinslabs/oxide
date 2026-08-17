// statfs shared helpers — used by ≥2 statfs handlers (docs/53 §0).
//
// `f_type`/`f_bsize`/usage derive from the resolved mounted-instance
// SuperBlock, the canonical per-mount state — NOT a hardcoded path-prefix magic
// table. Every production mount carries a real filled `SuperBlock`, so the `s_magic`/
// `s_op::statfs` reported here is the instance's own identity.
//
// The ABI encoder lives in `statfs_abi`, which is hosted-testable.

#![cfg(target_os = "oxide-kernel")]

use vfs::SbStatFs;

use crate::user_mem as um;

pub(crate) use crate::statfs_abi::STATFS_BYTES;

/// Copy the encoded `struct statfs` image into the caller's validated buffer.
/// `Err` is the caller's `-EFAULT`. # C: O(1)
pub(crate) fn write_statfs(buf: u64, st: &SbStatFs) -> Result<(), i64> {
    let img = crate::statfs_abi::encode_statfs(st);
    um::put_bytes(buf, &img).map_err(|_| um::EFAULT)
}

// tmpfs magic — the reported fs for an anon/pathless fd that belongs to no
// superblock at all (Linux `anon_inode` families live on their own pseudo-fs).
pub(crate) const M_TMPFS: u64 = vfs::uapi::TMPFS_SUPER_MAGIC;

/// Linux `vfs_statfs(&path)`: the SUPERBLOCK supplies the fs accounting
/// (`s_op->statfs_at` + the `statfs_by_dentry` defaults), narrowed to whatever
/// the named object is confined to, and the MOUNT supplies `f_flags`
/// (`calculate_f_flags`).
///
/// Takes the superblock rather than the mount so `fstatfs` can report an open
/// file's own superblock even when its owning mount lookup is the only thing
/// that fails. A filesystem with no per-object limits answers the same for
/// every inode. # C: O(1)
pub(crate) fn statfs_at_inode(sb: &vfs::SuperBlock, inode: &vfs::InodeRef, mnt_flags: u64)
    -> SbStatFs
{
    let mut st = sb.statfs_at(inode).unwrap_or_default();
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
