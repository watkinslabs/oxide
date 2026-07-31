// Rename gate: `renameat2(2)` flag validation plus the dual-parent DAC +
// type-agreement matrix.

use crate::inode::InodeRef;
use crate::types::{FileType, KResult, VfsError};

use super::{Cred, MAY_WRITE};
use super::may_create::may_create;
use super::may_delete::may_delete;
use super::permission::inode_permission;

/// `renameat2(2)` flag bits (Linux `include/uapi/linux/fs.h`). The VFS-crate
/// canonical definitions; the syscall shim reuses these rather than re-deriving
/// the bit values at the ABI boundary.
pub const RENAME_NOREPLACE: u32 = 1 << 0;
pub const RENAME_EXCHANGE:  u32 = 1 << 1;
pub const RENAME_WHITEOUT:  u32 = 1 << 2;

/// `do_renameat2` flag validation (Linux `fs/namei.c`): reject unknown bits and
/// the mutually-exclusive combinations. `RENAME_EXCHANGE` may not be combined
/// with `RENAME_NOREPLACE` or `RENAME_WHITEOUT` (both `EINVAL`). # C: O(1)
pub fn rename_flags_check(flags: u32) -> KResult<()> {
    const VALID: u32 = RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT;
    if flags & !VALID != 0 { return Err(VfsError::Einval); }
    if flags & RENAME_EXCHANGE != 0 && flags & (RENAME_NOREPLACE | RENAME_WHITEOUT) != 0 {
        return Err(VfsError::Einval);
    }
    Ok(())
}

/// `vfs_rename` permission gate (Linux `fs/namei.c`) — the DAC + type-agreement
/// checks for renaming the existing entry `old_victim` (in `old_dir`) onto a
/// name in `new_dir`, where `new_target` is the entry currently at the
/// destination (`None` if the destination name is free). `same_parent` is
/// whether the two parent directories are the same node. Honours `flags`:
///   * `RENAME_NOREPLACE` — destination must be free (`EEXIST` if occupied);
///   * `RENAME_EXCHANGE` — destination must exist (`ENOENT` if free), and the
///     target's deletion check uses the TARGET's OWN type (a dir may swap with a
///     file), not the source's;
///   * plain / `RENAME_WHITEOUT` — the occupied-target deletion check uses the
///     SOURCE's type, so a directory may only replace a directory (`ENOTDIR`
///     otherwise) and a non-directory only a non-directory (`EISDIR`).
/// Order mirrors Linux: existence (`EEXIST`/`ENOENT`), then `may_delete` on the
/// source, then `may_create` (free dest) or `may_delete` (occupied dest), then —
/// when the parent changes and a directory moves — `MAY_WRITE` on the moved
/// subtree (and, for `RENAME_EXCHANGE` of a directory target, the target) for
/// the `..` flip. # C: O(ngroups)
pub fn may_rename(
    old_dir: &InodeRef,
    old_victim: &InodeRef,
    new_dir: &InodeRef,
    new_target: Option<&InodeRef>,
    flags: u32,
    same_parent: bool,
    cred: &Cred,
) -> KResult<()> {
    let is_exchange = flags & RENAME_EXCHANGE != 0;
    if flags & RENAME_NOREPLACE != 0 && new_target.is_some() {
        return Err(VfsError::Eexist);
    }
    if is_exchange && new_target.is_none() {
        return Err(VfsError::Enoent);
    }
    if let Some(t) = new_target {
        if alloc::sync::Arc::ptr_eq(old_victim, t) { return Ok(()); }
    }
    let is_dir = matches!(old_victim.file_type(), FileType::Directory);
    may_delete(old_dir, old_victim, is_dir, cred)?;
    match new_target {
        None => may_create(new_dir, cred)?,
        Some(t) => {
            // EXCHANGE: target's own type (both survive). Else: source's type,
            // enforcing source/target type agreement (ENOTDIR / EISDIR).
            let victim_isdir = if is_exchange { matches!(t.file_type(), FileType::Directory) } else { is_dir };
            may_delete(new_dir, t, victim_isdir, cred)?;
        }
    }
    // Cross-directory move flips a moved directory's `..` entry, needing write
    // on it (Linux: `inode_permission(old_dentry->d_inode, MAY_WRITE)`).
    if !same_parent {
        if is_dir { inode_permission(old_victim, MAY_WRITE, cred)?; }
        if is_exchange {
            if let Some(t) = new_target {
                if matches!(t.file_type(), FileType::Directory) {
                    inode_permission(t, MAY_WRITE, cred)?;
                }
            }
        }
    }
    Ok(())
}

