// 082 rename — one syscall, one file (docs/53 §0). Hosts the shared
// rename_impl core (also used by 264_renameat + 316_renameat2).
//
// Structure mirrors Linux `fs/namei.c` `filename_renameat2` step for step,
// because rename's observable surface is an errno LADDER whose ORDER is the
// contract. The pure decisions live in `crate::rename_policy` (ungated, unit
// tested); this file only fetches paths, resolves parents, and applies them.
// The `RENAME_*` bit values are `vfs::namei`'s (single definition).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::{
    child_dentry, child_inode, drop_child_cache, errno_from_vfs, parent_mount_readonly,
    read_user_path, resolve_rename_parent_at,
};
use crate::perms_common::AT_FDCWD;
use crate::rename_policy::{self, LastKind, RENAME_EXCHANGE, Trap};

/// `rename(from, to)` slot 82 / `renameat(odir, from, ndir, to)` slot 264 /
/// `renameat2` slot 316. Rename variants route through resolved parent inodes;
/// strings are display/LSM inputs only, never object identity.
/// # C: O(1)
pub fn sys_rename(args: &SyscallArgs) -> i64 {
    rename_impl(AT_FDCWD, args.a0, AT_FDCWD, args.a1, 0)
}

fn same_mount(a: &vfs::VfsPath, b: &vfs::VfsPath) -> bool { a.mnt_id == b.mnt_id }

fn same_parent(a: &vfs::VfsPath, b: &vfs::VfsPath) -> bool {
    alloc::sync::Arc::ptr_eq(&a.dentry, &b.dentry)
}

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

#[cfg(feature = "debug-udevdb")]
fn trace_rename_udevdb(from: &str, to: &str, rv: i64) {
    crate::namei_common::trace_udevdb_path(b"rename-from", from, rv);
    crate::namei_common::trace_udevdb_path(b"rename-to", to, rv);
}

/// Linux `__start_renaming`'s trap test, expressed over this tree's dentries.
/// `lock_rename(old_parent, new_parent)` returns the child of the outer
/// directory that lies on the path to the inner one; `d1 == trap` means the
/// SOURCE entry is that node (the source is an ancestor-or-self of the new
/// parent), and `d2 == trap` means the DESTINATION entry is (an
/// ancestor-or-self of the old parent). `is_subdir_of` is that same
/// ancestor-or-self relation over `d_parent`. # C: O(tree depth)
fn classify_trap(
    old_parent: &vfs::VfsPath, src: Option<&alloc::sync::Arc<vfs::Dentry>>,
    new_parent: &vfs::VfsPath, dst: Option<&alloc::sync::Arc<vfs::Dentry>>,
) -> Trap {
    if let Some(s) = src {
        if new_parent.dentry.is_subdir_of(s) { return Trap::SourceIsAncestorOfTarget; }
    }
    if let Some(d) = dst {
        if old_parent.dentry.is_subdir_of(d) { return Trap::TargetIsAncestorOfSource; }
    }
    Trap::None
}

/// # C: O(N_path)
pub(crate) fn rename_impl(from_dirfd: i32, from_ptr: u64, to_dirfd: i32, to_ptr: u64, flags: u32) -> i64 {
    // `filename_renameat2` validates flags BEFORE either pathname is examined,
    // so bad flags beat a bad pointer.
    if let Err(e) = rename_policy::check_flags(flags) { return err(e); }
    // Linux resolves the OLD side fully before it touches the new pathname
    // (`filename_parentat(olddfd…)` then `filename_parentat(newdfd…)`), so a
    // missing old parent reports ENOENT even when `to` is unreadable.
    let from_raw = match read_user_path(from_ptr) { Ok(s) => s, Err(rv) => return rv };
    let (old_parent, old_name, old_kind) = match resolve_rename_parent_at(from_dirfd, &from_raw) {
        Ok(x) => x, Err(rv) => {
            #[cfg(feature = "debug-udevdb")]
            trace_rename_udevdb(&from_raw, "", rv);
            return rv;
        }
    };
    let to_raw = match read_user_path(to_ptr) { Ok(s) => s, Err(rv) => return rv };
    let (new_parent, new_name, new_kind) = match resolve_rename_parent_at(to_dirfd, &to_raw) {
        Ok(x) => x, Err(rv) => {
            #[cfg(feature = "debug-udevdb")]
            trace_rename_udevdb(&from_raw, &to_raw, rv);
            return rv;
        }
    };
    let sides = RenameSides { old_parent, old_name, old_kind, new_parent, new_name, new_kind };
    let rv = rename_resolved(&sides, &from_raw, &to_raw, flags);
    #[cfg(feature = "debug-udevdb")]
    trace_rename_udevdb(&from_raw, &to_raw, rv);
    rv
}

/// Both parents resolved plus each side's `last_type`.
struct RenameSides {
    old_parent: vfs::VfsPath,
    old_name: alloc::string::String,
    old_kind: LastKind,
    new_parent: vfs::VfsPath,
    new_name: alloc::string::String,
    new_kind: LastKind,
}

/// Tail of `filename_renameat2` + `__start_renaming` + `vfs_rename`, in Linux
/// order: EXDEV → LAST_NORM → EROFS → lookups → existence → trap →
/// trailing-slash → same-inode no-op → mountpoint → LSM → DAC → backend.
/// # C: O(tree depth)
fn rename_resolved(s: &RenameSides, from_raw: &str, to_raw: &str, flags: u32) -> i64 {
    let (old_parent, new_parent) = (&s.old_parent, &s.new_parent);
    let (old_name, new_name) = (s.old_name.as_str(), s.new_name.as_str());

    // EXDEV precedes the LAST_NORM tests (`filename_renameat2` order).
    if !same_mount(old_parent, new_parent) { return err(Errno::Exdev); }
    if let Err(e) = rename_policy::check_last_kinds(s.old_kind, s.new_kind, flags) { return err(e); }
    // `mnt_want_write(old_path.mnt)`; both sides are the same mount by now.
    if parent_mount_readonly(old_parent) { return err(Errno::Erofs); }

    // `__start_renaming`: look both names up under the (locked) parents.
    let old_victim = match child_inode(old_parent, old_name) { Ok(v) => v, Err(rv) => return rv };
    let new_target = match child_inode(new_parent, new_name) { Ok(v) => v, Err(rv) => return rv };
    if let Err(e) = rename_policy::check_existence(old_victim.is_some(), new_target.is_some(), flags) {
        return err(e);
    }
    let Some(old_victim) = old_victim else { return err(Errno::Enoent) };

    let source_dentry = child_dentry(old_parent, old_name);
    let dest_victim = if new_target.is_some() { child_dentry(new_parent, new_name) } else { None };
    let trap = classify_trap(old_parent, source_dentry.as_ref(), new_parent, dest_victim.as_ref());
    if let Err(e) = rename_policy::check_trap(trap, flags) { return err(e); }

    // Trailing slashes demand a directory (`foo/`).
    let old_is_dir = matches!(old_victim.file_type(), vfs::FileType::Directory);
    let new_is_dir = new_target.as_ref()
        .map(|i| matches!(i.file_type(), vfs::FileType::Directory)).unwrap_or(false);
    if let Err(e) = rename_policy::check_trailing_slashes(
        old_is_dir, new_is_dir,
        rename_policy::has_trailing_slash(from_raw), rename_policy::has_trailing_slash(to_raw),
        flags,
    ) { return err(e); }

    // `vfs_rename`: `source == target` is a no-op success. Reached only after
    // the EEXIST/ENOENT/trap gates above, so `rename(a, a, NOREPLACE)` still
    // reports EEXIST.
    if let Some(t) = new_target.as_ref() {
        if alloc::sync::Arc::ptr_eq(&old_victim, t) { return 0; }
    }
    if same_parent(old_parent, new_parent) && old_name == new_name { return 0; }

    // `is_local_mountpoint(old_dentry) || is_local_mountpoint(new_dentry)`.
    if source_dentry.as_ref().map(|d| d.is_mounted()).unwrap_or(false)
        || dest_victim.as_ref().map(|d| d.is_mounted()).unwrap_or(false) {
        return err(Errno::Ebusy);
    }

    if let Err(rv) = landlock_gate(old_parent, old_name, &old_victim, new_parent, new_name, new_target.as_ref()) {
        return rv;
    }
    if let Err(e) = vfs::namei::may_rename(&old_parent.inode, &old_victim, &new_parent.inode,
        new_target.as_ref(), flags, same_parent(old_parent, new_parent),
        &crate::pathresolve::current_cred()) {
        return errno_from_vfs(e);
    }
    // D29: hold BOTH parent dirs' `i_rwsem` via `lock_rename` (Linux
    // `vfs_rename` → `lock_rename`) across the backend rename. `lock_rename`
    // orders the two rank-40 `i_rwsem`s by address (deadlock-safe vs. a reverse
    // concurrent rename) and locks a same-dir rename's single inode ONCE. The
    // backend resolves names via `i_op.lookup` (no nested `i_rwsem`), so holding
    // the exclusive side here is deadlock-free. The guard drops at the end of
    // this block — before the rank-50/60 dcache update below.
    let r = {
        let _rg = vfs::lock_rename(&old_parent.inode, &new_parent.inode);
        old_parent.inode.rename_child(old_name, &new_parent.inode, new_name, flags, &vfs::CreateCtx::root())
    };
    match r {
        Ok(())  => {
            if flags & RENAME_EXCHANGE != 0 {
                drop_child_cache(old_parent, old_name);
                drop_child_cache(new_parent, new_name);
            } else if let Some(d) = source_dentry {
                if let Some(v) = dest_victim { vfs::dcache::d_unlink(&v); }
                vfs::dcache::d_move(&d, &new_parent.dentry, new_name);
            } else {
                drop_child_cache(old_parent, old_name);
                drop_child_cache(new_parent, new_name);
            }
            ::fs::inotify::fire_move(&old_parent.inode, &new_parent.inode, Some(&old_victim));
            0
        }
        Err(e)  => errno_from_vfs(e),
    }
}

/// Linux `security_path_rename`. From-side needs REMOVE_FILE | REMOVE_DIR |
/// REFER; to-side needs MAKE_REG. Approximated as REMOVE_FILE+MAKE_REG+REFER
/// on both. # C: O(landlock ruleset)
fn landlock_gate(
    old_parent: &vfs::VfsPath, old_name: &str, old_victim: &vfs::InodeRef,
    new_parent: &vfs::VfsPath, new_name: &str, new_target: Option<&vfs::InodeRef>,
) -> Result<(), i64> {
    let la = ::security::landlock::access::REMOVE_FILE
           | ::security::landlock::access::MAKE_REG
           | ::security::landlock::access::REFER;
    let old_check = vfs::VfsPath {
        mnt_id: old_parent.mnt_id,
        dentry: vfs::file::open_dentry_at(&old_parent.dentry, old_name, old_victim),
        inode: old_victim.clone(),
        last_component: None,
    };
    crate::landlock::check(&old_check, la)?;
    let new_check = match new_target {
        Some(i) => vfs::VfsPath {
            mnt_id: new_parent.mnt_id,
            dentry: vfs::file::open_dentry_at(&new_parent.dentry, new_name, i),
            inode: i.clone(),
            last_component: None,
        },
        None => new_parent.clone(),
    };
    crate::landlock::check(&new_check, la)
}
