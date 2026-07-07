extern crate alloc;

use crate::inode::InodeRef;
use crate::namei::Cred;
use crate::types::{OpenFlags, VfsError};

use super::File;

/// Create a `File` from an inode + path, install into the supplied
/// `FdTable`. Per `docs/53§3` work fn. Handles the common
/// post-lookup sequence: O_DIRECTORY check, O_TRUNC, Dentry wrap,
/// File construction, fd allocation.
///
/// `fop_override` installs a per-open `f_op` OTHER than the inode's `i_fop`
/// (Linux `f_op->open` swapping the vtable) — the named-FIFO path passes the
/// `pipefifo_fops` returned by `fifo_open`; `None` snapshots `inode->i_fop`.
/// # C: O(1) + fd_table alloc
pub fn install_open(
    fdt: &crate::fdtable::FdTable,
    inode: InodeRef,
    path: &str,
    flags: OpenFlags,
    mnt_id: u64,
    cred: Cred,
    limit: usize,
    fop_override: Option<alloc::sync::Arc<dyn crate::file_ops::FileOps>>,
) -> Result<i32, VfsError> {
    if flags.contains(OpenFlags::O_DIRECTORY)
        && !matches!(inode.file_type(), crate::types::FileType::Directory)
    {
        return Err(VfsError::Enotdir);
    }
    if flags.contains(OpenFlags::O_TRUNC) {
        if crate::mount::is_readonly_path(path) {
            return Err(VfsError::Erofs);
        }
        let _ = inode.truncate(0);
    }
    let cloexec = flags.contains(OpenFlags::O_CLOEXEC);
    let file_flags = flags - OpenFlags::O_CLOEXEC;
    let dentry = open_dentry(path, &inode);
    let file = match fop_override {
        Some(fop) => File::new_at_fop(inode, dentry, file_flags, mnt_id, cred, fop),
        None      => File::new_at(inode, dentry, file_flags, mnt_id, cred),
    };
    if !file_flags.contains(OpenFlags::O_PATH) { file.open_hook()?; }
    let fd = fdt.alloc_limit(file, limit).map_err(|_| VfsError::Emfile)?;
    if cloexec {
        fdt.set_cloexec(fd, true)?;
    }
    Ok(fd)
}

/// Build the `Dentry` for an opened file as a properly-PARENTED node (Linux
/// `f->f_path.dentry`): resolve the parent directory's dentry via the
/// per-component walk and hang the basename child off it, carrying the
/// opened inode. `Dentry::absolute_path` then reconstructs the pathname by
/// walking the parent chain — there is no whole-path-in-one-dentry shape.
/// Falls back to a basename-only dentry only when the root dentry isn't
/// built yet (very early boot) or the parent doesn't resolve.
/// # C: O(path components)
pub fn open_dentry(path: &str, inode: &InodeRef) -> alloc::sync::Arc<crate::dentry::Dentry> {
    use alloc::sync::Arc;
    use alloc::string::String;
    use crate::dentry::Dentry;
    // Root itself: reuse the canonical root dentry when available.
    if path == "/" {
        if let Some(r) = crate::namei::resolve_path_dentry("/") { return r; }
        return Dentry::new(None, String::new(), Arc::clone(inode));
    }
    let trimmed = path.trim_end_matches('/');
    let (parent, name) = match trimmed.rfind('/') {
        Some(0) => ("/", &trimmed[1..]),
        Some(i) => (&trimmed[..i], &trimmed[i + 1..]),
        None    => ("", trimmed),
    };
    if let Some(pd) = crate::namei::resolve_path_dentry(parent) {
        // D3: hand the fd the CANONICAL hashed dentry the walk produced, not a
        // fresh unhashed Arc. `d_lookup` returns the object already in the
        // global table (so a wired `d_move`/`d_drop` reaches the fd's dentry);
        // a miss `d_add`s the canonical positive.
        return match crate::dcache::d_lookup(&pd, name) {
            // Defensive: if a negative dentry is ever cached for this name
            // (e.g. once D5/D6 negative-caching lands), splice the real inode
            // onto it (Linux `d_splice_alias` / `d_instantiate`) → positive
            // rather than handing the fd a negative dentry.
            Some(d) if d.is_negative() => crate::dcache::d_splice_alias(Arc::clone(inode), &d),
            Some(d) => d,
            None    => crate::dcache::d_add(&pd, name, Arc::clone(inode)),
        };
    }
    Dentry::new(None, String::from(name), Arc::clone(inode))
}
