extern crate alloc;

use crate::inode::InodeRef;
use crate::types::{OpenFlags, VfsError};

use super::{File, FileCred};

/// Create a `File` from an inode + resolved dentry, install into the supplied
/// `FdTable`. Per `docs/53§3` work fn. Handles the common
/// post-lookup sequence: O_DIRECTORY check, O_TRUNC, Dentry wrap,
/// File construction, fd allocation.
///
/// `fop_override` installs a per-open `f_op` OTHER than the inode's `i_fop`
/// (Linux `f_op->open` swapping the vtable) — the named-FIFO path passes the
/// `pipefifo_fops` returned by `fifo_open`; `None` snapshots `inode->i_fop`.
/// # C: O(1) + fd_table alloc
pub fn install_open_at(
    fdt: &crate::fdtable::FdTable,
    inode: InodeRef,
    dentry: alloc::sync::Arc<crate::dentry::Dentry>,
    flags: OpenFlags,
    mnt_id: u64,
    cred: FileCred,
    limit: usize,
    fop_override: Option<alloc::sync::Arc<dyn crate::file_ops::FileOps>>,
) -> Result<i32, VfsError> {
    let fd = fdt.get_unused_fd_flags(flags, limit).map_err(|_| VfsError::Emfile)?;
    let result = (|| {
        if flags.contains(OpenFlags::O_DIRECTORY)
            && !flags.contains(OpenFlags::O_TMPFILE)
            && !matches!(inode.file_type(), crate::types::FileType::Directory)
        {
            return Err(VfsError::Enotdir);
        }
        // Linux ignores O_TRUNC for special files: device/FIFO/socket open is
        // an operation on the driver, not filesystem data. In particular,
        // shell redirection opens `/dev/null` with O_TRUNC even when /dev is
        // mounted read-only.
        let needs_trunc = flags.contains(OpenFlags::O_TRUNC);
        let truncate = needs_trunc && matches!(inode.file_type(), crate::types::FileType::Regular);
        if truncate {
            if mnt_id != 0 {
                if let Some(m) = crate::mount::mount_by_id(mnt_id) {
                    if (m.flags() & crate::mount::MNT_RDONLY) != 0 || m.sb().is_readonly() {
                        return Err(VfsError::Erofs);
                    }
                }
            }
        }
        let file_flags = flags - OpenFlags::O_CLOEXEC;
        let file = match fop_override {
            Some(fop) => File::new_at_fop(inode, dentry, file_flags, mnt_id, cred, fop),
            None      => File::new_at(inode, dentry, file_flags, mnt_id, cred),
        };
        if !file_flags.contains(OpenFlags::O_PATH) { file.open_hook()?; }
        if truncate { file.inode().truncate(0)?; }
        fdt.fd_install(fd, file);
        Ok(fd)
    })();
    if result.is_err() { fdt.put_unused_fd(fd); }
    result
}

/// Build the opened leaf from an already-resolved parent dentry. This is the
/// non-string entry used by `openat` create paths whose authority is a
/// `VfsPath`, not a rendered pathname. # C: O(1)
pub fn open_dentry_at(parent: &alloc::sync::Arc<crate::dentry::Dentry>, name: &str, inode: &InodeRef) -> alloc::sync::Arc<crate::dentry::Dentry> {
    use alloc::sync::Arc;
    match crate::dcache::d_lookup(parent, name) {
        Some(d) if d.is_negative() => crate::dcache::d_splice_alias(Arc::clone(inode), &d),
        Some(d) => d,
        None    => crate::dcache::d_add(parent, name, Arc::clone(inode)),
    }
}
