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
        let file = open_file_at(inode, dentry, flags, mnt_id, cred, fop_override)?;
        fdt.fd_install(fd, file);
        Ok(fd)
    })();
    if result.is_err() { fdt.put_unused_fd(fd); }
    result
}

/// Everything an open does to reach a live `struct file`, with no descriptor
/// involved: the `O_DIRECTORY` check, the read-only-mount gate, the `f_op`
/// binding, `f_op->open`, the `O_DIRECT` capability gate and `O_TRUNC`.
///
/// Split out so an in-kernel open ([`crate::file::kernel_open_at_root`]) and a
/// descriptor-installing open run the SAME sequence — an internal opener that
/// skipped any of it would hold a file the syscall path would have refused.
/// # C: O(1)
pub fn open_file_at(
    inode: InodeRef,
    dentry: alloc::sync::Arc<crate::dentry::Dentry>,
    flags: OpenFlags,
    mnt_id: u64,
    cred: FileCred,
    fop_override: Option<alloc::sync::Arc<dyn crate::file_ops::FileOps>>,
) -> Result<alloc::sync::Arc<File>, VfsError> {
    {
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
        if truncate && mnt_write_readonly(mnt_id) { return Err(VfsError::Erofs); }
        let file_flags = flags - OpenFlags::O_CLOEXEC;
        // Write admission for the DESCRIPTION, in the fixed order: the inode
        // writer counter first (`ETXTBSY` against a running executable), then
        // the mount/superblock read-only test (`EROFS`). Both stand AFTER the
        // permission ladder the caller already ran, which is why a caller who
        // lacks permission on a file that also sits on a read-only mount is
        // told `EACCES` and not `EROFS`.
        //
        // The write reference is held for the LIFE of the description and
        // released by `File::drop`, not by this call frame: it is what makes a
        // write-open of a running binary fail, and a running binary is one that
        // some OTHER description still holds. Acquired BEFORE the description
        // exists so that every failure below simply drops the `File` and lets
        // `Drop` do the single matching release.
        let write_ref = wants_write_ref(file_flags, mnt_id, inode.file_type());
        if write_ref {
            inode.get_write_access()?;
            if mnt_write_readonly(mnt_id) {
                inode.put_write_access();
                return Err(VfsError::Erofs);
            }
        }
        let file = match fop_override {
            Some(fop) => File::new_at_fop(inode, dentry, file_flags, mnt_id, cred, fop),
            None      => File::new_at(inode, dentry, file_flags, mnt_id, cred),
        };
        if !file_flags.contains(OpenFlags::O_PATH) { file.open_hook()?; }
        // `O_DIRECT` set without `FMODE_CAN_ODIRECT` is `EINVAL` at open time.
        //
        // `FMODE_CAN_ODIRECT` is set only by backends that install an
        // `a_ops->direct_IO`, plus block devices
        // and shmem. We have no
        // direct-I/O path for ext4 regular files — no cache bypass, no
        // alignment gate, no `invalidate_inode_pages2_range` for coherency —
        // so the honest answer is Linux's own answer for a filesystem without
        // one: EINVAL at open. Silently buffering an `O_DIRECT` open is the
        // one outcome that is not acceptable, because callers use the flag for
        // correctness (a database's "this write is not in the page cache"
        // assumption), not just for speed, and they discover the truth only by
        // being told at open.
        //
        // Scoped to regular files: `O_DIRECT` means packet-mode on a pipe
        // (`pipe2(2)`), and block devices already do unbuffered I/O — neither
        // is the buffered-behind-your-back case this gate exists to catch.
        if file_flags.contains(OpenFlags::O_DIRECT)
            && matches!(file.inode().file_type(), crate::types::FileType::Regular)
            && !file.f_op().can_odirect(file.inode())
        {
            return Err(VfsError::Einval);
        }
        if truncate { file.inode().truncate(0)?; }
        Ok(file)
    }
}

/// A device / FIFO / socket open addresses a driver, not filesystem data.
/// Write admission for those file types is the driver's business, so they are
/// exempt from the mount write admission and from the inode writer counter.
/// # C: O(1)
fn special_file(ftype: crate::types::FileType) -> bool {
    use crate::types::FileType;
    matches!(ftype, FileType::CharDev | FileType::BlockDev | FileType::Fifo | FileType::Socket)
}

/// The single rule deciding whether an open file description carries an inode
/// write reference: a write-capable access mode, on a real mount, on a
/// non-special file type. Both the acquire (open) and the release (final
/// close) read THIS function, so they cannot drift apart.
///
/// The mount test is what separates a real open from an anonymous/pseudo file
/// (pipe, socket, memfd, eventfd, …). Those are constructed directly rather
/// than through this path, take no write reference, and must not release one at
/// close — doing so would drive the counter negative and make an unrelated file
/// look like a running executable. `O_PATH` is excluded for free: it yields an
/// `f_mode` with neither read nor write. # C: O(1)
fn write_ref_for(f_mode: super::Fmode, mnt_id: u64, ftype: crate::types::FileType) -> bool {
    mnt_id != 0 && f_mode.contains(super::Fmode::WRITE) && !special_file(ftype)
}

/// [`write_ref_for`] evaluated from the flags an open is about to use, before
/// the description exists — the acquire side of the pair. # C: O(1)
fn wants_write_ref(flags: OpenFlags, mnt_id: u64, ftype: crate::types::FileType) -> bool {
    write_ref_for(super::fmode_from_flags(flags), mnt_id, ftype)
}

impl File {
    /// True iff THIS open file description holds one write reference on its
    /// inode's writer/exec counter for its whole lifetime — the state that makes
    /// a write-open of a running executable `ETXTBSY`, and an execute of a
    /// currently write-open file `ETXTBSY` in the other direction.
    ///
    /// Recomputed rather than stored: every input is immutable for the life of
    /// the description (the `f_mode` access bits are fixed at open and `F_SETFL`
    /// cannot change them, the mount identity is captured at open, an inode
    /// never changes file type), so the acquire site and the release site cannot
    /// disagree and no extra field is needed to keep them in step. # C: O(1)
    pub fn holds_write_ref(&self) -> bool {
        write_ref_for(self.f_mode(), self.mnt_id(), self.inode().file_type())
    }
}

/// True when a write through `mnt_id` must be refused `EROFS` because the mount
/// or its backing superblock is read-only. An anonymous file (`mnt_id == 0`) has
/// no mount to admit against and is never blocked here. # C: O(log N_mounts)
fn mnt_write_readonly(mnt_id: u64) -> bool {
    if mnt_id == 0 { return false; }
    match crate::mount::mount_by_id(mnt_id) {
        Some(m) => (m.flags() & crate::mount::MNT_RDONLY) != 0 || m.sb().is_readonly(),
        None    => false,
    }
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
