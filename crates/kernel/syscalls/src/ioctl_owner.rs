// WHO ANSWERS AN ioctl — the split between the generic VFS owner and the file's
// own operations, as one rule with no target gate so it is hosted-testable.
//
// Linux runs `do_vfs_ioctl` first; it answers only the commands it actually
// owns, and for everything else (and for the type-restricted cases it declines)
// it returns `-ENOIOCTLCMD`, which sends the call on to `vfs_ioctl` →
// `f_op->unlocked_ioctl`. `ENOTTY` is what the FILE reports when it has no
// handler, never something the generic stage invents on the file's behalf.
//
// The distinction that actually bites is `IS_ANON_FILE`: an epoll / eventfd /
// timerfd / signalfd / io_uring / userfaultfd fd carries a regular-or-chardev
// type tag for `fstat` but has no filesystem behind it. Letting the generic
// stage run its regular-file paths on one of those shadows the fd's own handler
// and answers with a fabricated result (`FIONREAD` reporting `i_size - f_pos`
// = 0) or the wrong errno (`ENOTTY` where the fd's own operations say `EINVAL`).

use crate::ioctl_uapi::*;

/// Which stage answers a given `(command, file)` pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoctlOwner {
    /// `do_vfs_ioctl` answers it.
    Vfs,
    /// `-ENOIOCTLCMD` → the file's own `unlocked_ioctl` answers it.
    FileOps,
}

/// The file properties the split depends on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoctlFile {
    pub ft: vfs::FileType,
    /// `IS_ANON_FILE` — an `anon_inode_getfd` inode with no filesystem behind it.
    pub anon: bool,
}

impl IoctlFile {
    /// A regular file backed by a real filesystem — the only shape whose
    /// contents the generic stage may answer about. # C: O(1)
    pub fn is_fs_regular(&self) -> bool {
        self.ft == vfs::FileType::Regular && !self.anon
    }

    /// Shapes whose allocated size `FIOQSIZE` can report. # C: O(1)
    pub fn has_allocated_size(&self) -> bool {
        matches!(self.ft, vfs::FileType::Directory | vfs::FileType::Symlink) || self.is_fs_regular()
    }
}

/// `do_vfs_ioctl`'s dispatch decision for one command.
///
/// Commands not listed belong to the file: the generic stage has no opinion, so
/// naming them here at all would be the shadowing bug this function exists to
/// prevent. # C: O(1)
pub fn ioctl_owner(req: u64, f: IoctlFile) -> IoctlOwner {
    match req {
        // Descriptor-table and open-file-description state: owned for every
        // file type, including anon fds.
        FIOCLEX | FIONCLEX | FIONBIO | FIOASYNC => IoctlOwner::Vfs,
        // Superblock/inode-attribute queries: owned wherever the file has a
        // filesystem, which an anon inode does not.
        FIGETBSZ | FS_IOC_GETFLAGS | FS_IOC_SETFLAGS | FS_IOC_FSGETXATTR
        | FS_IOC_FSSETXATTR | FS_IOC_GETFSUUID | FS_IOC_GETFSSYSFSPATH
            if !f.anon => IoctlOwner::Vfs,
        // Range/clone operations: regular files on a filesystem.
        FICLONE | FICLONERANGE | FIDEDUPERANGE if !f.anon => IoctlOwner::Vfs,
        FIBMAP | FS_IOC_RESVSP | FS_IOC_RESVSP64 | FS_IOC_UNRESVSP
        | FS_IOC_UNRESVSP64 | FS_IOC_ZERO_RANGE if f.is_fs_regular() => IoctlOwner::Vfs,
        // `FIOQSIZE` is owned for EVERY file type: the generic stage measures
        // directories, symlinks, and non-anon regular files, and answers
        // `ENOTTY` itself for the rest rather than handing the command on.
        // That asymmetry with `FIONREAD` right below is deliberate and is the
        // reason this decision is a table and not a type test at each site.
        FIOQSIZE => IoctlOwner::Vfs,
        // `FIONREAD` is the canonical shadowing trap: Linux answers
        // `i_size - f_pos` ONLY for a real regular file and hands every other
        // file — sockets, pipes, ttys, and every anon fd — to its own handler.
        FIONREAD if f.is_fs_regular() => IoctlOwner::Vfs,
        _ => IoctlOwner::FileOps,
    }
}

/// Project an open file onto the two properties the dispatch split reads.
/// # C: O(1)
pub fn ioctl_file(file: &vfs::File) -> IoctlFile {
    IoctlFile { ft: file.inode().file_type(), anon: file.inode().is_anon_file() }
}

/// Does the filesystem's own `unlocked_ioctl` (the `ext4_ioctl` family:
/// versions, label, trim) apply to this file? An anon fd's operations are its
/// own, so the filesystem set must not run — and must not answer `ENOTTY` —
/// ahead of them. # C: O(1)
pub fn fs_unlocked_ioctl_applies(f: IoctlFile) -> bool { !f.anon }

#[cfg(test)]
#[path = "ioctl_owner_tests.rs"]
mod tests;
