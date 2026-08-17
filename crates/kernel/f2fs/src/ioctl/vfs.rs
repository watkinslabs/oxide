//! The bodies behind the operations vector's ioctl entry points.
//!
//! `mount/ops.rs` holds the entry points themselves and nothing else, so the
//! work is here, beside the surface it belongs to. Three stages reach this
//! module and each keeps its own door:
//!
//! - the generic stage, through the file-attribute pair;
//! - the typed file-operations stage, through the version, label and trim
//!   commands the interface already carries;
//! - this filesystem's own handler, through [`raw`], with the command number
//!   untouched.
//!
//! No stage answers for another. A stage that claimed a command an earlier
//! one owns would shadow it, which is the defect that once had every
//! anonymous descriptor reporting a filesystem's errno.

use alloc::sync::Arc;

use vfs::{FileIoctlCmd, FileIoctlReply, Inode, KResult, VfsError};

use crate::mount::node::F2fsNode;

use super::entry::Answer;
use super::fileattr::{self, Kind, View};
use super::perm::{Ctx, DstFd};
use super::req::Extra;

/// Is this inode one of ours?
///
/// The dispatcher above asks before it does anything, so a foreign inode
/// falls through this filesystem's handler untouched rather than being told
/// no such operation on another backend's behalf.
/// # C: O(1)
pub fn is_f2fs(inode: &Inode) -> bool { inode.private::<F2fsNode>().is_some() }

/// What the second descriptor a move names is, as the ladder needs it.
///
/// The three outcomes are not interchangeable and the caller cannot collapse
/// them: a descriptor that cannot be written is refused before the mount's
/// write reference and one naming another volume after it, so which one this
/// returns decides which errno the caller sees. `None` for the descriptor
/// itself — no such file — is the same answer as one that cannot be written,
/// because neither is a destination.
///
/// Both halves of the reference's test are made: the same MOUNT and the same
/// SUPERBLOCK. Two mounts of one volume are two mounts, and a move across
/// them is not this operation.
/// # C: O(1)
pub fn resolve_dst(src: &vfs::File, dst: Option<&vfs::File>) -> DstFd {
    let Some(dst) = dst else { return dst_of(None) };
    let facts = DstFacts {
        writable: dst.f_mode().contains(vfs::Fmode::WRITE),
        same_mount: dst.mnt_id() == src.mnt_id(),
        same_volume: match (src.inode().private::<F2fsNode>(),
                            dst.inode().private::<F2fsNode>()) {
            (Some(a), Some(b)) => Arc::ptr_eq(&a.fs, &b.fs),
            _ => false,
        },
        ino: dst.inode().private::<F2fsNode>().map_or(0, |n| n.ino),
    };
    dst_of(Some(facts))
}

/// What the layer above can see about the second description.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DstFacts {
    /// The description was opened for writing.
    pub writable: bool,
    /// It is on the same mount as the source.
    pub same_mount: bool,
    /// It is a file of the same volume.
    pub same_volume: bool,
    /// Its inode number, meaningful only when it is one of ours.
    pub ino: u32,
}

/// The decision itself, over stated facts.
///
/// Both halves of the reference's test are made — the same MOUNT and the same
/// volume — because two mounts of one volume are two mounts and a move across
/// them is not this operation.
/// # C: O(1)
pub fn dst_of(f: Option<DstFacts>) -> DstFd {
    // No such descriptor and one that cannot be written are the same answer:
    // neither is a destination, and both are refused before the mount's write
    // reference rather than after it.
    let Some(f) = f else { return DstFd::Unusable };
    if !f.writable { return DstFd::Unusable; }
    if !f.same_mount || !f.same_volume { return DstFd::Foreign; }
    DstFd::Ours(f.ino)
}

/// The node behind an inode, or the refusal a foreign inode gets. # C: O(1)
fn node(inode: &Inode) -> KResult<&F2fsNode> {
    inode.private::<F2fsNode>().ok_or(VfsError::Einval)
}

/// What kind of thing this inode is, for the flag mask that depends on it.
/// # C: O(1)
fn kind(inode: &Inode) -> Kind {
    match inode.file_type() {
        vfs::FileType::Directory => Kind::Dir,
        vfs::FileType::Regular => Kind::Reg,
        _ => Kind::Other,
    }
}

/// `FS_IOC_GETFLAGS` and `FS_IOC_FSGETXATTR`. # C: O(1 block)
pub fn fileattr_get(inode: &Inode) -> KResult<vfs::FileAttr> {
    let n = node(inode)?;
    let live = n.live()?;
    let flags = fileattr::report(&View {
        stored: live.flags,
        encrypted: live.encrypted(),
        verity: live.verity(),
        inline_data: live.inline_data() || live.inline_dentry(),
        pinned: live.has(crate::flags::PIN_FILE),
    });
    let mut fa = vfs::fileattr_fill_flags(flags);
    if crate::features::has_project_quota(n.fs.volume.lock().super_block().feature) {
        fa.fsx_projid = live.projid;
    }
    Ok(fa)
}

/// `FS_IOC_SETFLAGS` and `FS_IOC_FSSETXATTR`. # C: O(1 block)
pub fn fileattr_set(inode: &Inode, fa: &vfs::FileAttr) -> KResult<()> {
    let n = node(inode)?;
    let live = n.live()?;
    let next = fileattr::apply(live.flags, fa.flags, kind(inode))
        .map_err(crate::mount::errno_to_vfs)?;
    if next == live.flags { return Ok(()); }
    let mut v = n.fs.volume_now();
    v.set_inode_flags(n.ino, next).map_err(crate::mount::errno_to_vfs)
}

/// The typed file-operations stage: the version, label and trim commands the
/// interface carries for every filesystem. # C: command-dependent
pub fn unlocked_ioctl(file: &vfs::File, cred: &vfs::Cred, cmd: FileIoctlCmd)
    -> KResult<FileIoctlReply> {
    let _ = cred;
    let n = node(file.inode())?;
    match cmd {
        FileIoctlCmd::GetVersion =>
            Ok(FileIoctlReply::U32(n.live()?.generation)),
        FileIoctlCmd::SetVersionPrepare => {
            if !n.fs.is_writable() { return Err(VfsError::Erofs); }
            Ok(FileIoctlReply::Done)
        }
        FileIoctlCmd::SetVersion(generation) => {
            let mut v = n.fs.volume_now();
            v.set_generation(n.ino, generation).map_err(crate::mount::errno_to_vfs)?;
            Ok(FileIoctlReply::Done)
        }
        FileIoctlCmd::GetFsLabel => {
            let v = n.fs.volume.lock();
            let mut out = [0u8; 17];
            let s = v.label().as_bytes();
            let take = s.len().min(out.len() - 1);
            out[..take].copy_from_slice(&s[..take]);
            Ok(FileIoctlReply::Label(out))
        }
        FileIoctlCmd::SetFsLabelPrepare(cap) => {
            if !cap { return Err(VfsError::Eperm); }
            if !n.fs.is_writable() { return Err(VfsError::Erofs); }
            Ok(FileIoctlReply::Done)
        }
        FileIoctlCmd::SetFsLabel(label) => {
            let end = label.iter().position(|b| *b == 0).unwrap_or(label.len());
            let name = core::str::from_utf8(&label[..end]).map_err(|_| VfsError::Einval)?;
            let mut v = n.fs.volume_now();
            v.set_label(name).map_err(crate::mount::errno_to_vfs)?;
            Ok(FileIoctlReply::Done)
        }
        FileIoctlCmd::FitTrimPrepare(cap) => {
            if !cap { return Err(VfsError::Eperm); }
            let v = n.fs.volume.lock();
            if !v.discards() { return Err(VfsError::Eopnotsupp); }
            drop(v);
            if !n.fs.is_writable() { return Err(VfsError::Erofs); }
            Ok(FileIoctlReply::Done)
        }
        FileIoctlCmd::FitTrim { start, len, minlen } => {
            let mut v = n.fs.volume_now();
            v.trim_free_space(start, len, minlen).map_err(crate::mount::errno_to_vfs)?;
            Ok(FileIoctlReply::Done)
        }
    }
}

/// This filesystem's own handler, reached with the raw command number.
///
/// `None` means the file is not one of ours or the command is not this
/// handler's, so the caller carries on down its own chain rather than being
/// told no such operation on our behalf.
/// # C: command-dependent
pub fn raw(file: &Arc<vfs::File>, cmd: u32, payload: &[u8], extra: &Extra, c: &Ctx)
    -> Option<KResult<Answer>> {
    if !super::spec::owns(cmd) { return None; }
    let n = file.inode().private::<F2fsNode>()?;
    let mut v = n.fs.volume_now();
    Some(super::entry::handle(&mut v, n.ino, cmd, payload, extra, c)
        .map_err(crate::mount::errno_to_vfs))
}

#[cfg(test)]
#[path = "../tests/ioctl/dst.rs"]
mod tests;
