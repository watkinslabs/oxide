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
use super::perm::Ctx;
use super::req::Extra;

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
