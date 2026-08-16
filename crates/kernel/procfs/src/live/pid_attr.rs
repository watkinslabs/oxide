// `/proc/<pid>/attr/`: the mandatory-access-control label of one task, live
// (`62§9`).
//
// Plumbing only. Which names exist, which are writable, what a written buffer
// means and which permission governs it are all decided by
// `sched::selinux_label`, which is ungated and tested; a rule written here
// could not be.

use alloc::string::String;
use alloc::sync::Arc;

use sched::selinux_label::{ATTR_SLOTS, AttrSlot, attr_mode, read_attr, write_attr};
use syscall::errno::Errno;
use vfs::{DirContext, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError, default_inode_ops, mk_mode};

use super::{next_ino, pid_ino};
use crate::dyn_file::read_at;

/// Per-pid inode tag of the first attribute file; the slot's index is added to
/// it so each file of a task keeps its own identity.
const ATTR_INO_TAG_BASE: u64 = 0x50;

/// The AppArmor sub-directory is a separate module's interface and reports
/// what this kernel has: no AppArmor profile.
const APPARMOR_CURRENT: &[u8] = b"kernel\n";
/// An AppArmor slot this kernel never sets.
const APPARMOR_EMPTY: &[u8] = b"";

const APPARMOR_ENTRIES: &[(&str, FileType, fn() -> InodeRef)] = &[
    ("current", FileType::Regular, apparmor_current),
    ("exec", FileType::Regular, apparmor_empty),
    ("prev", FileType::Regular, apparmor_empty),
];

fn apparmor_current() -> InodeRef { crate::sysctl::SysctlInode::new(APPARMOR_CURRENT) }
fn apparmor_empty() -> InodeRef { crate::sysctl::SysctlInode::new(APPARMOR_EMPTY) }

pub struct ProcPidAttrDirInode {
    pub tid: u32,
}

/// One attribute file: the task it describes and the slot it exposes.
struct ProcPidAttrFile { tid: u32, slot: AttrSlot }

/// Translate a label refusal into the filesystem's error. # C: O(1)
fn vfs_error(e: Errno) -> VfsError {
    match e {
        Errno::Einval => VfsError::Einval,
        _ => VfsError::Eacces,
    }
}

fn task(tid: u32) -> KResult<Arc<sched::Task>> {
    sched::live::registry::lookup(tid).ok_or(VfsError::Enoent)
}

struct ProcPidAttrFileOps;

impl FileOps for ProcPidAttrFileOps {
    /// procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }

    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let data = inode.private::<ProcPidAttrFile>().ok_or(VfsError::Einval)?;
        let target = task(data.tid)?;
        let body = read_attr(&target, data.slot).map_err(vfs_error)?;
        Ok(read_at(&body, off, buf))
    }

    /// A context is written whole or not at all, so a non-zero offset is a
    /// continuation of a write this interface has no way to represent.
    fn write(&self, inode: &Inode, off: u64, src: &[u8]) -> KResult<usize> {
        let data = inode.private::<ProcPidAttrFile>().ok_or(VfsError::Einval)?;
        if off != 0 { return Err(VfsError::Einval); }
        let target = task(data.tid)?;
        write_attr(&target, data.slot, src).map_err(vfs_error)
    }
}

/// Inode of one attribute file of one task. # C: O(slots)
fn make_attr_file(tid: u32, name: &str, slot: AttrSlot) -> InodeRef {
    let index = ATTR_SLOTS.iter().position(|(n, _)| *n == name).unwrap_or(0) as u64;
    InodeBuilder::new(
        pid_ino(ATTR_INO_TAG_BASE + index, tid),
        mk_mode(FileType::Regular, attr_mode(slot)),
        default_inode_ops(),
        Arc::new(ProcPidAttrFileOps),
    )
    .private(Arc::new(ProcPidAttrFile { tid, slot }))
    .build()
}

struct ProcPidAttrDirOps;

impl InodeOps for ProcPidAttrDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let tid = inode.private::<ProcPidAttrDirInode>().ok_or(VfsError::Einval)?.tid;
        if name == "apparmor" { return Ok(make_proc_pid_attr_apparmor_dir()); }
        let slot = AttrSlot::from_name(name).ok_or(VfsError::Enoent)?;
        Ok(make_attr_file(tid, name, slot))
    }
}

impl FileOps for ProcPidAttrDirOps {
    /// # C: O(N log N)
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let _tid = inode.private::<ProcPidAttrDirInode>().ok_or(VfsError::Einval)?.tid;
        let names = ATTR_SLOTS.iter().map(|(n, _)| (String::from(*n), FileType::Regular))
            .chain(core::iter::once((String::from("apparmor"), FileType::Directory)));
        crate::readdir::emit_resolved(names, |n| inode.lookup(n).ok().map(|i| i.ino()), ctx)
    }
}

pub fn make_proc_pid_attr_dir(tid: u32) -> InodeRef {
    InodeBuilder::new(
        pid_ino(0x09, tid),
        mk_mode(FileType::Directory, 0o555),
        Arc::new(ProcPidAttrDirOps),
        Arc::new(ProcPidAttrDirOps),
    )
    .private(Arc::new(ProcPidAttrDirInode { tid }))
    .build()
}

struct ProcPidAttrApparmorDirOps;

impl InodeOps for ProcPidAttrApparmorDirOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        let (_, _, ctor) = APPARMOR_ENTRIES.iter().find(|(n, _, _)| *n == name)
            .ok_or(VfsError::Enoent)?;
        Ok(ctor())
    }
}

impl FileOps for ProcPidAttrApparmorDirOps {
    /// # C: O(N log N)
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let names = APPARMOR_ENTRIES.iter().map(|(n, ft, _)| (String::from(*n), *ft));
        crate::readdir::emit_resolved(names, |n| inode.lookup(n).ok().map(|i| i.ino()), ctx)
    }
}

fn make_proc_pid_attr_apparmor_dir() -> InodeRef {
    let ino = next_ino();
    InodeBuilder::new(
        ino,
        mk_mode(FileType::Directory, 0o555),
        Arc::new(ProcPidAttrApparmorDirOps),
        Arc::new(ProcPidAttrApparmorDirOps),
    )
    .build()
}
