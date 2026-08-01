use alloc::string::String;
use alloc::sync::Arc;

use vfs::{DirContext, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError, mk_mode};

use super::{next_ino, pid_ino};

const ATTR_CURRENT: &[u8] = b"kernel\n";
const ATTR_EMPTY: &[u8] = b"";

const ATTR_ENTRIES: &[(&str, FileType, fn() -> InodeRef)] = &[
    ("current", FileType::Regular, attr_current),
    ("exec", FileType::Regular, attr_empty),
    ("fscreate", FileType::Regular, attr_empty),
    ("keycreate", FileType::Regular, attr_empty),
    ("prev", FileType::Regular, attr_empty),
    ("sockcreate", FileType::Regular, attr_empty),
    ("apparmor", FileType::Directory, attr_apparmor),
];

const APPARMOR_ENTRIES: &[(&str, FileType, fn() -> InodeRef)] = &[
    ("current", FileType::Regular, attr_current),
    ("exec", FileType::Regular, attr_empty),
    ("prev", FileType::Regular, attr_empty),
];

fn attr_current() -> InodeRef { crate::sysctl::SysctlInode::new(ATTR_CURRENT) }
fn attr_empty() -> InodeRef { crate::sysctl::SysctlInode::new(ATTR_EMPTY) }
fn attr_apparmor() -> InodeRef { make_proc_pid_attr_apparmor_dir() }

pub struct ProcPidAttrDirInode {
    pub tid: u32,
}

struct ProcPidAttrDirOps;

impl InodeOps for ProcPidAttrDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let _tid = inode.private::<ProcPidAttrDirInode>().ok_or(VfsError::Einval)?.tid;
        let (_, _, ctor) = ATTR_ENTRIES.iter().find(|(n, _, _)| *n == name)
            .ok_or(VfsError::Enoent)?;
        Ok(ctor())
    }
}

impl FileOps for ProcPidAttrDirOps {
    /// # C: O(N log N)
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let _tid = inode.private::<ProcPidAttrDirInode>().ok_or(VfsError::Einval)?.tid;
        let names = ATTR_ENTRIES.iter().map(|(n, ft, _)| (String::from(*n), *ft));
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
