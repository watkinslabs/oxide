// `/sys/subsystem` — the unified classification view.
//
// Every bus and every class appears here under one layout, `<name>/devices`
// (plus `<name>/drivers` for a bus). A consumer that finds this directory is
// entitled to stop scanning `/sys/bus`, `/sys/class` and `/sys/block`, so it
// must be COMPLETE: it is built as a projection over the very registries
// those paths render, never as a second list of subsystems. Registering a new
// class or bus therefore publishes it here with no further action, and the
// two views cannot disagree.
//
// `<name>/devices` is a symlink to the canonical directory rather than a
// re-rendered copy. Relative device targets under it (`../../devices/...`)
// are then resolved against the canonical directory's own path, so one set of
// targets stays correct at both depths and no target convention is duplicated.

#[cfg(test)]
mod tests;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{mk_mode, DirContext, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef,
    KResult, VfsError};

use crate::{ids, DIR_PERM};

/// The two classification roots this view unifies, in the order their names
/// are merged.
pub(crate) const CLASS_ROOT: &str = "class";
pub(crate) const BUS_ROOT: &str = "bus";

/// `devices`/`drivers` — the per-subsystem entries the layout defines.
pub(crate) const DEVICES: &str = "devices";
pub(crate) const DRIVERS: &str = "drivers";

/// Names registered under one classification root. # C: O(N children)
fn names_under(root: &str) -> Vec<String> {
    match crate::root::sys_root().lookup_dir(root) {
        Some(dir) => dir.child_names(),
        None => Vec::new(),
    }
}

/// Every subsystem name, class and bus merged, each appearing once. # C: O(N log N)
fn subsystem_names() -> Vec<String> {
    let mut names = names_under(CLASS_ROOT);
    for name in names_under(BUS_ROOT) {
        if !names.contains(&name) { names.push(name); }
    }
    names.sort();
    names
}

/// Which classification root owns `name`, preferring the bus view because it
/// is the one whose layout `/sys/subsystem` follows. # C: O(N children)
fn root_of(name: &str) -> Option<&'static str> {
    if names_under(BUS_ROOT).iter().any(|n| n == name) { return Some(BUS_ROOT); }
    if names_under(CLASS_ROOT).iter().any(|n| n == name) { return Some(CLASS_ROOT); }
    None
}

struct SubsystemRootOps;

impl InodeOps for SubsystemRootOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        let root = root_of(name).ok_or(VfsError::Enoent)?;
        Ok(make_subsystem_dir_inode(String::from(name), root))
    }
}

impl FileOps for SubsystemRootOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let names = subsystem_names();
        crate::readdir::emit_names(inode, ctx, names.iter().map(String::as_str),
            FileType::Directory)
    }
}

/// One subsystem's own directory: which name, and which root renders it.
struct SubsystemData {
    name: String,
    root: &'static str,
}

struct SubsystemDirOps;

impl SubsystemDirOps {
    /// `devices`/`drivers` target, relative to `/sys/subsystem/<name>`. # C: O(len)
    fn link(data: &SubsystemData, entry: &str) -> Vec<u8> {
        match data.root {
            BUS_ROOT => alloc::format!("../../{BUS_ROOT}/{}/{entry}", data.name),
            _ => alloc::format!("../../{CLASS_ROOT}/{}", data.name),
        }.into_bytes()
    }

    /// A class has devices only; a bus has drivers too. # C: O(1)
    fn entries(data: &SubsystemData) -> &'static [&'static str] {
        if data.root == BUS_ROOT { &[DEVICES, DRIVERS] } else { &[DEVICES] }
    }
}

impl InodeOps for SubsystemDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let data = inode.private::<SubsystemData>().ok_or(VfsError::Einval)?;
        if !Self::entries(data).contains(&name) { return Err(VfsError::Enoent); }
        Ok(crate::make_symlink_inode(SubsystemDirOps::link(data, name)))
    }
}

impl FileOps for SubsystemDirOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let data = inode.private::<SubsystemData>().ok_or(VfsError::Einval)?;
        crate::readdir::emit_names(inode, ctx, Self::entries(data).iter().copied(),
            FileType::Symlink)
    }
}

fn make_subsystem_dir_inode(name: String, root: &'static str) -> InodeRef {
    InodeBuilder::new(
        ids::SUBSYSTEM_DIR,
        mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(SubsystemDirOps),
        Arc::new(SubsystemDirOps),
    )
    .private(Arc::new(SubsystemData { name, root }))
    .build()
}

/// Build the `/sys/subsystem` root inode. # C: O(1)
pub(crate) fn make_sys_subsystem_inode() -> InodeRef {
    InodeBuilder::new(
        ids::SUBSYSTEM_ROOT,
        mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(SubsystemRootOps),
        Arc::new(SubsystemRootOps),
    ).build()
}
