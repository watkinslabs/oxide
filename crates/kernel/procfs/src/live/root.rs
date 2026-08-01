use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{CookieEntry, DirContext, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError, mk_mode};

const PROC_ROOT_DIR_MODE: u16 = 0o555;

use super::pid_dir::{make_proc_pid_dir, pid_to_kernel_tid};

pub struct ProcRootInode {
    children: BTreeMap<String, InodeRef>,
}

fn proc_root_lookup(d: &ProcRootInode, name: &str) -> KResult<InodeRef> {
    if let Some(i) = d.children.get(name) {
        return Ok(i.clone());
    }
    if name == "self" {
        return Ok(crate::proc_links::make_proc_self_link());
    }
    if name == "thread-self" {
        return Ok(crate::proc_links::make_proc_thread_self_link());
    }
    if let Some(i) = crate::reg::proc_reg().lookup_path(name) {
        return Ok(i);
    }
    let vpid: u32 = name.parse().map_err(|_| VfsError::Enoent)?;
    let tid = pid_to_kernel_tid(vpid).ok_or(VfsError::Enoent)?;
    Ok(make_proc_pid_dir(tid, false, true))
}

struct ProcRootOps;

impl InodeOps for ProcRootOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<ProcRootInode>().ok_or(VfsError::Einval)?;
        proc_root_lookup(d, name)
    }

    /// The per-pid directories — and, by `d_op` inheritance, everything under
    /// them — carry `pid_dentry_operations`. `/proc`'s static children and the
    /// `self`/`thread-self` magic symlinks (which recompute their target on
    /// every read) do not. # C: O(name.len())
    fn child_d_op(&self, _inode: &Inode, name: &str) -> Option<&'static vfs::dentry::DentryOps> {
        if name.parse::<u32>().is_ok() { Some(&super::pid_reval::PID_DENTRY_OPS) } else { None }
    }
}

impl FileOps for ProcRootOps {
    /// The pid set is re-snapshotted on every call, so an ordinal cursor over it
    /// is not a `d_off`: one process exiting mid-listing shifts every later
    /// ordinal. Cookies come from the name (`crate::readdir`). # C: O(N log N)
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let d = inode.private::<ProcRootInode>().ok_or(VfsError::Einval)?;
        // Statically registered children hold their inode already — no lookup.
        let mut es: Vec<CookieEntry> = d.children.iter()
            .map(|(n, c)| CookieEntry::new(n.clone(), c.ino(), c.file_type()))
            .collect();
        let vpids = sched::live::registry::live_vpids();
        crate::readdir::push_resolved(&mut es, crate::readdir::proc_root_dynamic(&vpids),
            |n| inode.lookup(n).ok().map(|i| i.ino()));
        vfs::emit_by_cookie(&mut es, ctx)
    }
}

pub fn make_proc_root(children: BTreeMap<String, InodeRef>) -> InodeRef {
    InodeBuilder::new(
        crate::ids::PROC_ROOT,
        mk_mode(FileType::Directory, PROC_ROOT_DIR_MODE),
        Arc::new(ProcRootOps),
        Arc::new(ProcRootOps),
    )
    .private(Arc::new(ProcRootInode { children }))
    .build()
}
