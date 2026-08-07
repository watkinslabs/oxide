use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{CookieEntry, DirContext, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError, mk_mode};

const PROC_ROOT_DIR_MODE: u16 = 0o555;

use super::pid_dir::{make_proc_pid_dir, pid_to_kernel_tid};

pub struct ProcRootInode {
    children: BTreeMap<String, InodeRef>,
    /// THIS MOUNT's identity (Linux `sb->s_fs_info`). Every mount builds its own
    /// root, so `hidepid=`/`subset=` are answers this mount owns rather than
    /// properties of the process asking.
    info: Arc<crate::fs_info::ProcFsInfo>,
    /// The user namespace the mount fixed for credential copy-out.
    user_ns: namespace_identity::NamespaceRef,
}

fn proc_root_lookup(d: &ProcRootInode, name: &str) -> KResult<InodeRef> {
    // `subset=pid` (Linux `proc_lookup`: `if (fs_info->pidonly ==
    // PROC_PIDONLY_ON) return ERR_PTR(-ENOENT)`) removes every non-process
    // entry from the mount. The `self`/`thread-self` links and the pid
    // directories below survive it — the reference creates those in
    // `proc_fill_super` rather than as PDE lookups, so the gate never sees
    // them.
    let statics_visible = crate::fs_info::static_entries_visible(&d.info);
    if statics_visible {
        if let Some(i) = d.children.get(name) {
            return Ok(i.clone());
        }
    }
    if name == "self" {
        return Ok(crate::proc_links::make_proc_self_link());
    }
    if name == "thread-self" {
        return Ok(crate::proc_links::make_proc_thread_self_link());
    }
    if statics_visible {
        if let Some(i) = crate::reg::proc_reg().lookup_path(name) {
            return Ok(i);
        }
    }
    let vpid: u32 = name.parse().map_err(|_| VfsError::Enoent)?;
    let tid = pid_to_kernel_tid(vpid).ok_or(VfsError::Enoent)?;
    // `hidepid` at the ACCESS threshold (Linux `proc_pid_lookup` →
    // `has_pid_permissions(fs_info, task, HIDEPID_NO_ACCESS)`): a directory the
    // reader may not reach reports ENOENT, not EPERM, so the existence of the
    // process is not disclosed by the errno.
    if !super::pid_access::pid_visible(&d.info, tid, crate::fs_info::HidePid::NoAccess) {
        return Err(VfsError::Enoent);
    }
    Ok(make_proc_pid_dir(tid, false, true, d.user_ns.clone()))
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
        // `subset=pid` (Linux `proc_readdir`: `if (fs_info->pidonly ==
        // PROC_PIDONLY_ON) return 1` — emit nothing and report the directory
        // exhausted) leaves only the process entries.
        let mut es: Vec<CookieEntry> = if crate::fs_info::static_entries_visible(&d.info) {
            d.children.iter()
                .map(|(n, c)| CookieEntry::new(n.clone(), c.ino(), c.file_type()))
                .collect()
        } else {
            Vec::new()
        };
        // `hidepid` at the VISIBILITY threshold (Linux `proc_pid_readdir` →
        // `has_pid_permissions(fs_info, iter.task, HIDEPID_INVISIBLE)`): a
        // process the reader may not see is left out of the listing entirely.
        // `hidepid=off` keeps the whole snapshot, so the default `/proc` listing
        // costs exactly what it did.
        let mut vpids = sched::live::registry::live_vpids();
        if d.info.hide_pid != crate::fs_info::HidePid::Off {
            vpids.retain(|vpid| match pid_to_kernel_tid(*vpid) {
                Some(tid) => super::pid_access::pid_visible(
                    &d.info, tid, crate::fs_info::HidePid::Invisible),
                None => false,
            });
        }
        crate::readdir::push_resolved(&mut es, crate::readdir::proc_root_dynamic(&vpids),
            |n| inode.lookup(n).ok().map(|i| i.ino()));
        vfs::emit_by_cookie(&mut es, ctx)
    }
}

/// Build ONE mount's `/proc` root. Called per mount — the reference builds a
/// fresh root inode in `proc_fill_super` for every superblock and shares only
/// the static `proc_dir_entry` skeleton between them. # C: O(N static files)
pub fn make_proc_root(children: BTreeMap<String, InodeRef>,
                      info: Arc<crate::fs_info::ProcFsInfo>,
                      user_ns: namespace_identity::NamespaceRef) -> InodeRef {
    InodeBuilder::new(
        crate::ids::PROC_ROOT,
        mk_mode(FileType::Directory, PROC_ROOT_DIR_MODE),
        Arc::new(ProcRootOps),
        Arc::new(ProcRootOps),
    )
    .private(Arc::new(ProcRootInode { children, info, user_ns }))
    .build()
}
