use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use syscall::errno::Errno;
use vfs::InodeRef;
use vfs::namei::root_dentry;

pub(super) fn current_cred() -> vfs::Cred {
    let Some(c) = sched::current() else { return vfs::Cred::root(); };
    let eff = c.creds.cap_effective.load(Ordering::Acquire);
    let uid = c.creds.fsuid.load(Ordering::Acquire);
    let gid = c.creds.fsgid.load(Ordering::Acquire);
    let ng = (c.creds.ngroups.load(Ordering::Acquire) as usize).min(vfs::CRED_NGROUPS);
    let mut groups = [0u32; vfs::CRED_NGROUPS];
    // SAFETY: groups slot follows the task single-mutator credential rule.
    unsafe {
        let g = &*c.creds.groups.get();
        groups[..ng].copy_from_slice(&g[..ng]);
    }
    let has = |cap: u32| eff & (1u64 << cap) != 0;
    vfs::Cred {
        uid,
        gid,
        cap_dac_override: has(sched::cap::DAC_OVERRIDE),
        cap_dac_read_search: has(sched::cap::DAC_READ_SEARCH),
        cap_fowner: has(sched::cap::FOWNER),
        cap_chown: has(sched::cap::CHOWN),
        cap_fsetid: has(sched::cap::FSETID),
        ngroups: ng as u32,
        groups,
    }
}

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn namespace_root() -> Result<vfs::VfsPath, i64> {
    let global = root_dentry().ok_or(errno(Errno::Enoent))?;
    let ns = vfs::mount::current_ns();
    let (mnt_id, dentry) = vfs::mount::namespace_root_path(ns, &global)
        .unwrap_or((vfs::mount::MNT_ID_NONE, global));
    let inode = dentry.inode().ok_or(errno(Errno::Enoent))?;
    Ok(vfs::VfsPath { mnt_id, dentry, inode, last_component: None })
}

fn current_start_root() -> Result<(vfs::VfsPath, vfs::VfsPath), i64> {
    let cur = sched::current().ok_or(errno(Errno::Ebadf))?;
    let snapshot = cur.fs_context_snapshot();
    let root = snapshot.root_vfs().unwrap_or(namespace_root()?);
    let start = snapshot.cwd_vfs().unwrap_or_else(|| root.clone());
    Ok((start, root))
}

pub(super) fn resolve_watch_path(raw: &str, no_follow_final: bool, only_dir: bool) -> Result<InodeRef, i64> {
    let (start, root) = current_start_root()?;
    resolve_watch_path_at(
        start.dentry,
        start.mnt_id,
        root.dentry,
        root.mnt_id,
        raw,
        no_follow_final,
        only_dir,
        current_cred(),
    )
}

pub(crate) fn resolve_watch_path_at(
    start: Arc<vfs::Dentry>,
    start_mnt_id: u64,
    root: Arc<vfs::Dentry>,
    root_mnt_id: u64,
    raw: &str,
    no_follow_final: bool,
    only_dir: bool,
    cred: vfs::Cred,
) -> Result<InodeRef, i64> {
    let flags = vfs::LookupFlags {
        no_follow_final,
        follow: !no_follow_final,
        directory: only_dir,
        ..Default::default()
    };
    vfs::path_lookup_at_root_cred(
        start,
        start_mnt_id,
        root,
        root_mnt_id,
        raw,
        flags,
        cred,
    ).and_then(|p| {
        vfs::inode_permission(&p.inode, vfs::MAY_READ, &cred)?;
        Ok(p.inode)
    }).map_err(|e| -(e as i64))
}
