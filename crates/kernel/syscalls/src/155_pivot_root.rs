// 155 pivot_root — one syscall, one file (docs/53 §0).
// Shim only: `pivot_root_policy` owns the lookup/EPERM sequence and
// `vfs::mount::pivot_root_from` owns the admission ladder + re-parent.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use alloc::sync::Arc;

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::mount_common::read_user_path_required;
use crate::namei_common::errno_from_vfs;
use crate::pivot_root_policy::{Arg, PivotOps};

struct KernelPivotOps {
    new_raw: u64,
    old_raw: u64,
    /// `struct path new` — resolved with LOOKUP_FOLLOW, so it has crossed into
    /// whatever is mounted at `new_root`.
    new_path: Option<vfs::VfsPath>,
    old_path: Option<vfs::VfsPath>,
    /// The mountpoint dentry the new-root mount is grafted at. A plain resolve
    /// crosses in and yields the mount's ROOT dentry — ambiguous for a bind
    /// (which shares its source root dentry) and unmatchable by the
    /// mountpoint-dentry-keyed mount lookup; that was the "new_root not a mount
    /// root" EINVAL that broke systemd service mount-namespacing
    /// (ProtectSystem= et al) and deadlocked sysinit.
    new_mountpoint: Option<Arc<vfs::dentry::Dentry>>,
}

/// `user_path_at(..., LOOKUP_FOLLOW | LOOKUP_DIRECTORY)`. The walk itself
/// reports ENOENT / ENOTDIR / ELOOP / EACCES, and it runs before
/// `may_mount()`, so those beat EPERM.
fn resolve_directory(raw: u64) -> Result<(vfs::VfsPath, String), i64> {
    let name = read_user_path_required(raw)?;
    let path = crate::pathresolve::resolve_path_raw(&name, false).map_err(errno_from_vfs)?;
    if path.inode.file_type() != vfs::FileType::Directory {
        return Err(-(Errno::Enotdir.as_i32() as i64));
    }
    Ok((path, name))
}

impl PivotOps for KernelPivotOps {
    fn lookup_directory(&mut self, arg: Arg) -> Result<(), i64> {
        let raw = match arg { Arg::NewRoot => self.new_raw, Arg::PutOld => self.old_raw };
        let (path, name) = resolve_directory(raw)?;
        match arg {
            Arg::NewRoot => {
                // Second walk, non-crossing, purely to recover the mountpoint
                // dentry the mount tree is keyed by. It cannot introduce a
                // failure the crossing walk above did not already report.
                self.new_mountpoint = crate::pathresolve::resolve_mount_target_raw(&name)
                    .ok().map(|(t, _)| t.mountpoint);
                self.new_path = Some(path);
            }
            Arg::PutOld => self.old_path = Some(path),
        }
        Ok(())
    }

    fn may_mount(&mut self) -> bool {
        let Some(cur) = sched::live::current() else { return false; };
        // Linux `may_mount()` is `ns_capable(current->nsproxy->mnt_ns->user_ns,
        // CAP_SYS_ADMIN)`: the capability must be held in the user namespace
        // that OWNS the mount namespace being modified, not merely present in
        // the caller's own effective set.
        match cur.mount_namespace_snapshot() {
            Some(mnt_ns) => nscg::proc_ns::has_cap_for(
                &cur, &mnt_ns.owner_user_namespace(), sched::cap::SYS_ADMIN),
            None => false,
        }
    }

    fn commit(&mut self) -> Result<(), i64> {
        let einval = -(Errno::Einval.as_i32() as i64);
        let (Some(new_path), Some(old_path)) = (self.new_path.as_ref(), self.old_path.as_ref())
            else { return Err(einval); };
        // `get_fs_root(current->fs, &root)` plus `path_mounted(&root)`.
        let root = current_root().ok_or(einval)?;
        // Prefer the mountpoint dentry; fall back to the crossed dentry so a
        // `new_root` naming no mount at all still carries an identity the
        // ladder can reject with the errno Linux gives it.
        let nr_d = self.new_mountpoint.clone().unwrap_or_else(|| new_path.dentry.clone());
        #[cfg(feature = "debug-mount")]
        {
            klog::write_raw(b"[MNTCREATE] syscall=pivot_root flags=0x0 recursive=false target=");
            klog::write_raw(vfs::mount::render_path_for_mount(
                old_path.mnt_id, &old_path.dentry).as_bytes());
            klog::write_raw(b"\n");
        }
        vfs::mount::pivot_root_from(&nr_d, &old_path.dentry, root).map_err(errno_from_vfs)
    }
}

/// The caller's root as `path_pivot_root()` reads it. `path_mounted(&root)` is
/// "the root dentry IS its mount's root dentry", false exactly when the task
/// chrooted into a plain directory — which Linux rejects with EINVAL.
fn current_root() -> Option<vfs::mount::PivotRoot> {
    let cur = sched::live::current()?;
    let ns = sched::live::current_mount_ns();
    let snap = cur.fs_context_snapshot();
    let (mnt_id, dentry) = match snap.root_vfs() {
        Some(p) if p.mnt_id != vfs::mount::MNT_ID_NONE => (p.mnt_id, Some(p.dentry)),
        // No recorded root path: the task's root is the namespace root, which
        // is a mount root by definition.
        _ => (vfs::mount::root_mount_id(ns)?, None),
    };
    let path_mounted = match dentry {
        None => true,
        Some(d) => vfs::mount::root_dentry_for_mount_id(mnt_id)
            .map(|r| Arc::ptr_eq(&r, &d)).unwrap_or(false),
    };
    Some(vfs::mount::PivotRoot { mnt_id, path_mounted })
}

/// `sys_pivot_root(new_root, put_old)` — slot 155. Makes the mount at
/// `new_root` the namespace root and relocates the old root tree under
/// `put_old` (`docs/16§6`). Requires CAP_SYS_ADMIN in the user namespace owning
/// the mount namespace. Paths resolve like normal Linux pathnames, so relative
/// arguments are interpreted against cwd.
/// # C: O(N_mounts)
pub fn sys_pivot_root(args: &SyscallArgs) -> i64 {
    if sched::live::current().is_none() { return -(Errno::Esrch.as_i32() as i64); }
    let mut ops = KernelPivotOps {
        new_raw: args.a0, old_raw: args.a1,
        new_path: None, old_path: None, new_mountpoint: None,
    };
    match crate::pivot_root_policy::pivot_root(&mut ops) {
        Ok(()) => 0,
        Err(rv) => rv,
    }
}
