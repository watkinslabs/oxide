// 166 umount2 — one syscall, one file (docs/53 §0).
//
// `sys_umount2(target, flags)`, shaped as Linux's `ksys_umount`
// → `path_umount` → `can_umount` + `do_umount`: validate the flag word, resolve
// the target, run `can_umount`'s rungs, then the `do_umount` ladder (owned as a
// pure decision by `vfs::mount::umount_check`), fire `s_op->umount_begin` when
// `MNT_FORCE` asked for it, and detach.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::mount_common::read_user_path_required;

/// `sys_umount2(target, flags)` — slot 166. `MNT_FORCE` / `MNT_DETACH` /
/// `MNT_EXPIRE` / `UMOUNT_NOFOLLOW` all carry their Linux meaning; the refusal
/// ladder and its errnos are [`vfs::mount::umount_check`].
/// # C: O(N_subtree)
pub fn sys_umount2(args: &SyscallArgs) -> i64 {
    let rv = sys_umount2_impl(args);
    #[cfg(feature = "debug-mount")]
    {
        if let Ok(tgt) = read_user_path_required(args.a0) {
            crate::mount_common::mnt_log("umount2", &tgt, rv);
        }
    }
    rv
}

fn sys_umount2_impl(args: &SyscallArgs) -> i64 {
    // Linux ksys_umount flag gate (D53): reject unknown bits, and MNT_EXPIRE is
    // mutually exclusive with MNT_FORCE/MNT_DETACH — both before the path walk.
    use vfs::mount::{MNT_DETACH, MNT_EXPIRE, MNT_FORCE, UMOUNT_NOFOLLOW, UMOUNT_VALID};
    let flags = args.a1;
    if flags & !UMOUNT_VALID != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    if (flags & MNT_EXPIRE) != 0 && (flags & (MNT_FORCE | MNT_DETACH)) != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    let target_ptr = args.a0;
    let path_raw = match read_user_path_required(target_ptr) {
        Ok(p) => p, Err(rv) => return rv,
    };
    let no_follow = (flags & UMOUNT_NOFOLLOW) != 0;
    let resolved = match crate::pathresolve::resolve_path_raw(&path_raw, no_follow) {
        Ok(p) => p,
        Err(e) => return crate::namei_common::errno_from_vfs(e),
    };
    // Linux `ksys_umount` resolves the path (`user_path_at`) BEFORE `path_umount`
    // → `can_umount`, whose rungs run in THIS order: `may_mount()`,
    // `path_mounted()`, `check_mnt()`, `MNT_LOCKED`, then the `MNT_FORCE`
    // capability demand. The force rung used to run second, so a forced unmount
    // of a plain directory reported EPERM where Linux reports EINVAL.
    if let Some(rv) = crate::mount_perm::may_mount_or_eperm() { return rv; }
    // `path_mounted(path)`: the resolved dentry IS the mount's root. The walk
    // crosses into the mounted filesystem at the final component, so a mount
    // target lands on that filesystem's root dentry; anything else names a
    // directory inside a filesystem, not a mount.
    let at_mount_root = vfs::mount::root_dentry_for_mount_id(resolved.mnt_id)
        .map(|r| Arc::ptr_eq(&resolved.dentry, &r)).unwrap_or(false);
    if !at_mount_root { return -(Errno::Einval.as_i32() as i64); }
    let Some(target_mount) = vfs::mount::mount_by_id(resolved.mnt_id) else {
        return -(Errno::Einval.as_i32() as i64);
    };
    // `check_mnt` + the optimistic `MNT_LOCKED` test. `do_umount` repeats both
    // under the namespace lock (they live in [`vfs::mount::umount_check`]);
    // Linux tests them here first because they are cheap and they must outrank
    // the force rung.
    if !vfs::mount::check_mnt(&target_mount) { return -(Errno::Einval.as_i32() as i64); }
    if target_mount.is_locked() { return -(Errno::Einval.as_i32() as i64); }
    // `if (flags & MNT_FORCE && !ns_capable(sb->s_user_ns, CAP_SYS_ADMIN))
    // return -EPERM` — a forced unmount needs authority over the FILESYSTEM's
    // user namespace, a strictly stronger demand than may_mount.
    if (flags & MNT_FORCE) != 0 && !cur.has_cap(sched::cap::SYS_ADMIN) {
        return -(Errno::Eperm.as_i32() as i64);
    }
    let _display = vfs::mount::render_path_for_mount(resolved.mnt_id, &resolved.dentry);
    let namespace = match cur.mount_namespace_snapshot() {
        Some(namespace) => namespace,
        None => return -(Errno::Esrch.as_i32() as i64),
    };
    let _ns = namespace.id();

    // Linux `do_umount`'s admission ladder over the resolved mount. The three
    // rungs this had never applied: MNT_EXPIRE's two-pass grace (an autofs
    // expiry that unmounts on the FIRST call tears mounts down the moment they
    // go briefly idle), MNT_LOCKED (an unprivileged user namespace must not
    // reveal what a locked mount covers), and `check_mnt`.
    let root_mnt = cur.fs_context_snapshot().root_vfs().map(|r| r.mnt_id);
    let Some(facts) = vfs::mount::umount_facts(
        resolved.mnt_id, flags, root_mnt, cur.has_cap(sched::cap::SYS_ADMIN)) else {
        return -(Errno::Einval.as_i32() as i64);
    };
    let plan = vfs::mount::umount_check(flags, &facts);
    // `if (flags & MNT_FORCE && sb->s_op->umount_begin) sb->s_op->umount_begin(sb)`
    // — the whole reason MNT_FORCE exists: a mount whose server/daemon is gone
    // has callers blocked inside it holding references that keep it busy, and
    // only the filesystem can abort those requests. Fires BEFORE the ladder's
    // remaining rungs are acted on, so a subsequently refused unmount still
    // unwedges them and a retry can succeed.
    if plan.umount_begin {
        let sb = target_mount.sb();
        sb.s_op.umount_begin(&sb);
    }
    let outcome = match plan.outcome {
        Err(vfs::mount::UmountRefusal::Einval) => return -(Errno::Einval.as_i32() as i64),
        Err(vfs::mount::UmountRefusal::Ebusy) => return -(Errno::Ebusy.as_i32() as i64),
        Err(vfs::mount::UmountRefusal::Eagain) => return -(Errno::Eagain.as_i32() as i64),
        Err(vfs::mount::UmountRefusal::Eperm) => return -(Errno::Eperm.as_i32() as i64),
        Ok(o) => o,
    };
    if outcome == vfs::mount::Umount::RemountRootReadonly {
        // Linux `do_umount_root`: "unmounting" the caller's own root
        // reconfigures the superblock read-only rather than detaching it —
        // there is nothing underneath to expose.
        return match vfs::mount::mnt_setattr_attached(
            resolved.mnt_id, vfs::mount::MNT_RDONLY, 0, None, false) {
            Ok(()) => 0,
            Err(e) => crate::namei_common::errno_from_vfs(e),
        };
    }
    // `MNT_DETACH` ⇒ `umount_tree(mnt, UMOUNT_PROPAGATE)`, which takes the whole
    // subtree. A plain umount instead owes the two steps `do_umount` performs
    // past the ladder, in this order:
    //
    //  1. `shrink_submounts(mnt)` — reap the expirable (automounted) submounts
    //     under the target. A mount whose only children are autofs/NFS
    //     short-lived submounts is NOT busy: those are exactly what the
    //     automounter would have reaped on its own next idle sweep, so Linux
    //     reaps them eagerly here. Without it, unmounting an autofs-managed
    //     directory reported EBUSY where Linux succeeds.
    //  2. `propagate_mount_busy(mnt, 2)` — the busy test, which is
    //     PROPAGATION-AWARE: unmounting a mount under a shared parent removes
    //     the mirror copy under every peer and slave too, so a pinned mirror
    //     refuses the whole operation even when the named mount is idle.
    //
    // Both need the live mount tree, so neither can live in the pure ladder;
    // the rules themselves are unit-tested in `vfs::mount::{shrink,busy}`.
    let recursive = outcome == vfs::mount::Umount::DetachTree;
    if !recursive {
        vfs::mount::shrink_submounts(&target_mount);
        if vfs::mount::propagate_mount_busy(&target_mount, vfs::mount::UMOUNT_SYSCALL_REFCNT) {
            return -(Errno::Ebusy.as_i32() as i64);
        }
    }
    // The mount engine detaches by the COVERED mountpoint dentry, so translate
    // the mount id back to it. `umount_check`'s `has_parent` rung already
    // refused a namespace root, which is the only mount without one. Resolved
    // AFTER the shrink: it reaps mounts, never the target itself.
    let Some((target_d, _)) = vfs::mount::mountpoint_of(resolved.mnt_id) else {
        return -(Errno::Einval.as_i32() as i64);
    };
    // `s_dev` of the filesystem this mount exposes, captured while the mount is
    // still in the table so the post-detach "was that the last one?" test below
    // has something to compare against.
    let doomed_fsid = target_mount.sb().s_dev;
    let removed_tab = vfs::mount::unregister_top(&target_d, recursive);
    // Linux reports `FS_UNMOUNT` (and then frees every mark) when the
    // SUPERBLOCK is torn down — `generic_shutdown_super` →
    // `fsnotify_unmount_inodes`/`evict_inodes` — not on each detach. A bind or a
    // second namespace's copy keeps the filesystem alive, so the notice is owed
    // only once no mount refers to it any more. Without it a watcher on a file
    // under an unmounted filesystem is never told, and its `wd` stays live
    // forever pointing at an unreachable object.
    if removed_tab > 0 && doomed_fsid != 0
        && !vfs::mount::all_mounts().iter().any(|m| m.sb().s_dev == doomed_fsid) {
        fs::inotify::fire_unmount(doomed_fsid);
    }
    if removed_tab == 0 {
        #[cfg(feature = "debug-boot")]
        {
            klog::write_raw(b"[umount EINVAL] ns="); klog::write_dec_u64(_ns);
            klog::write_raw(b" lazy="); klog::write_dec_u64(recursive as u64);
            klog::write_raw(b" path="); klog::write_raw(_display.as_bytes());
            klog::write_raw(b"\n");
        }
        return -(Errno::Einval.as_i32() as i64);
    }
    0
}
