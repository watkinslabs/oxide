// 432 fsmount — one syscall, one file (docs/53 §0). Every decision this call
// makes without a mount tree lives in `crate::fsmount_abi`, which is ungated
// and therefore covered by hosted tests; what is left here is the part that
// needs the kernel: sample the capabilities, take the context lock, build the
// mount, install the descriptor.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::fsmount_abi::{self, FsmountCaps};
use crate::fsmount_common::*;

/// `sys_fsmount(fs_fd, flags, attr_flags)` — slot 432. Materialises a real
/// mount from the realized `fs_context` and returns a descriptor for it: an
/// `O_PATH` fd over the mount, or — with `FSMOUNT_NAMESPACE` — a mount-namespace
/// fd holding it.
/// # C: O(1)
pub fn sys_fsmount(args: &SyscallArgs) -> i64 {
    let caps = sample_caps();
    let admitted = match fsmount_abi::admit(args.a1, args.a2, caps) {
        Ok(a)  => a,
        Err(e) => return -(e.as_i32() as i64),
    };
    let fd = args.a0 as i32;
    let inode = match fd_inode(fd) { Some(i) => i, None => return -(Errno::Ebadf.as_i32() as i64) };
    let ctx = match inode.private::<FsContextInode>() {
        Some(c) => c, None => return -(Errno::Einval.as_i32() as i64),
    };
    // The superblock was realized at `fsconfig(FSCONFIG_CMD_CREATE)`. The
    // context MUST be `AwaitingMount` with a pinned root; the ladder below is
    // the reference's, in its order.
    let mut g = ctx.fc.lock();
    let Some(fc) = g.as_mut() else { return -(Errno::Einval.as_i32() as i64) };
    // No realized root → EINVAL. Too-revealing → EPERM. Wrong phase → EBUSY.
    // The phase rung is LAST and it is EBUSY, not EINVAL — "the context exists
    // but is not holding a mountable tree right now" is a retry condition, and
    // it is what a SECOND fsmount on one context fd reports once the first has
    // cleaned it back to the fspick state.
    let sb = match (fc.sb(), fc.root()) {
        (Some(sb), Some(_)) => sb.clone(),
        _ => return -(Errno::Einval.as_i32() as i64),
    };
    // `mnt_flags` is the MOUNT_ATTR_* request mapped into the MNT_* option
    // space, exactly what the mount will carry. The locked attributes the
    // visibility gate feeds back travel on the mount object.
    let mnt_flags = vfs::mount::mount_attr_to_mnt(admitted.attrs);
    let mut lock_flags = match vfs::mount::mount_too_revealing(&sb, mnt_flags) {
        Ok(l) => l,
        Err(_) => {
            // The errno is shared with the privilege rungs, so without this the
            // caller cannot tell WHICH refusal it hit; `read(2)` on the context
            // fd is where it finds out.
            fc.errorf(fsmount_abi::TOO_REVEALING_MSG);
            return -(Errno::Eperm.as_i32() as i64);
        }
    };
    if fc.phase() != vfs::fs::FsContextPhase::AwaitingMount {
        return -(Errno::Ebusy.as_i32() as i64);
    }
    // Mandatory locking is accepted and does nothing; announcing it is the only
    // way an administrator learns the semantics they asked for are not in
    // force. It goes on the context's own warning channel, which is what
    // `read(2)` on this descriptor returns — the caller that set the option is
    // the party that needs to hear it, and it can.
    if fsmount_abi::warns_mandlock(fc.sb_flags()) { fc.warnf(fsmount_abi::MANDLOCK_MSG); }
    if crate::mount_perm::current_user_ns_differs_from_mount_ns_owner() {
        lock_flags |= vfs::mount::lock_new_mount_bits(mnt_flags);
    }
    // The mount is REAL from here: its own id, its own root, belonging to a
    // namespace no task is in until `move_mount(2)` (anonymous form) or until
    // someone enters it (namespace form).
    let created = if admitted.namespace {
        vfs::mount::create_ns_mount(sb, mnt_flags, lock_flags, None).map(|(m, ns)| (m, Some(ns)))
    } else {
        vfs::mount::create_anon_mount(sb, mnt_flags, lock_flags, None).map(|m| (m, None))
    };
    // The namespace reference travels with the mount for the namespace form and
    // MUST be held until the descriptor takes it: nothing else refers to a
    // freshly named namespace, and dropping it here would reap the mount.
    let (anon, new_ns) = match created {
        Ok(pair) => pair,
        Err(e) => return crate::namei_common::errno_from_vfs(e),
    };
    // A filesystem marks its superblock unmountable-by-user while filling it,
    // so this is the first point the fact exists. The mount is undone rather
    // than handed back.
    if let Err(e) = fsmount_abi::admit_created_sb(anon.sb().s_flags()) {
        vfs::mount::dissolve_anon(&anon);
        return -(e.as_i32() as i64);
    }
    let (Some(mnt_root), Some(root_inode)) =
        (anon.mnt_root(), anon.mnt_root().and_then(|d| d.inode()))
    else {
        vfs::mount::dissolve_anon(&anon);
        return -(Errno::Einval.as_i32() as i64);
    };
    // `vfs_clean_context(fc)`: the mount is made, so the context returns to the
    // state an `fspick(2)` leaves behind. Without this a caller could fsmount
    // one context fd repeatedly and mint N mounts from a single superblock.
    vfs::fs::vfs_clean_context(fc);
    drop(g);
    if let Some(ns) = new_ns {
        // The namespace form's descriptor is the NAMESPACE, not the mount: it
        // is what `setns(2)` takes, and holding it is what keeps the namespace
        // — and so the mount inside it — alive.
        return install_fd(nscg::proc_ns::mnt_ns_inode(ns), "[mntns]", admitted.cloexec);
    }
    // A real path fd over (mount, root dentry): it carries the mount id,
    // resolves as a dirfd, and dissolves its mount if closed unmoved.
    let path = vfs::VfsPath {
        mnt_id: anon.mnt_id, dentry: mnt_root, inode: root_inode, last_component: None,
    };
    install_mount_path_fd(path, anon.mnt_id, admitted.cloexec)
}

/// The two capability facts the flag word chooses between, sampled before the
/// context lock (the capability walk reads scheduler state). Both are taken
/// because which one applies is settled inside the ungated admission.
/// # C: O(userns depth)
fn sample_caps() -> FsmountCaps {
    FsmountCaps {
        cap_sys_admin_current_user_ns: crate::mount_perm::cap_sys_admin_in_current_user_ns(),
        may_mount: crate::mount_perm::may_mount(),
    }
}
