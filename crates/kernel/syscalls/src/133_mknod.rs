// 133 mknod — one syscall, one file (docs/53 §0). Hosts the shared ABI shim
// core (also used by 259_mknodat): path resolution, the security ladder, the
// backend call and the dcache update. The type/mode/capability DECISION is
// `fs::mknod` (Linux `may_mknod` + the type-dependent half of `vfs_mknod`).

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use ::fs::mknod::{may_mknod, MayMknod, NodeType};
use crate::namei_common::{
    read_user_path, errno_from_vfs, resolve_create_parent_at, render_child_path,
    parent_mount_readonly, drop_child_cache,
};

/// `mknod(path, mode, dev)` slot 133.
/// # C: O(N parent entries)
pub fn sys_mknod(args: &SyscallArgs) -> i64 {
    // D1/D2: PATH_MAX errno contract (EFAULT/ENOENT-on-empty/ENAMETOOLONG).
    let raw = match read_user_path(args.a0) {
        Ok(s) => s, Err(rv) => return rv,
    };
    mknod_impl(crate::pathresolve::AT_FDCWD, raw, args.a1 as u16, args.a2 as u32)
}

/// Landlock right the new node's type consumes. # C: O(1)
fn landlock_right(t: NodeType) -> u64 {
    use ::landlock::uapi as access;
    match t {
        NodeType::Reg  => access::ACCESS_FS_MAKE_REG,
        NodeType::Chr  => access::ACCESS_FS_MAKE_CHAR,
        NodeType::Blk  => access::ACCESS_FS_MAKE_BLOCK,
        NodeType::Fifo => access::ACCESS_FS_MAKE_FIFO,
        NodeType::Sock => access::ACCESS_FS_MAKE_SOCK,
    }
}

/// # C: O(N parent entries)
pub(crate) fn mknod_impl(dirfd: i32, raw: String, mode: u16, dev: u32) -> i64 {
    // Linux `may_mknod` runs BEFORE `filename_create`: a bad type reports its
    // errno without regard to whether the path exists or the parent is writable.
    let ntype = match may_mknod(mode) {
        MayMknod::Ok(t)  => t,
        MayMknod::Eperm  => return -(Errno::Eperm.as_i32() as i64),
        MayMknod::Einval => return -(Errno::Einval.as_i32() as i64),
    };
    let (parent, name) = match resolve_create_parent_at(dirfd, &raw) {
        Ok(x) => x, Err(rv) => return rv,
    };
    let p = render_child_path(&parent, &name);
    if let Err(rv) = crate::namei_common::check_create_leaf(
        &parent, &name, &raw, crate::path_ops_policy::CreateKind::NonDir) { return rv; }
    if parent_mount_readonly(&parent) {
        return -(Errno::Erofs.as_i32() as i64);
    }
    if let Err(rv) = crate::landlock::check_parent(&parent, landlock_right(ntype)) { return rv; }
    let cred = crate::pathresolve::current_cred();
    if let Err(e) = vfs::may_create(&parent.inode, &cred) {
        return errno_from_vfs(e);
    }
    // Linux `vfs_mknod`: CAP_MKNOD (device nodes only, and never the `0:0`
    // character whiteout), then device-cgroup policy, then LSM/backend.
    if ntype.needs_cap_mknod(dev) {
        let has = sched::live::current()
            .map(|c| c.has_cap(sched::cap::MKNOD)).unwrap_or(false);
        if !has { return -(Errno::Eperm.as_i32() as i64); }
    }
    if ntype.needs_devcg(dev) {
        let kind = if ntype == NodeType::Chr {
            ::security::bpf::DEVCG_DEV_CHAR
        } else {
            ::security::bpf::DEVCG_DEV_BLOCK
        };
        let (major, minor) = NodeType::dev_major_minor(dev);
        if let Err(e) = ::security::bpf::check_device_access(
            kind, major, minor, ::security::bpf::DEVCG_ACC_MKNOD,
        ) {
            return -(e.as_i32() as i64);
        }
    }
    // A new name changes the directory, so a directory delegation on the parent
    // is recalled before the node appears. Placed after every permission gate
    // above: a caller who may not create here must not be able to recall
    // someone else's delegation, and before the backend call, because the
    // holder's cached listing must be invalidated before it goes stale.
    if let Some(rv) = crate::deleg_break::break_deleg_for_mutation(&parent.inode) { return rv; }
    let umask = sched::live::current()
        .map(|c| c.umask()).unwrap_or(0) as u16;
    // Thread the mount idmap + caller cred + umask so the new node gets the
    // right owner (Linux `->mknod`/`->create(struct mnt_idmap *, ...)`).
    let ctx = vfs::CreateCtx { idmap: &vfs::IDENTITY, cred: &cred, umask };
    // D29: parent dir `i_rwsem` EXCLUSIVE across the backend create/mknod (Linux
    // `filename_create` → `->create`/`->mknod`); dropped before the dcache update.
    let perm = mode & !::fs::mknod::S_IFMT;
    let r = {
        let _g = parent.inode.inode_lock();
        if ntype == NodeType::Reg {
            // POSIX-compat: mknod-with-regular-type = open(O_CREAT) equivalent.
            parent.inode.create_child(&name, perm as u32, &ctx).map(|_| ())
        } else {
            parent.inode.mknod_child(&name, ntype.ifmt() | perm, ntype.node_dev(dev), &ctx)
        }
    };
    match r {
        Ok(())  => {
            drop_child_cache(&parent, &name);
            // `mknod` never creates a directory (`S_IFDIR` is EPERM above), so
            // the create notification is always the non-directory form.
            vfs::fire_dirent_create(&parent.inode, &name, false);
            0
        }
        Err(e)  => {
            crate::namei_common::trace_run_vfs_error(b"mknod", &p, e);
            errno_from_vfs(e)
        }
    }
}
