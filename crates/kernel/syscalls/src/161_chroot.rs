// `sys_chroot(path)` — slot 161. ABI shim only: path fetch + resolution; the
// directory/permission/capability ladder and the `fs_struct` root install are
// `fs::cwd::set_fs_root` (Linux `fs/open.c SYSCALL_DEFINE1(chroot)`).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_chroot(path)` — slot 161.
/// # C: O(N_path)
pub fn sys_chroot(args: &SyscallArgs) -> i64 {
    let p = args.a0;
    // D1/D2: PATH_MAX errno contract (EFAULT/ENOENT-on-empty/ENAMETOOLONG).
    let path = match crate::namei_common::read_user_path(p) {
        Ok(s)   => s,
        Err(rv) => return rv,
    };
    let s: &str = path.as_str();
    // TEMP (D24, debug-mnt): mount-creating syscall ENTRY trace — chroot into the
    // assembled sandbox root that pins cur_mnt_id 10/11 for the api-mount walks.
    #[cfg(feature = "debug-boot")]
    {
        klog::write_raw(b"[MNTCREATE] syscall=chroot flags=0x0 recursive=false source=<none> target=");
        klog::write_raw(s.as_bytes());
        klog::write_raw(b"\n");
    }
    // chroot(2) accepts absolute and relative paths and FOLLOWS the final
    // symlink (`LOOKUP_FOLLOW`). Both must resolve through the live
    // `(root,cwd)` VFS identities; the stored string is display only.
    // Linux reports the lookup's own errno here — ENOENT/ENOTDIR/ELOOP/EACCES —
    // BEFORE any capability test, so an unprivileged caller naming a missing
    // directory sees ENOENT, not EPERM.
    let root_obj = match crate::pathresolve::resolve_path_raw(s, false) {
        Ok(p)  => p,
        Err(e) => return crate::namei_common::errno_from_vfs(e),
    };
    if !matches!(root_obj.inode.file_type(), vfs::FileType::Directory) {
        trace_chroot_enotdir(s, s, root_obj.mnt_id);
    }
    ::fs::cwd::set_fs_root(root_obj, &crate::pathresolve::current_cred(), may_chroot)
}

/// Linux `ns_capable(current_user_ns(), CAP_SYS_CHROOT)` — the capability must
/// be held in the CALLER's user namespace, not merely in its effective set with
/// no namespace scoping. # C: O(userns-depth)
fn may_chroot() -> bool {
    let Some(cur) = sched::live::current() else { return false };
    let Some(user_ns) = cur.namespace_owner(namespace_identity::NamespaceKind::User) else {
        return false;
    };
    nscg::proc_ns::has_cap_for(&cur, &user_ns.pin(), sched::cap::SYS_CHROOT)
}

#[cfg(feature = "debug-boot")]
fn trace_chroot_enotdir(raw: &str, resolved: &str, mnt_id: u64) {
    klog::write_raw(b"[ENOTDIR] op=chroot why=target-not-dir tid=");
    klog::write_dec_u64(sched::live::current().map(|c| c.tid as u64).unwrap_or(0));
    klog::write_raw(b" raw=");
    klog::write_raw(raw.as_bytes());
    klog::write_raw(b" resolved=");
    klog::write_raw(resolved.as_bytes());
    klog::write_raw(b" mnt=");
    klog::write_dec_u64(mnt_id);
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-boot"))]
fn trace_chroot_enotdir(_raw: &str, _resolved: &str, _mnt_id: u64) {}
