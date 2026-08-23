// mount — VFS path-walk hook + mount-ns provider installer (docs/53 §0).
// The mount-family syscall handlers (sys_mount/sys_umount2/sys_pivot_root)
// moved to per-file modules: s165_mount, s166_umount2, s155_pivot_root.
// Shared helper read_user_cstr_owned lives in mount_common.

#![cfg(target_os = "oxide-kernel")]

/// Retain the calling task's mount namespace (`docs/16§6`), or init at boot /
/// kthread context. Installed into `vfs::mount` so `register` can stamp
/// each mount's owning ns without threading it through every call site.
/// # C: O(1)
fn current_mount_ns() -> vfs::mntns::MntNamespaceRef {
    sched::live::current().and_then(sched::Task::mount_namespace_snapshot)
        .unwrap_or_else(vfs::mntns::initial)
}

/// User namespace a superblock built right now belongs to (Linux stamps
/// `sb->s_user_ns` from the MOUNTING task). Boot-time and kernel-internal
/// mounts have no task and get the initial namespace, whose maps are the
/// identity. # C: O(1)
fn current_user_ns() -> Option<namespace_identity::NamespacePin> {
    sched::live::current()?
        .namespace_owner(namespace_identity::NamespaceKind::User)
        .map(|ns| ns.pin())
}

/// Label of the running thread, for a check taken below the task layer. A
/// kernel thread and the pre-task boot window both answer with the kernel's
/// own label, which is the label those contexts genuinely act under. # C: O(1)
fn current_selinux_sid() -> selinux::sidtab::Sid {
    sched::live::current().map_or_else(selinux_runtime::label::kernel_sid,
                                       |c| c.selinux_label.lock().sid)
}

/// Label the running thread staged for the next file it creates. # C: O(1)
fn current_fscreate_sid() -> Option<selinux::sidtab::Sid> {
    sched::live::current().and_then(|c| c.selinux_label.lock().fscreate)
}

/// Linux `capable(CAP_SYS_RESOURCE)` for the quota limit ladder: the holder
/// charges past hard limits and expired grace periods. # C: O(1)
fn quota_has_sys_resource() -> bool {
    sched::live::current().is_some_and(|cur| cur.has_cap(sched::cap::SYS_RESOURCE))
}

/// Ambient identity a filesystem's reserved-block pool is decided from: the
/// id the access is charged to, whether the caller holds the group the volume
/// reserved for (Linux `in_group_p`, which counts the fsgid itself), and
/// `CAP_SYS_RESOURCE`. Read HERE rather than threaded, because the allocation
/// that consults it happens far below the last entry point that carries a
/// credential. # C: O(groups)
fn current_reserved_caller(res_gid: u32) -> vfs::ReservedCaller {
    use core::sync::atomic::Ordering;
    match sched::live::current() {
        None => vfs::ReservedCaller { fsuid: 0, in_res_group: true, cap_sys_resource: true },
        Some(cur) => {
            let fsuid = cur.creds.fsuid.load(Ordering::Acquire);
            let fsgid = cur.creds.fsgid.load(Ordering::Acquire);
            let in_res_group = fsgid == res_gid || cur.creds.vfs_group_list().contains(res_gid);
            vfs::ReservedCaller {
                fsuid, in_res_group,
                cap_sys_resource: cur.has_cap(sched::cap::SYS_RESOURCE),
            }
        }
    }
}

/// Stop the machine because a mount was given `errors=panic` and hit the error
/// it was told not to survive.
///
/// Installed from here because stopping the machine is this layer's business,
/// not a filesystem's: a volume decides that its mount line asked for a halt,
/// and the layer that owns the machine carries it out. The reason is written to
/// the log FIRST — a panic message cannot carry it, and the reason is the whole
/// diagnosis. # C: does not return
fn fs_halt(fs: &'static str, reason: &'static str) {
    klog::write_raw(b"[FATAL] ");
    klog::write_raw(fs.as_bytes());
    klog::write_raw(b": errors=panic, halting after: ");
    klog::write_raw(reason.as_bytes());
    klog::write_raw(b"\n");
    hal::kassert!(false, "filesystem mounted errors=panic hit a critical error");
}

/// Install the VFS path-walk hooks (mount-crossing) AND the mount-ns
/// provider at boot. Resolution is now always per-component
/// (`d_lookup → i_op->lookup → d_add`); there is no whole-path delegate to
/// install (WP2 deleted `FileSystem::lookup`).
/// # C: O(1)
pub fn install_vfs_hooks() {
    vfs::mount::set_current_ns_provider(current_mount_ns);
    vfs::superblock::set_freeze_wait_hooks(
        sched::live::sb_freeze::park,
        sched::live::sb_freeze::schedule_after_park,
        sched::live::sb_freeze::wake,
    );
    vfs::superblock::set_current_user_ns_hook(current_user_ns);
    // Label-based access control over inodes. Installed beside the other VFS
    // hooks so the mandatory decision and the discretionary one are taken on
    // the same path; with no policy loaded it answers allow. The two readers
    // are what make the SUBJECT of a check the running thread rather than the
    // kernel: the label lives on the task, and this is the layer that can see
    // both the task and the module.
    selinux_runtime::task::set_current_sid_source(current_selinux_sid);
    selinux_runtime::task::set_fscreate_sid_source(current_fscreate_sid);
    fs::selinux::install();
    fs::selinux::mount::install();
    vfs::set_quota_sys_resource_hook(quota_has_sys_resource);
    vfs::set_reserved_caller_hook(current_reserved_caller);
    vfs::set_fs_halt_hook(fs_halt);
    vfs::set_quota_wait_hooks(
        sched::live::quota_wait::park,
        sched::live::quota_wait::schedule_after_park,
        sched::live::quota_wait::wake,
    );
    vfs::inode::set_inode_rwsem_wait_hooks(
        sched::live::inode_wait::park_rwsem,
        sched::live::inode_wait::schedule_after_park,
        sched::live::inode_wait::wake_rwsem,
    );
    // Sleeping half of a delegation break: every VFS mutation path (mknod,
    // unlink, rmdir, rename, link, setattr) waits here for a delegation holder
    // to answer before the change lands.
    crate::deleg_break::init();
    vfs::set_file_lock_wait_hooks(
        sched::live::inode_wait::park_interruptible,
        sched::live::inode_wait::schedule_after_park,
        sched::live::inode_wait::wake,
        || sched::live::current().is_none_or(sched::interruptible_work_pending),
    );
    // The mount engine NEVER resolves a mount-point STRING to a dentry
    // (`docs/16§3`): every caller hands `register*`/`move_mount`/… the
    // `Arc<Dentry>` its namei walk produced. The only provider needed is the
    // global root dentry — the start of the owning-mount identification walk
    // (`resolve_mount` → namei `walk_to_mount`) AND of the engine-internal
    // `descend` that materialises SYNTHESIZED mount positions.
    vfs::set_root_dentry_provider(crate::pathresolve::root_dentry);
    // pivot_root chroot-refs (Linux `chroot_fs_refs`): vfs commits the re-root
    // then calls this hook to re-point every task whose root/cwd was on the old
    // root mount to the new root. The walk lives in sched (it owns the task
    // table). Last-writer-wins with the vfs test's own hook; in production this
    // is the only installer.
    vfs::mount::set_chroot_refs_hook(sched::live::chroot_fs_refs);
    // Wall clock for `file_update_time` / `current_time`: vfs owns no time
    // source, so it reads the canonical CLOCK_REALTIME provider. Without it a
    // write-stamped mtime would
    // be frozen at the epoch.
    vfs::inode_times::set_realtime_provider(timekeeper::realtime_ns);
    vfs::inode_times::set_timezone_provider(crate::time_common::timezone_minuteswest);
}
