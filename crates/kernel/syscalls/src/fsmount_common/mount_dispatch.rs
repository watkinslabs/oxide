// Pure `mount(2)`-by-fstype dispatch (docs/53 hollow-shell shim pattern):
// given the CALLER-resolved `vfs::fs::get_fs(fstype)` outcome, either
// construct+graft the superblock or return the honest Linux errno. Deliberately
// UNGATED (no `target_os` cfg) — its only deps (`vfs`, `syscall::errno`) are
// hosted-compilable, so `cargo test` can drive this exact decision path
// without booting (docs/CLAUDE "verify left" rule). `mount_ops.rs` (the real
// kernel-only glue, `ensure_filesystems_registered()` + user-string reads)
// stays `target_os`-gated and delegates here.
use alloc::sync::Arc;
use syscall::errno::Errno;
use vfs::Dentry;
use vfs::fs::FsFlags;

/// The capability facts `mount_capable` chooses between, sampled by the caller
/// (`mount_perm::sample_mount_caps`) so this module stays free of `sched`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct MountCaps {
    /// `capable(CAP_SYS_ADMIN)` — held in the INITIAL user namespace.
    pub init_user_ns: bool,
    /// `may_mount()` — `ns_capable(mnt_ns->user_ns, CAP_SYS_ADMIN)`.
    pub mnt_user_ns: bool,
}

/// Linux `fs/super.c` `mount_capable`: a filesystem WITHOUT `FS_USERNS_MOUNT`
/// may only be mounted by a caller privileged in the INITIAL user namespace;
/// one with the flag settles for privilege in the mount namespace's owning user
/// namespace. `FS_USERNS_MOUNT` was defined in `vfs::fs::FsFlags` and set on
/// procfs/sysfs, but NOTHING read it — so an unprivileged user-namespace holder
/// (who by construction has CAP_SYS_ADMIN inside its own userns, and so passes
/// `may_mount`) could mount ext4, tmpfs, devtmpfs, devpts, fuse … every type
/// Linux reserves for the initial user namespace. # C: O(1)
pub(crate) fn mount_capable(fs_flags: FsFlags, caps: MountCaps) -> bool {
    if !fs_flags.contains(FsFlags::FS_USERNS_MOUNT) { caps.init_user_ns } else { caps.mnt_user_ns }
}

fn graft_mount(sb: Arc<vfs::SuperBlock>, target_d: &Arc<Dentry>, parent_hint: Option<u64>,
    mnt_flags: u64, lock_flags: u32) -> i64 {
    match vfs::mount::attach_sb_locked_at(Some(target_d.clone()), sb, mnt_flags, lock_flags,
        parent_hint) {
        Ok(()) => { let _ = vfs::mount::propagate_mount(target_d); 0 }
        Err(vfs::VfsError::Eexist) => -(Errno::Ebusy.as_i32() as i64),
        Err(e) => crate::namei_common::errno_from_vfs(e),
    }
}

/// Resolve `fstype` against the registered `vfs::fs` types and either graft a
/// freshly constructed superblock at `target_d`, or report the honest reason
/// nothing was mounted.
///
/// `fstype == "cgroup"` (legacy v1) is NEVER registered
/// (`fsmount_common/registry.rs` registers only `"cgroup2"`, the unified
/// hierarchy) — the `cgroup` crate is a single global tree keyed off one
/// `ROOT` constant (`cgroup::tree::ROOT`, `crates/kernel/cgroup/src/state.rs`
/// `TREE`), architecturally unable to host N independent, separately
/// mountable v1 hierarchies (per-hierarchy controller exclusivity, `tasks`/
/// `release_agent`/`notify_on_release` files, per-hierarchy task membership)
/// without either a parallel hierarchy registry (forbidden, `07§5` no-split-
/// source-of-truth) or a real spec section (`docs/26` is titled "cgroup v2"
/// and has no v1 section at all — spec-before-code, `02`, blocks writing that
/// surface here). So this returns Linux's ENODEV ("filesystem type not
/// configured into the kernel") — the SAME default every other unregistered
/// fstype already gets — rather than the previous `=> 0` silent lie (B1413).
/// `devpts` needs no special case: it IS registered (`registry.rs`), so it
/// resolves through the `Some(ty)` arm below like any real filesystem.
///
/// `ms_flags` is the RAW `mount(2)` flag word. Linux `path_mount` derives the
/// per-mount option mask from it and `do_new_mount` → `do_add_mount` stamps that
/// mask onto the new mount (`newmnt->mnt.mnt_flags = mnt_flags`). This shim did
/// the same graft with a HARD-CODED `0`, so `mount -o ro,nosuid,nodev,noexec`
/// produced a mount whose `mnt_flags` were empty: every consumer of those bits
/// (`may_open`'s EROFS/EACCES ladder, `mnt_may_suid` at execve, the mmap PROT_EXEC
/// gate) then read "unrestricted" and the options were advertised by
/// `/proc/mounts` while enforcing nothing.
/// # C: O(1) dispatch + O(construct) on hit
pub(crate) fn dispatch_mount(source: Option<&str>, fstype: &str, target: &str, target_d: &Arc<Dentry>,
    parent_hint: Option<u64>, data: &str, ms_flags: u64, caps: MountCaps) -> i64 {
    if let Some(ty) = vfs::fs::get_fs(fstype) {
        // Linux `do_new_mount` order: resolve the type, build the context, parse
        // the options, THEN `if (!mount_capable(fc)) err = -EPERM`, then graft.
        // The superblock is constructed first, so a refused mount must not leave
        // it grafted — this returns before `graft_mount`.
        if !mount_capable(ty.fs_flags(), caps) { return -(Errno::Eperm.as_i32() as i64); }
        let sb_flags = ms_flags & vfs::fs::SB_FLAGS_USER_MASK;
        let sb = match ty.construct_with_flags(source, target, data, sb_flags) {
            Ok(s) => s,
            Err(e) => return crate::namei_common::errno_from_vfs(e),
        };
        let mnt_flags = vfs::mount::ms_to_mnt(ms_flags);
        // Linux `do_new_mount_fc`: after the superblock exists and BEFORE
        // `do_add_mount`, `if (mount_too_revealing(sb, &mnt_flags)) return
        // -EPERM;`. This is what stops an unprivileged user-namespace holder
        // from mounting a pristine `proc`/`sysfs` over the masked one it was
        // given. It also feeds back the locked read-only/atime attributes the
        // already-visible instance imposes, which ride the same `mnt_flags`
        // word in Linux and a separate internal word here. The refusal returns
        // BEFORE `graft_mount`, so nothing is left attached.
        let lock_flags = match vfs::mount::mount_too_revealing(&sb, mnt_flags) {
            Ok(l) => l,
            Err(_) => {
                // Linux's `fc_mount` result is `__free(mntput)`, so refusing
                // here releases the just-built superblock. Drop the active ref
                // `fill_super` took, or the instance leaks (and, for a
                // device-backed type, keeps `fs_supers` occupied).
                sb.deactivate_super();
                return -(Errno::Eperm.as_i32() as i64);
            }
        };
        return graft_mount(sb, target_d, parent_hint, mnt_flags, lock_flags);
    }
    -(Errno::Enodev.as_i32() as i64)
}
