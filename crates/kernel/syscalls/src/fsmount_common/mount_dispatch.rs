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

pub(crate) use crate::mount_capable::{mount_capable, MountCaps};

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
        // Linux `do_new_mount` order, exactly: build the context, parse
        // `source`, parse the monolithic data blob, THEN
        // `if (!mount_capable(fc)) err = -EPERM`, then `vfs_get_tree`.
        //
        // Building the context is the point: before this, `mount(2)` handed the
        // raw comma-separated blob straight to the constructor, so the
        // per-parameter admission every `fsconfig(2)` goes through was applied
        // to PROBES only. A filesystem could report an option unsupported to a
        // probe and still swallow it silently on the mount that mattered.
        //
        // Parsing precedes the privilege check, so an unprivileged caller
        // supplying a bad option gets EINVAL rather than EPERM — the option is
        // rejected on its own merits and the errno does not leak whether the
        // caller would have been allowed to mount.
        let sb_flags = ms_flags & vfs::fs::SB_FLAGS_USER_MASK;
        let mut fc = vfs::fs::FsContext::for_mount(ty.clone() as Arc<dyn vfs::FileSystemType>, sb_flags);
        fc.set_mount_target(target);
        if let Some(name) = source {
            if let Err(e) = vfs::fs::vfs_parse_fs_string(&mut fc, "source", name) {
                return crate::namei_common::errno_from_vfs(e);
            }
        }
        if let Err(e) = vfs::fs::parse_monolithic_mount_data(&mut fc, data) {
            return crate::namei_common::errno_from_vfs(e);
        }
        // The superblock does not exist yet, so a refusal here leaks nothing.
        if !mount_capable(ty.fs_flags(), caps) { return -(Errno::Eperm.as_i32() as i64); }
        if let Err(e) = vfs::fs::vfs_get_tree(&mut fc) {
            return crate::namei_common::errno_from_vfs(e);
        }
        let sb = match fc.sb() {
            Some(s) => s.clone(),
            None => return -(Errno::Einval.as_i32() as i64),
        };
        // Release the context BEFORE grafting so the mount holds the same
        // superblock reference count the pre-context path handed it.
        vfs::fs::put_fs_context(fc);
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
