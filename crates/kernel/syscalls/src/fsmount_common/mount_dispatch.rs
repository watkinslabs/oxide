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

fn graft_mount(sb: Arc<vfs::SuperBlock>, target_d: &Arc<Dentry>, parent_hint: Option<u64>) -> i64 {
    match vfs::mount::attach_sb_with_flags_at(Some(target_d.clone()), sb, 0, parent_hint) {
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
/// # C: O(1) dispatch + O(construct) on hit
pub(crate) fn dispatch_mount(source: Option<&str>, fstype: &str, target: &str, target_d: &Arc<Dentry>,
    parent_hint: Option<u64>, data: &str) -> i64 {
    if let Some(ty) = vfs::fs::get_fs(fstype) {
        let sb = match ty.construct(source, target, data) {
            Ok(s) => s,
            Err(e) => return crate::namei_common::errno_from_vfs(e),
        };
        return graft_mount(sb, target_d, parent_hint);
    }
    -(Errno::Enodev.as_i32() as i64)
}
