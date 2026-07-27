// `SYSCALL_DEFINE2(pivot_root)`'s outer sequence (`fs/namespace.c`, Linux
// v7.2.0-rc4): resolve `new_root`, resolve `put_old`, THEN `may_mount()`, then
// the mount-tree work. The mount-tree admission ladder itself belongs to the
// mount subsystem and lives in `vfs::mount::pivot_check` (docs/53).
//
// The order here is the part callers actually trip over: both pathnames are
// resolved by the syscall wrapper before `path_pivot_root()` runs, so an
// unprivileged caller naming a nonexistent or non-directory path gets ENOENT /
// ENOTDIR — not EPERM. Deliberately NOT `target_os`-gated so that stays tested.
//
// Errors are already-negated `i64` errnos, the currency the mount-family
// helpers (`mount_common`, `namei_common::errno_from_vfs`, `userbuf`) speak;
// values are always built from `Errno`, never written as literals.

use syscall::errno::Errno;

/// Which pathname a lookup is resolving. Linux resolves `new_root` first, so a
/// bad `new_root` reports before `put_old` is looked at at all.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Arg { NewRoot, PutOld }

/// Effects, injected so the sequence is testable.
pub trait PivotOps {
    /// `user_path_at(AT_FDCWD, name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY)`.
    /// ENOTDIR for a non-directory is raised by the walk itself.
    fn lookup_directory(&mut self, arg: Arg) -> Result<(), i64>;
    /// `may_mount()` — `ns_capable(mnt_ns->user_ns, CAP_SYS_ADMIN)`.
    fn may_mount(&mut self) -> bool;
    /// `path_pivot_root()`: the admission ladder plus the re-parent and
    /// `chroot_fs_refs`.
    fn commit(&mut self) -> Result<(), i64>;
}

/// # C: O(N_mounts × depth)
pub fn pivot_root(ops: &mut impl PivotOps) -> Result<(), i64> {
    ops.lookup_directory(Arg::NewRoot)?;
    ops.lookup_directory(Arg::PutOld)?;
    if !ops.may_mount() { return Err(-(Errno::Eperm.as_i32() as i64)); }
    ops.commit()
}

#[cfg(test)]
mod tests;
