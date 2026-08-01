// Keyring task-lifecycle hooks the scheduler drives but does not own.
//
// Linux hangs keyring state on `cred`, so `put_cred` and `commit_creds` carry
// the exit and fsid transitions for free. Here that state lives in `fs`, which
// already depends on `sched` — a direct `sched -> fs` edge would cycle — so the
// two transitions whose call site is inside `sched` reach the owner through the
// same boot-installed function-pointer arrangement `RobustExitFn` and
// `DisassociateCttyFn` use.
//
// The fork and exec transitions are NOT here: their call sites (`clone`,
// `execve`) are in `syscalls`, which depends on `fs` directly and calls the
// owner without indirection.

use core::sync::atomic::{AtomicPtr, Ordering};

/// Final `put_cred` for a dying task (`fs::keyring::exit_keys`), installed at
/// boot. `(tid, tgid, last_thread)`.
pub type KeyringExitFn = fn(u32, u32, bool);

static KEYRING_EXIT_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// # C: O(1)
pub fn set_keyring_exit_hook(f: KeyringExitFn) {
    KEYRING_EXIT_HOOK.store(f as *mut (), Ordering::Release);
}

/// Release `task`'s keyring state. No-op if the hook is unset (early boot).
///
/// Both exit paths drive it — `exit(2)`/`exit_group(2)` and the fatal-signal
/// termination path — because a task killed by SIGSEGV strands exactly the same
/// session keyring, thread keyring and assumed authority as one that returned
/// from `main`. Without it a RECYCLED tid inherits a dead task's keys.
///
/// `last_thread` is read from the ONE source of truth the rest of the exit path
/// uses for group-dead (`ThreadGroup::is_single_member`), so the process
/// keyring is released on exactly the transition that releases the controlling
/// terminal and the SysV undo list. MUST be called before `mark_done`, while
/// the dying task is still counted live.
/// # C: O(log N) via the installed hook
pub fn run_keyring_exit(task: &crate::Task) {
    let p = KEYRING_EXIT_HOOK.load(Ordering::Acquire);
    if p.is_null() { return; }
    // SAFETY: hook installed via set_keyring_exit_hook with the documented KeyringExitFn signature; Acquire load pairs with the Release store in the setter; ptr is a valid 'static fn address.
    let f: KeyringExitFn = unsafe { core::mem::transmute(p) };
    f(task.tid, keyring_tgid(task), task.thread_group.is_single_member());
}

/// `key_fsuid_changed` / `key_fsgid_changed` (`fs::keyring::fsids_changed`),
/// installed at boot. `(tid, fsuid, fsgid)`.
pub type FsidsChangedFn = fn(u32, u32, u32);

static FSIDS_CHANGED_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// # C: O(1)
pub fn set_fsids_changed_hook(f: FsidsChangedFn) {
    FSIDS_CHANGED_HOOK.store(f as *mut (), Ordering::Release);
}

/// Re-own the task's thread keyring after its filesystem ids moved. No-op if
/// the hook is unset. Driven from the credential commit point so every id-
/// changing syscall reaches it through one call, never per-syscall.
/// # C: O(log N) via the installed hook
pub fn run_fsids_changed(tid: u32, fsuid: u32, fsgid: u32) {
    let p = FSIDS_CHANGED_HOOK.load(Ordering::Acquire);
    if p.is_null() { return; }
    // SAFETY: hook installed via set_fsids_changed_hook with the documented FsidsChangedFn signature; Acquire load pairs with the Release store in the setter; ptr is a valid 'static fn address.
    let f: FsidsChangedFn = unsafe { core::mem::transmute(p) };
    f(tid, fsuid, fsgid);
}

/// Return both hooks to their boot-time (unset) state so a hosted test can
/// assert the no-hook path is a no-op rather than a null-pointer call.
/// # C: O(1)
#[cfg(test)]
pub(crate) fn clear_hooks_for_tests() {
    KEYRING_EXIT_HOOK.store(core::ptr::null_mut(), Ordering::Release);
    FSIDS_CHANGED_HOOK.store(core::ptr::null_mut(), Ordering::Release);
}

/// The thread-group id the keyring store keys its process keyring on: the
/// PID-namespace-visible one, which is what the `keyctl(2)` entry path records
/// when it mints a `@p`. Reading the global `tgid` here instead would release a
/// keyring nothing was ever filed under.
/// # C: O(1)
fn keyring_tgid(task: &crate::Task) -> u32 { task.vtgid.load(Ordering::Acquire) }
