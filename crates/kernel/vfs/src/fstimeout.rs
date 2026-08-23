//! Filesystem fault-injection timeouts.
//!
//! A filesystem owns the decision to inject a delay, but it does not own the
//! scheduler operation that realizes one. The kernel layer installs that
//! operation here, leaving hosted filesystems able to exercise the same call
//! path without depending on the scheduler.

use sync::Spinlock;

struct FsTimeoutHookLock;
impl sync::LockClass for FsTimeoutHookLock {
    fn rank() -> u16 { 30 }
    fn name() -> &'static str { "FsTimeoutHookLock" }
}

/// The Linux f2fs fault-injection timeout modes.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum FsTimeout {
    Running,
    IoSleep,
    NonIoSleep,
    Runnable,
}

/// The scheduler-owned implementation of one timeout mode.
pub type FsTimeoutHook = fn(FsTimeout);

static HOOK: Spinlock<Option<FsTimeoutHook>, FsTimeoutHookLock> = Spinlock::new(None);

/// Install the timeout realization used by filesystem fault injection. # C: O(1)
pub fn set_fs_timeout_hook(hook: FsTimeoutHook) { *HOOK.lock() = Some(hook); }

/// Remove the timeout realization. # C: O(1)
pub fn clear_fs_timeout_hook() { *HOOK.lock() = None; }

/// Apply one requested timeout, returning whether a realization was installed.
/// # C: O(1), plus the selected scheduler operation
pub fn fs_timeout(timeout: FsTimeout) -> bool {
    let hook = *HOOK.lock();
    match hook {
        Some(hook) => { hook(timeout); true }
        None => false,
    }
}

#[cfg(test)]
#[path = "tests/fstimeout.rs"]
mod tests;
