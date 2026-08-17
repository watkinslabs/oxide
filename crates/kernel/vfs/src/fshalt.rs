//! Stopping the machine because a mount line asked for it.
//!
//! `errors=panic` is a mount option, so the DECISION belongs to the filesystem
//! that parsed it and knows what it found. Carrying it out does not: stopping a
//! machine is the business of the layer that owns the machine, and a filesystem
//! that reached for it directly would be taking a decision about the whole
//! system from inside one volume's error path.
//!
//! So the layer that owns the machine installs a hook here, in the shape the
//! reserved-pool probe next door already uses, and a filesystem hands it the
//! two facts a diagnosis needs: which filesystem, and what it found. The
//! filesystem learns whether anything took the request, which is what lets a
//! hosted test observe the demand without a machine to stop.
//!
//! With no hook installed nothing halts and the caller is told so. That is the
//! honest answer for a hosted build and for early boot — there is no machine to
//! stop yet — and it must NOT be read as the option having been honoured: a
//! filesystem whose halt was refused carries on down its remaining arms, which
//! is the same thing the reference does when a halt is suppressed on the way
//! down.

use sync::Spinlock;

struct FsHaltHookLock;
impl sync::LockClass for FsHaltHookLock {
    fn rank() -> u16 { 30 }
    fn name() -> &'static str { "FsHaltHookLock" }
}

/// Stops the machine, naming the filesystem and what it found.
///
/// Both strings are static: they name a filesystem and one of a closed set of
/// reasons, and the diagnostic path a halt goes down cannot allocate.
pub type FsHaltHook = fn(&'static str, &'static str);

static HOOK: Spinlock<Option<FsHaltHook>, FsHaltHookLock> = Spinlock::new(None);

/// Install the halt path. # C: O(1)
pub fn set_fs_halt_hook(hook: FsHaltHook) { *HOOK.lock() = Some(hook); }

/// Remove it. # C: O(1)
pub fn clear_fs_halt_hook() { *HOOK.lock() = None; }

/// Whether a halt path is installed at all, which a filesystem may want to know
/// before it decides how loudly to complain. # C: O(1)
pub fn fs_halt_installed() -> bool { HOOK.lock().is_some() }

/// Stop the machine, reporting whether anything took the request.
///
/// `false` means nothing halted — no hook is installed — and the caller is
/// still running. A caller must go on to its remaining arms in that case rather
/// than assume the machine is gone.
/// # C: O(1), and does not return when a hook is installed
pub fn fs_halt(fs: &'static str, reason: &'static str) -> bool {
    let hook = *HOOK.lock();
    match hook {
        Some(hook) => { hook(fs, reason); true }
        None => false,
    }
}

#[cfg(test)]
#[path = "tests/fshalt.rs"]
mod tests;
