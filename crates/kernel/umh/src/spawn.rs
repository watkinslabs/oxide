// The real spawn backend. Module manifest:
//   arch     per-arch user page-table root allocation + activation
//   image    resolve the helper program through the VFS and read it
//   child    build the helper process: address space, image, stack, task
//   queue    worker-thread hand-off and the caller's completion
//   reap     wait for a helper to terminate and read its wait status
//
// The exec must not run on the caller's page tables — loading an image writes
// through the NEW address space's user addresses, so the loader has to run on a
// thread that owns no user address space of its own. That is what the worker
// hand-off in `queue` buys, and it is why a helper is a child of a kernel
// worker rather than of whoever asked for it.

#![cfg(target_os = "oxide-kernel")]

mod arch;
mod image;
mod child;
mod queue;
mod reap;
#[cfg(feature = "debug-umh")]
mod selftest;

/// Install the helper machinery and start its thread. Boot calls this once the
/// runqueues exist; the gate stays closed until `usermodehelper_enable` is
/// called separately, so nothing can exec before userspace is up.
/// # C: O(1)
pub fn init() -> Result<(), sched::live::SpawnError> {
    queue::spawn_helper_thread()?;
    crate::backend::install(queue::submit);
    crate::gate::set_yield_hook(queue::yield_one_ms);
    Ok(())
}
