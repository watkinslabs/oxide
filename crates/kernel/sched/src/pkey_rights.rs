// Per-task protection-key rights register (Linux `thread.pkru`,
// `x86_pkru_load`/`x86_pkru_save` around `__switch_to`).
//
// Arch-neutral face of the register x86 calls PKRU. The aarch64 equivalent
// (`POR_EL0`) joins this module when its enablement lands; every caller —
// task creation, fork, exec, context switch — talks to these four functions so
// neither arch grows its own copy of the policy.
//
// The rights register is USER-writable (`WRPKRU` is unprivileged), so the
// per-task field is a snapshot, not the truth: [`switch_to`] refreshes the
// outgoing task's copy by reading the live register before loading the
// incoming one's. A switch path that only wrote would silently discard every
// change userspace made since the task was scheduled in.

use core::sync::atomic::Ordering;

use crate::Task;

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
#[path = "pkey_rights/hw_x86.rs"]
mod hw;
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
#[path = "pkey_rights/hw_arm.rs"]
mod hw;
// Hosted builds have no rights register at all.
#[cfg(not(any(all(target_arch = "x86_64", target_os = "oxide-kernel"),
              all(target_arch = "aarch64", target_os = "oxide-kernel"))))]
#[path = "pkey_rights/hw_none.rs"]
mod hw;

/// Does this system enforce protection keys? False makes every function here
/// inert, which is the honest answer on a CPU whose rights register does not
/// exist. # C: O(1)
pub fn supported() -> bool { hw::supported() }

/// The rights register value a task is born with and `execve` resets to.
/// Zero when unsupported: no key can deny anything. # C: O(1)
pub fn init_value() -> u64 { hw::init_value() }

/// Snapshot the live register. # C: O(1)
pub fn read_live() -> u64 { hw::read_live() }

/// Load `v` into the live register. # C: O(1)
pub fn write_live(v: u64) { hw::write_live(v); }

/// `__switch_to`'s rights-register handoff: capture what `prev` ended up with
/// — including any unprivileged user write the kernel never saw — then install
/// `next`'s.
///
/// Ordering matters: reading before writing is what makes a task that opened a
/// key still hold it when it is scheduled again.
/// # C: O(1)
pub fn switch_to(prev: &Task, next: &Task) {
    if !supported() { return; }
    prev.pkey_rights.store(read_live(), Ordering::Relaxed);
    write_live(next.pkey_rights.load(Ordering::Relaxed));
}

/// `execve` reset (Linux `fpu_flush_thread` → `pkru_write_default`): a fresh
/// program must not inherit rights the old one opened, because its keys mean
/// something else entirely. # C: O(1)
pub fn reset_on_exec(task: &Task) {
    let init = init_value();
    task.pkey_rights.store(init, Ordering::Relaxed);
    write_live(init);
}

#[cfg(test)]
mod tests;
