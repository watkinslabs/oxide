// Protection-key rights register plumbing. x86 PKRU is an XSAVE component,
// so its architectural image owns context switch, fork, signal return, and
// exec. Aarch64 POR_EL0 is outside its FPSIMD image, so this module owns that
// target's per-task snapshot and register handoff.

#[cfg(target_arch = "aarch64")]
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
pub fn read_live() -> u64 { if fake::active() { fake::get() } else { hw::read_live() } }

/// Load `v` into the live register. # C: O(1)
pub fn write_live(v: u64) { if fake::active() { fake::set(v); } else { hw::write_live(v); } }

/// A stand-in for the hardware register, so the read-before-write ordering
/// [`switch_to`] depends on can be tested on a host that has no such register.
/// Inert unless a test arms it; the production paths above compile to the same
/// branch either way and it is never armed outside `cfg(test)`.
mod fake {
    #[cfg(test)]
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    #[cfg(test)]
    pub(super) static ARMED: AtomicBool = AtomicBool::new(false);
    #[cfg(test)]
    pub(super) static VALUE: AtomicU64 = AtomicU64::new(0);

    #[cfg(test)]
    pub(super) fn active() -> bool { ARMED.load(Ordering::Relaxed) }
    #[cfg(test)]
    pub(super) fn get() -> u64 { VALUE.load(Ordering::Relaxed) }
    #[cfg(test)]
    pub(super) fn set(v: u64) { VALUE.store(v, Ordering::Relaxed); }

    #[cfg(not(test))]
    pub(super) fn active() -> bool { false }
    #[cfg(not(test))]
    pub(super) fn get() -> u64 { 0 }
    #[cfg(not(test))]
    pub(super) fn set(v: u64) { let _ = v; }
}

/// Aarch64 `__switch_to` rights-register handoff. x86 returns without a
/// second handoff because `fpu_save`/`fpu_restore` own PKRU there.
/// # C: O(1)
pub fn switch_to(prev: &Task, next: &Task) {
    #[cfg(target_arch = "aarch64")]
    {
    if !supported() && !fake::active() { return; }
    prev.pkey_rights.store(read_live(), Ordering::Relaxed);
    write_live(next.pkey_rights.load(Ordering::Relaxed));
    }
    #[cfg(not(target_arch = "aarch64"))]
    { let _ = (prev, next); }
}

/// `execve` reset (Linux `fpu_flush_thread` → `pkru_write_default`): a fresh
/// program must not inherit rights the old one opened, because its keys mean
/// something else entirely. # C: O(1)
pub fn reset_on_exec(task: &Task) {
    #[cfg(target_arch = "aarch64")]
    {
    let init = init_value();
    task.pkey_rights.store(init, Ordering::Relaxed);
    write_live(init);
    }
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: exec resets its running task before user return; no other
        // CPU may access this task's single-mutator xstate buffer.
        unsafe {
            let fpu = &mut *task.fpu_state.get();
            fpu.reset_initial();
            hal_x86_64::fpu_restore(fpu.as_ptr() as *const hal_x86_64::FpuStateX86_64);
        }
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    { let _ = task; }
}

#[cfg(all(test, target_arch = "aarch64"))]
mod tests;
