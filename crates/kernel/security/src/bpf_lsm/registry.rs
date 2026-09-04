//! Attached BPF LSM programs and the chained invocation the hooks run.
//!
//! Composition follows the modify-return shape: the most recently attached
//! program runs first, each program's exit value is taken as the hook's
//! answer, and the first non-zero answer ends the chain — the remaining
//! programs and the hook's own default do not run. An all-zero chain, and
//! an empty one, allow.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Spinlock, TaskList as TaskListClass};
use syscall::errno::Errno;
use vfs::InodeRef;

use super::hooks::{Hook, SLOT_BYTES, context_bytes};

/// One attached program: the verified bytecode plus the map set it may
/// reference. Held by the link, so the program outlives every fd the
/// loader closed.
pub struct Attached {
    pub hook: Hook,
    /// The loaded program object, pinned for the life of the attachment so
    /// the bytecode and its map set outlive every fd the loader closed.
    prog: InodeRef,
}

/// Link identity paired with the program it attached.
struct Entry {
    id: u64,
    program: Arc<Attached>,
}

/// Attached programs, most recently attached first.
static ATTACHED: Spinlock<Vec<Entry>, TaskListClass> = Spinlock::new(Vec::new());

// Linux's non-s390 trampoline can carry at most 38 links. Oxide supports
// x86_64 and aarch64, which both use this branch of BPF_MAX_TRAMP_LINKS.
const BPF_MAX_TRAMP_LINKS: usize = 38;

/// Attach one verified program to `hook` and return the link identity that
/// detaches it. The new program runs ahead of every program already
/// attached to the same hook.
/// # C: O(attached programs)
/// # Ctx: process; caller holds no `TaskListClass` lock
/// # Lk: takes `TaskListClass`
/// # Sleeps: no
pub fn register(hook: Hook, prog: InodeRef) -> Result<u64, Errno> {
    let mut attached = ATTACHED.lock();
    let mut on_hook = attached.iter().filter(|entry| entry.program.hook == hook);
    if on_hook.clone().count() >= BPF_MAX_TRAMP_LINKS { return Err(Errno::E2big); }
    if on_hook.any(|entry| Arc::ptr_eq(&entry.program.prog, &prog)) {
        return Err(Errno::Ebusy);
    }
    let id = attached.iter().map(|entry| entry.id).max().unwrap_or(0) + 1;
    let program = Arc::new(Attached { hook, prog });
    attached.insert(0, Entry { id, program });
    Ok(id)
}

/// Detach the program behind one link identity. # C: O(attached programs)
/// # Ctx: process; caller holds no `TaskListClass` lock
/// # Lk: takes `TaskListClass`
/// # Sleeps: no
pub fn unregister(id: u64) {
    ATTACHED.lock().retain(|entry| entry.id != id);
}

/// Programs attached to `hook`, newest first, snapshotted so the chain runs
/// without the registry lock held.
/// # C: O(attached programs)
fn chain(hook: Hook) -> Vec<Arc<Attached>> {
    ATTACHED.lock().iter()
        .filter(|entry| entry.program.hook == hook)
        .map(|entry| Arc::clone(&entry.program))
        .collect()
}

/// Run every program attached to `hook` over `args`, newest first, and
/// return the first non-zero answer. `args` holds one register-wide value
/// per declared hook argument; the slot past them is the pending return
/// value the chain has produced so far.
///
/// A program that fails to run at all is taken as its own refusal rather
/// than as an allow, so a hook can never be silently bypassed.
/// # C: O(attached programs × instructions run)
/// # Ctx: process
/// # Lk: takes `TaskListClass` for the snapshot only
/// # Sleeps: no
pub fn run(hook: Hook, args: &[u64]) -> i64 {
    run_with_kernel(hook, args, None)
}

/// Run a task hook with its concrete BTF task view as the only readable
/// kernel-object region. # C: O(attached programs × instructions run)
pub(super) fn run_task(hook: Hook, args: &[u64], base: u64, task: &[u8]) -> i64 {
    run_with_kernel(hook, args, Some((base, task)))
}

fn run_with_kernel(hook: Hook, args: &[u64], kernel: Option<(u64, &[u8])>) -> i64 {
    let programs = chain(hook);
    if programs.is_empty() { return 0; }
    let mut context = alloc::vec![0u8; context_bytes(hook)];
    for (at, arg) in args.iter().enumerate() {
        let start = at * SLOT_BYTES;
        let Some(slot) = context.get_mut(start..start + SLOT_BYTES) else { break; };
        slot.copy_from_slice(&arg.to_ne_bytes());
    }
    let mut state = crate::bpf_interp::HelperState::default();
    for program in programs {
        let answer = program.prog.private::<crate::bpf::BpfProgInode>()
            .and_then(|loaded| match kernel {
                Some((base, bytes)) => crate::bpf_interp::run_program_with_kernel_state(
                    &loaded, &context, base, bytes, &mut state),
                None => crate::bpf_interp::run_program_with_state(
                    &loaded, &context, &[], &[], &mut state),
            })
            .unwrap_or(REFUSE);
        if answer != 0 { return answer; }
    }
    0
}

/// Answer taken for a program the runner could not execute.
const REFUSE: i64 = -(syscall::errno::Errno::Eperm.as_i32() as i64);

/// Retained-count of programs attached to one hook. # C: O(attached programs)
#[cfg(test)]
pub(super) fn attached_count(hook: Hook) -> usize { chain(hook).len() }

#[cfg(test)]
#[path = "registry_tests.rs"]
mod tests;
