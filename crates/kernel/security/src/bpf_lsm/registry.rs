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

/// Attach one verified program to `hook` and return the link identity that
/// detaches it. The new program runs ahead of every program already
/// attached to the same hook.
/// # C: O(attached programs)
/// # Ctx: process; caller holds no `TaskListClass` lock
/// # Lk: takes `TaskListClass`
/// # Sleeps: no
pub fn register(hook: Hook, prog: InodeRef) -> u64 {
    let program = Arc::new(Attached { hook, prog });
    let mut attached = ATTACHED.lock();
    let id = attached.iter().map(|entry| entry.id).max().unwrap_or(0) + 1;
    attached.insert(0, Entry { id, program });
    id
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
            .and_then(|loaded| crate::bpf_interp::run_program_with_state(
                &loaded, &context, &[], &[], &mut state,
            ))
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
