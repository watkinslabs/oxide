// Refcounted `Task` allocation — the Linux `dup_task_struct` shape.
//
// A `Task` is ~3.5 KiB. Building one as a local and then handing it to
// `Arc::new` costs TWO copies of that on the creator's 16 KiB kernel stack
// (constructor sret slot + the move-into-`Arc` temporary), and fork/clone runs
// that on the PARENT's stack while the parent still holds its own syscall
// frame. Linux never does this: `task_struct` comes out of a slab first and
// `copy_process` fills it in through the pointer.
//
// These helpers allocate the refcounted box first and construct into it, so
// the creator's frame carries no `Task`-sized slot at all. Callers finish
// initialization through [`unique_mut`] while the allocation is still
// uniquely owned.

use alloc::sync::Arc;
use core::mem::MaybeUninit;

use vmm::AddressSpace;

use super::{SchedClass, Task};

/// Allocate a kernel-thread `Task` (no `mm`) directly into its `Arc`.
/// # C: O(1)
pub fn new_kthread_arc(tid: u32, name: &'static str, class: SchedClass) -> Arc<Task> {
    build(|| Task::new(tid, name, class))
}

/// Allocate a user `Task` bound to `mm` directly into its `Arc`.
/// # C: O(1)
pub fn new_user_arc(tid: u32, name: &'static str, class: SchedClass, mm: Arc<AddressSpace>)
    -> Arc<Task>
{
    build(|| Task::new_user(tid, name, class, mm))
}

/// Exclusive access to a `Task` that has not been published yet.
///
/// Panics if the allocation is shared — a caller that has already handed the
/// `Arc` to the registry, a runqueue or a wait list must not keep mutating the
/// task through `&mut`.
/// # C: O(1)
pub fn unique_mut(task: &mut Arc<Task>) -> &mut Task {
    let t = Arc::get_mut(task);
    hal::kassert!(t.is_some(), "task mutated after publication");
    // SAFETY: `Arc::get_mut` returned Some under the kassert above, so this
    // allocation is uniquely owned and `&mut Task` is the only live reference.
    unsafe { t.unwrap_unchecked() }
}

/// Allocate the refcounted box first, then construct into it.
#[inline]
fn build<F: FnOnce() -> Task>(ctor: F) -> Arc<Task> {
    let mut slot: Arc<MaybeUninit<Task>> = Arc::new_uninit();
    let dst = Arc::get_mut(&mut slot);
    hal::kassert!(dst.is_some(), "fresh Arc allocation is not unique");
    // SAFETY: `dst` is the freshly allocated, uniquely owned, uninitialized
    // Task slot; `write` initializes it exactly once before `assume_init`.
    unsafe { dst.unwrap_unchecked().write(ctor()); }
    // SAFETY: the sole `MaybeUninit` slot was initialized by the write above,
    // so every field of the Task is valid.
    unsafe { slot.assume_init() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class() -> SchedClass { SchedClass::Normal { weight: 1024 } }

    #[test]
    fn kthread_arc_is_fully_constructed_and_uniquely_owned() {
        let mut t = new_kthread_arc(7, "dup-test", class());
        assert_eq!(t.tid, 7);
        assert_eq!(Arc::strong_count(&t), 1);
        assert_eq!(Arc::weak_count(&t), 0);
        // The construction phase must still be able to take `&mut`.
        unique_mut(&mut t).start_boottime_ns = 42;
        assert_eq!(t.start_boottime_ns, 42);
    }

    #[test]
    fn published_task_survives_clone_of_the_handle() {
        let t = new_kthread_arc(8, "dup-test", class());
        let publish = Arc::clone(&t);
        assert_eq!(Arc::strong_count(&t), 2);
        assert_eq!(publish.tid, 8);
    }
}
