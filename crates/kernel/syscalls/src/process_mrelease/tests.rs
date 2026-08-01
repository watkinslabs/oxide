// `process_mrelease` admission: who may have their memory reaped, and when the
// refusal is an error rather than a no-op.

use super::{disposition, task_will_free_mem, task_will_free_mem_one, Disposition, ExitState};
use syscall::errno::Errno;

const LIVE: ExitState = ExitState { coredumping: false, group_exit: false, thread_group_empty: true, exiting: false };
const GROUP_EXITING: ExitState = ExitState { coredumping: false, group_exit: true, thread_group_empty: false, exiting: false };
const LONE_EXITING: ExitState = ExitState { coredumping: false, group_exit: false, thread_group_empty: true, exiting: true };

// A running task is not about to free anything — this is the case that stops a
// caller from reaping an arbitrary process it happens to hold a pidfd for.
#[test]
fn a_live_task_is_never_about_to_free_its_mm() {
    assert!(!task_will_free_mem_one(LIVE));
}

// A group exit frees the mm regardless of how many threads are still in it.
#[test]
fn a_group_exit_frees_the_mm() {
    assert!(task_will_free_mem_one(GROUP_EXITING));
}

// A thread exiting on its own only frees the mm when it is the last one; a
// sibling thread would keep the address space alive.
#[test]
fn a_lone_exiting_thread_frees_the_mm_but_one_of_many_does_not() {
    assert!(task_will_free_mem_one(LONE_EXITING));
    assert!(!task_will_free_mem_one(ExitState { thread_group_empty: false, ..LONE_EXITING }));
}

// A core dump can sleep for a long time before releasing anything, so a
// dumping task is refused even though it is dying.
#[test]
fn a_coredumping_task_is_refused_despite_dying() {
    assert!(!task_will_free_mem_one(ExitState { coredumping: true, ..GROUP_EXITING }));
    assert!(!task_will_free_mem_one(ExitState { coredumping: true, ..LONE_EXITING }));
}

// With a single user, the named task's own state settles it.
#[test]
fn a_single_user_mm_needs_no_sharer_scan() {
    assert!(task_will_free_mem(GROUP_EXITING, false, 1, &[]));
    assert!(!task_will_free_mem(LIVE, false, 1, &[]));
}

// A shared mm (CLONE_VM outside the thread group) is reapable only when EVERY
// sharer is dying. One live sharer keeps the pages, and reaping anyway would
// pull memory out from under a running process.
#[test]
fn a_shared_mm_needs_every_sharer_dying() {
    assert!(task_will_free_mem(GROUP_EXITING, false, 2, &[GROUP_EXITING]));
    assert!(task_will_free_mem(GROUP_EXITING, false, 3, &[GROUP_EXITING, LONE_EXITING]));
    assert!(!task_will_free_mem(GROUP_EXITING, false, 2, &[LIVE]));
    assert!(!task_will_free_mem(GROUP_EXITING, false, 3, &[GROUP_EXITING, LIVE]));
}

// An already-drained mm has nothing left to give, so it is not "about to free"
// anything even while its owner is dying.
#[test]
fn an_already_drained_mm_is_not_reapable_again() {
    assert!(!task_will_free_mem(GROUP_EXITING, true, 1, &[]));
}

// A dying target is reaped.
#[test]
fn a_dying_target_is_reaped() {
    assert_eq!(disposition(true, false), Disposition::Reap);
}

// Repeating the call on an mm this syscall already drained SUCCEEDS: the
// caller's intent is satisfied, so reporting an error would be misleading.
#[test]
fn a_repeat_call_on_a_drained_mm_succeeds_instead_of_erroring() {
    assert_eq!(disposition(false, true), Disposition::AlreadyDrained);
}

// A live target that was never drained is the one real error case.
#[test]
fn a_live_undrained_target_is_einval() {
    assert_eq!(disposition(false, false), Disposition::Refuse(Errno::Einval));
}
