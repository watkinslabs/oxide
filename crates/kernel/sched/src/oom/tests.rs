//! Hosted end-to-end out-of-memory selection over real tasks.
//
// The pure decision is proved in `select.rs`. This file proves the wiring
// around it: that the badness an installed observer reports reaches the
// selector, that the process the selector names is the one that receives
// SIGKILL, that the protections hold against a live registry, and that a
// second event over the same scope does not choose a second victim.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::score::{install_managed_pages, install_memory_observer, OomMemory};
use super::{out_of_memory, Outcome, Scope};
use crate::signum::Signum;
use crate::task::{SchedClass, Task};
use crate::tests::common::registry_test_lock;

/// Managed-page total the scores normalise against.
const TOTAL_PAGES: u64 = 1 << 20;
/// A control group id with no members, for the scope-narrowing test.
const EMPTY_CGID: u64 = 4_242_424;

/// Resident units the stub observer reports, keyed by address-space identity.
/// A test installs its own table; the observer itself is the one PMM would
/// install, so selection reads exactly the path the kernel reads.
fn table() -> &'static std::sync::Mutex<Vec<(usize, u64)>> {
    static TABLE: std::sync::Mutex<Vec<(usize, u64)>> = std::sync::Mutex::new(Vec::new());
    &TABLE
}

fn observe(mm: &vmm::AddressSpace) -> Option<OomMemory> {
    let key = mm as *const vmm::AddressSpace as usize;
    let units = table().lock().unwrap_or_else(|e| e.into_inner())
        .iter().find(|(addr, _)| *addr == key).map(|(_, units)| *units)?;
    Some(OomMemory { proportional_resident_units: units, ..OomMemory::default() })
}

/// A live single-threaded user process holding `resident` PSS units, published
/// in the registry exactly as a spawn would publish it.
fn process(tid: u32, resident: u64) -> Arc<Task> {
    let task = Arc::new(Task::new(tid, "victim", SchedClass::Normal { weight: 1024 }));
    task.tgid.store(tid, Ordering::Release);
    task.vtgid.store(tid, Ordering::Release);
    let mm = vmm::AddressSpace::new(0).expect("hosted address space");
    table().lock().unwrap_or_else(|e| e.into_inner())
        .push((Arc::as_ptr(&mm) as *const vmm::AddressSpace as usize, resident));
    // SAFETY: the task is not published, not running and not on any runqueue, so this test thread is its only mutator for the mm slot.
    unsafe { task.replace_mm(Some(mm)); }
    crate::registry::insert(&task);
    task
}

fn killed(task: &Arc<Task>) -> bool {
    task.sigpending.load(Ordering::Acquire) & Signum::Sigkill.bit() != 0
}

/// Reset every global this file touches, so one test cannot see another's
/// registry, observer table or managed-page total.
fn fixture() -> std::sync::MutexGuard<'static, ()> {
    let guard = registry_test_lock();
    crate::registry::clear_for_tests();
    table().lock().unwrap_or_else(|e| e.into_inner()).clear();
    install_managed_pages(TOTAL_PAGES);
    install_memory_observer(observe);
    guard
}

#[test]
fn the_largest_process_is_the_one_killed() {
    let _guard = fixture();
    let small = process(4001, 1_000);
    let large = process(4002, 900_000);
    let middling = process(4003, 50_000);

    assert_eq!(out_of_memory(Scope::Global), Outcome::Killed);
    assert!(killed(&large), "the largest consumer must be the victim");
    assert!(!killed(&small));
    assert!(!killed(&middling));
    assert!(large.oom_marked(), "the victim must be marked so a second pass sees it");
}

#[test]
fn a_process_pinned_at_the_minimum_adjustment_is_never_chosen() {
    let _guard = fixture();
    let huge = process(4101, 900_000);
    let ordinary = process(4102, 10);
    assert!(huge.set_oom_score_adj(super::OOM_SCORE_ADJ_MIN));

    assert_eq!(out_of_memory(Scope::Global), Outcome::Killed);
    assert!(killed(&ordinary), "the only choosable process must be the victim");
    assert!(!killed(&huge));
}

#[test]
fn the_init_task_is_never_chosen_even_alone() {
    let _guard = fixture();
    let init = process(1, 900_000);

    assert_eq!(out_of_memory(Scope::Global), Outcome::NoKillable);
    assert!(!killed(&init), "the protected init task must survive");
}

#[test]
fn a_kernel_thread_is_never_chosen() {
    let _guard = fixture();
    let helper = Arc::new(Task::new(4201, "kworker", SchedClass::Normal { weight: 1024 }));
    helper.tgid.store(4201, Ordering::Release);
    helper.vtgid.store(4201, Ordering::Release);
    helper.kernel_thread.store(true, Ordering::Release);
    crate::registry::insert(&helper);

    assert_eq!(out_of_memory(Scope::Global), Outcome::NoKillable);
    assert!(!killed(&helper));
}

#[test]
fn a_victim_that_is_still_exiting_stops_a_second_being_chosen() {
    let _guard = fixture();
    let first = process(4301, 900_000);
    let second = process(4302, 800_000);

    assert_eq!(out_of_memory(Scope::Global), Outcome::Killed);
    assert!(killed(&first));
    // The victim is marked and has not exited: every further event over the
    // same scope must wait for it rather than widen the kill.
    for _ in 0..8 { assert_eq!(out_of_memory(Scope::Global), Outcome::InProgress); }
    assert!(!killed(&second), "an OOM storm must not kill every process on the box");
}

#[test]
fn a_larger_process_is_spared_while_a_smaller_victim_is_still_exiting() {
    let _guard = fixture();
    // The victim was chosen by an earlier event and is worth less than what
    // is left running. Selection must still wait for it: the point is that
    // memory is already on its way back, not that it was the biggest.
    let dying = process(4901, 10);
    let biggest = process(4902, 900_000);
    dying.oom_victim.store(true, Ordering::Release);

    assert_eq!(out_of_memory(Scope::Global), Outcome::InProgress);
    assert!(!killed(&biggest), "a pass must not kill a second process while one is exiting");
}

#[test]
fn the_scope_resumes_selecting_once_the_victim_has_gone() {
    let _guard = fixture();
    let first = process(4401, 900_000);
    let second = process(4402, 800_000);

    assert_eq!(out_of_memory(Scope::Global), Outcome::Killed);
    first.set_state(crate::TaskState::Zombie);
    assert_eq!(out_of_memory(Scope::Global), Outcome::Killed);
    assert!(killed(&second), "with the victim gone the next largest is choosable");
}

#[test]
fn a_fault_that_cannot_be_answered_reports_deadlock_instead_of_retrying() {
    let _guard = fixture();
    let init = process(1, 900_000);
    // Nothing here may be killed, so a retry would re-take the same fault with
    // nothing able to change the answer.
    assert_eq!(super::pagefault_out_of_memory(), super::FaultOutcome::Deadlocked);
    assert!(!killed(&init));
}

#[test]
fn a_fault_that_kills_a_victim_asks_for_the_instruction_to_be_re_taken() {
    let _guard = fixture();
    let victim = process(4501, 900_000);
    assert_eq!(super::pagefault_out_of_memory(), super::FaultOutcome::Retake);
    assert!(killed(&victim));
    // And the retry's own next pass is bounded: it reports the kill in
    // progress rather than selecting again.
    assert_eq!(super::pagefault_out_of_memory(), super::FaultOutcome::Retake);
    assert_eq!(out_of_memory(Scope::Global), Outcome::InProgress);
}

#[test]
fn a_control_group_scope_never_widens_into_a_global_scan() {
    let _guard = fixture();
    let outside = process(5001, 900_000);
    // A group with no members of its own has nobody to kill, and must not
    // reach for a process that merely exists elsewhere on the machine.
    assert_eq!(out_of_memory(Scope::Memcg(EMPTY_CGID)), Outcome::NoKillable);
    assert!(!super::kill_memcg(EMPTY_CGID));
    assert!(!killed(&outside));
    // The same process is choosable the moment the scope is the machine.
    assert_eq!(out_of_memory(Scope::Global), Outcome::Killed);
    assert!(killed(&outside));
}

#[test]
fn every_kill_is_counted_once() {
    let _guard = fixture();
    let before = super::kill_count();
    let _big = process(4601, 900_000);
    assert_eq!(out_of_memory(Scope::Global), Outcome::Killed);
    assert_eq!(super::kill_count(), before + 1);
    // The in-progress pass counts nothing.
    assert_eq!(out_of_memory(Scope::Global), Outcome::InProgress);
    assert_eq!(super::kill_count(), before + 1);
}

#[test]
fn a_process_with_no_address_space_is_skipped_not_chosen() {
    let _guard = fixture();
    let bare = Arc::new(Task::new(4701, "bare", SchedClass::Normal { weight: 1024 }));
    bare.tgid.store(4701, Ordering::Release);
    bare.vtgid.store(4701, Ordering::Release);
    bare.kernel_thread.store(false, Ordering::Release);
    crate::registry::insert(&bare);
    let real = process(4702, 5);

    assert_eq!(out_of_memory(Scope::Global), Outcome::Killed);
    assert!(killed(&real));
    assert!(!killed(&bare));
}

#[test]
fn all_threads_of_the_chosen_process_are_scored_through_the_one_holding_the_mm() {
    let _guard = fixture();
    // Leader dropped its mm; a sibling thread still owns the process memory.
    let leader = Arc::new(Task::new(4801, "leader", SchedClass::Normal { weight: 1024 }));
    leader.tgid.store(4801, Ordering::Release);
    leader.vtgid.store(4801, Ordering::Release);
    leader.kernel_thread.store(false, Ordering::Release);
    crate::registry::insert(&leader);
    let sibling = process(4802, 900_000);
    sibling.tgid.store(4801, Ordering::Release);
    let other = process(4803, 1_000);

    assert_eq!(out_of_memory(Scope::Global), Outcome::Killed);
    assert!(killed(&sibling), "the process must be scored through the thread that holds its mm");
    assert!(!killed(&other));
}
