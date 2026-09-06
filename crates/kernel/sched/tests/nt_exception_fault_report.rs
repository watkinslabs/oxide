// Where an unresolved user fault is REPORTED: a Windows thread reaches its own
// exception dispatcher, every other thread reaches the POSIX signal path.
//
// The fault funnel asks exactly one question — `publish_for_current` — and
// reports the signal when the answer is no, so this test pins the whole
// branch. Without it the decision would only be observable at a boot.

use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use std::boxed::Box;
use std::sync::Mutex;

use sched::nt_exception::fault::{self, x86_64, Raised, READ_FAULT, WRITE_FAULT, STATUS_ACCESS_VIOLATION};
use sched::{SchedClass, Task};

static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static NEXT_TID: AtomicU64 = AtomicU64::new(0x4a00);
static TEST_LOCK: Mutex<()> = Mutex::new(());

/// A user-mode write to a mapped-but-refused page: PROT|WRITE|USER.
const WRITE_ERROR_CODE: u64 = 0x7;
const FAULT_ADDRESS: u64 = 0x0000_0000_dead_beef;
const FAULT_PC: u64 = 0x0000_7ff8_1234_5670;

fn hooked_current() -> Option<&'static Task> {
    let task = CURRENT.load(Ordering::Acquire);
    if task.is_null() { return None; }
    // SAFETY: the tests store leaked Task pointers and clear the slot before returning.
    Some(unsafe { &*task })
}

fn install_current(nt: bool) -> &'static Task {
    let tid = NEXT_TID.fetch_add(1, Ordering::Relaxed);
    let task = Box::leak(Box::new(Task::new(tid as u32, "nt-fault-test", SchedClass::Normal { weight: 1024 })));
    task.set_nt_personality(nt);
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
    task
}

fn clear_current() { CURRENT.store(ptr::null_mut(), Ordering::Release); }

fn write_fault() -> Option<Raised> { Some(x86_64::page_fault(WRITE_ERROR_CODE, FAULT_ADDRESS, FAULT_PC)) }

#[test]
fn a_windows_thread_fault_becomes_a_pending_exception_not_a_signal() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    let task = install_current(true);
    assert!(fault::publish_for_current(write_fault()));
    let pending = task.nt_exception.peek().expect("the fault is queued against the faulting thread");
    // A hardware trap carries no context: the return-to-user pass captures it.
    assert!(pending.context.is_none());
    assert!(pending.first_chance);
    assert_eq!(u32::from_le_bytes(pending.record[0..4].try_into().unwrap()), STATUS_ACCESS_VIOLATION);
    assert_eq!(u32::from_le_bytes(pending.record[0x18..0x1c].try_into().unwrap()), 2);
    assert_eq!(u64::from_le_bytes(pending.record[0x20..0x28].try_into().unwrap()), WRITE_FAULT);
    assert_eq!(u64::from_le_bytes(pending.record[0x28..0x30].try_into().unwrap()), FAULT_ADDRESS);
    assert_eq!(u64::from_le_bytes(pending.record[0x10..0x18].try_into().unwrap()), FAULT_PC);
    clear_current();
}

#[test]
fn a_thread_without_the_windows_personality_reports_through_the_signal_path() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    let task = install_current(false);
    assert!(!fault::publish_for_current(write_fault()));
    assert!(!task.nt_exception.is_pending());
    clear_current();
}

#[test]
fn a_condition_with_no_windows_exception_reports_through_the_signal_path() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    let task = install_current(true);
    // The device-not-available trap has no runtime-describable exception.
    assert!(!fault::publish_for_current(x86_64::trap(hal::fault_class::x86_64::TRAP_NM, FAULT_PC)));
    assert!(!task.nt_exception.is_pending());
    clear_current();
}

#[test]
fn a_fault_taken_while_an_exception_is_pending_is_not_queued_behind_it() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    let task = install_current(true);
    assert!(fault::publish_for_current(write_fault()));
    // The second fault must reach the signal path: the dispatcher can only
    // consume one record, and a replaced one would be lost silently.
    let read = Some(x86_64::page_fault(0x4, FAULT_ADDRESS, FAULT_PC));
    assert!(!fault::publish_for_current(read));
    let pending = task.nt_exception.peek().expect("the first exception still owns the slot");
    assert_eq!(u64::from_le_bytes(pending.record[0x20..0x28].try_into().unwrap()), WRITE_FAULT);
    let _ = READ_FAULT;
    clear_current();
}

#[test]
fn no_current_thread_reports_through_the_signal_path() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    clear_current();
    sched::set_current_hook(hooked_current);
    assert!(!fault::publish_for_current(write_fault()));
}
