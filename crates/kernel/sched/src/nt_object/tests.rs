use super::*;
use crate::SchedClass;

const READ: u32 = 1;
const WRITE: u32 = 2;

#[test]
fn handles_are_process_local_and_type_stable() {
    let table = NtHandleTable::new();
    let object = table.new_object(NtObjectType::Event);
    let handle = table.insert(object, READ | WRITE).unwrap();
    let resolved = table.get(handle, READ).unwrap();
    assert_eq!(resolved.kind(), NtObjectType::Event);
    assert_eq!(resolved.id(), 1);
    assert!(table.get(handle, 4).is_none());
    assert!(table.contains(handle));
}

#[test]
fn registry_key_handles_have_a_distinct_native_object_type() {
    let table = NtHandleTable::new();
    let handle = table.insert(table.new_key(), READ).unwrap();
    let key = table.get(handle, READ).unwrap();
    assert_eq!(key.kind(), NtObjectType::Key);
    assert_ne!(key.kind(), NtObjectType::File);
}

#[test]
fn event_state_matches_manual_and_auto_reset_rules() {
    let manual = NtObject::new_event(1, true, false).event().unwrap();
    assert!(!manual.try_wait()); manual.set();
    assert!(manual.try_wait()); assert!(manual.try_wait()); manual.reset();
    assert!(!manual.try_wait());
    let auto = NtObject::new_event(2, false, false).event().unwrap();
    auto.set(); assert!(auto.try_wait()); assert!(!auto.try_wait());
}

#[test]
fn pulse_is_transient_and_auto_reset_pulse_has_one_consumer() {
    let manual = NtObject::new_event(6, true, false).event().unwrap();
    let mut manual_epoch = manual.pulse_epoch();
    assert!(!manual.pulse());
    assert!(!manual.is_signaled());
    assert!(manual.try_pulse_since(&mut manual_epoch));
    assert!(!manual.is_signaled());
    assert!(!manual.try_pulse_since(&mut manual_epoch));

    let auto = NtObject::new_event(7, false, false).event().unwrap();
    let mut first_epoch = auto.pulse_epoch();
    let mut second_epoch = first_epoch;
    assert!(!auto.pulse());
    assert!(auto.try_pulse_since(&mut first_epoch));
    assert!(!auto.try_pulse_since(&mut second_epoch));
    let mut new_epoch = auto.pulse_epoch();
    assert!(!auto.try_pulse_since(&mut new_epoch));
}

#[test]
fn semaphore_count_and_maximum_are_enforced() {
    let semaphore = NtObject::new_semaphore(3, 1, 2).semaphore().unwrap();
    assert!(semaphore.try_wait()); assert!(!semaphore.is_signaled());
    assert_eq!(semaphore.release(1), Some(0)); assert_eq!(semaphore.release(2), None);
    assert!(semaphore.try_wait()); assert!(!semaphore.try_wait());
}

#[test]
fn timer_deadlines_support_one_shot_periodic_and_cancel() {
    let one_shot = NtObject::new_timer(4, false).timer().unwrap();
    one_shot.arm(100, 0);
    assert!(!one_shot.is_signaled_at(99));
    assert!(one_shot.try_wait_at(100));
    assert!(!one_shot.try_wait_at(101));
    let periodic = NtObject::new_timer(5, true).timer().unwrap();
    periodic.arm(200, 10);
    assert!(periodic.try_wait_at(200));
    assert!(periodic.try_wait_at(210));
    assert!(periodic.cancel());
    assert!(!periodic.is_signaled_at(220));
}

#[test]
fn completion_port_retains_packets_until_removed() {
    let table = NtHandleTable::new();
    let port = table.new_completion_port(2).completion().unwrap();
    assert_eq!(port.concurrency(), 2);
    assert!(!port.is_signaled());
    port.post(NtCompletionPacket { key: 7, overlapped: 8, status: 9, information: 10 });
    port.post(NtCompletionPacket { key: 11, overlapped: 12, status: 13, information: 14 });
    assert!(port.is_signaled());
    assert_eq!(port.try_remove(), Some(NtCompletionPacket { key: 7, overlapped: 8, status: 9, information: 10 }));
    assert_eq!(port.try_remove(), Some(NtCompletionPacket { key: 11, overlapped: 12, status: 13, information: 14 }));
    assert_eq!(port.try_remove(), None);
}

#[test]
fn named_pipe_handles_accept_completion_port_association() {
    let table = NtHandleTable::new();
    let pipe = alloc::sync::Arc::new(NtPipe::new(NtPipeConfig { pipe_type: 0, read_mode: 0,
        completion_mode: 0, max_instances: 1, inbound_quota: 4096, outbound_quota: 4096,
        timeout_100ns: 0, sharing: 3 }));
    assert!(pipe.reserve_instance());
    let object = table.new_named_pipe_endpoint(pipe, NtPipeSide::Server);
    let port = table.new_completion_port(0).completion().unwrap();
    assert!(object.set_file_completion(port.clone(), 0x55));
    assert_eq!(object.file_completion().map(|(_, key)| key), Some(0x55));
    assert!(!table.new_object(NtObjectType::Event).set_file_completion(port, 0));
}

#[test]
fn section_backing_is_zeroed_and_retains_exact_extent() {
    let section = NtSection::new(8192).unwrap();
    assert_eq!(section.size(), 8192); assert_eq!(section.bytes().len(), 8192);
    assert!(section.bytes().iter().all(|byte| *byte == 0));
    let object = NtObject::new_section(3, section);
    assert_eq!(object.kind(), NtObjectType::Section); assert_eq!(object.section().unwrap().size(), 8192);
}

#[test]
fn process_and_thread_objects_retain_canonical_scheduler_tasks() {
    let process_task = alloc::sync::Arc::new(Task::new(41, "nt-process", SchedClass::Normal { weight: 1024 }));
    let thread_task = alloc::sync::Arc::new(Task::new(42, "nt-thread", SchedClass::Normal { weight: 1024 }));
    let process = NtObject::new_process(41, alloc::sync::Arc::clone(&process_task));
    let thread = NtObject::new_thread(42, alloc::sync::Arc::clone(&thread_task));
    assert_eq!(process.kind(), NtObjectType::Process); assert_eq!(thread.kind(), NtObjectType::Thread);
    assert!(alloc::sync::Arc::ptr_eq(&process.task().unwrap(), &process_task));
    assert!(alloc::sync::Arc::ptr_eq(&thread.task().unwrap(), &thread_task));
}

#[test]
fn close_invalidates_old_generation_before_reuse() {
    let table = NtHandleTable::new();
    let first = table.insert(table.new_object(NtObjectType::File), READ).unwrap();
    assert!(table.close(first)); assert!(table.get(first, READ).is_none()); assert!(!table.contains(first));
    let second = table.insert(table.new_object(NtObjectType::File), READ).unwrap();
    assert_ne!(first, second); assert!(table.get(second, READ).is_some());
}

#[test]
fn duplicate_cannot_escalate_access() {
    let table = NtHandleTable::new();
    let source = table.insert(table.new_object(NtObjectType::Thread), READ).unwrap();
    assert!(table.duplicate(source, WRITE).is_none());
    let copy = table.duplicate(source, READ).unwrap(); assert!(table.get(copy, READ).is_some());
}

#[test]
fn mutant_is_reentrant_and_release_requires_owner() {
    let mutant = NtObject::new_mutant(7, None).mutant().unwrap();
    assert!(mutant.try_acquire(41)); assert!(mutant.try_acquire(41));
    assert!(!mutant.try_acquire(42)); assert_eq!(mutant.release(42), Err(()));
    assert_eq!(mutant.release(41), Ok(-2)); assert!(!mutant.is_signaled_for(42));
    assert_eq!(mutant.release(41), Ok(-1)); assert!(mutant.is_signaled_for(42)); assert!(mutant.try_acquire(42));
}
