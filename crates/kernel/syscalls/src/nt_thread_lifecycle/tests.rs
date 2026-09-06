use super::*;
use core::cell::Cell;

fn child() -> Arc<Task> {
    let task = Arc::new(Task::new(98177, "nt-create", sched::SchedClass::Normal { weight: 1024 }));
    task.set_nt_teb(0x7000_0000);
    task.set_nt_peb(0x7100_0000);
    task
}

#[test]
fn suspended_handle_observes_canonical_task_before_writeback() {
    let child = child();
    let table = NtHandleTable::new();
    let published = Cell::new(false);
    publish(&child, &table, 0, true, |handle| {
        let target = table.get(handle, 0).unwrap().task().unwrap();
        assert!(Arc::ptr_eq(&target, &child));
        assert_eq!(target.nt_teb(), 0x7000_0000);
        assert_eq!(target.nt_peb(), 0x7100_0000);
        assert!(target.nt_creation_pending.load(Ordering::Acquire));
        assert_eq!(target.nt_suspend_count.load(Ordering::Acquire), 1);
        assert!(!published.get());
        Ok(())
    }, |target| {
        assert!(Arc::ptr_eq(target, &child));
        assert!(target.nt_creation_pending.load(Ordering::Acquire));
        published.set(true);
    }, || unreachable!("successful creation must retain its mappings")).unwrap();
    assert!(published.get());
    assert!(!child.nt_creation_pending.load(Ordering::Acquire));
    assert!(child.nt_suspend_requested());
}

#[test]
fn output_fault_closes_handle_and_never_commits_child() {
    let child = child();
    let table = NtHandleTable::new();
    let written = Cell::new(NtHandle::invalid());
    let refs = Arc::strong_count(&child);
    let result = publish(&child, &table, 0, true, |handle| {
        written.set(handle);
        Err(())
    }, |_| unreachable!("faulted child must remain unpublished"), || {});
    assert_eq!(result, Err(PublishError::Writeback));
    assert!(!table.contains(written.get()));
    assert_eq!(Arc::strong_count(&child), refs);
    assert!(child.nt_creation_pending.load(Ordering::Acquire));
    assert_eq!(child.nt_resume(), 1);
    assert!(!child.claim_nt_initial_wake(), "failed child cannot be resumed into freed mappings");
}

#[test]
fn suspended_native_writeback_failure_allows_pthread_cleanup() {
    let child = child();
    let table = NtHandleTable::new();
    let written = Cell::new(NtHandle::invalid());
    let result = publish(&child, &table, 0, true, |handle| {
        written.set(handle);
        assert!(child.nt_creation_pending.load(Ordering::Acquire));
        assert!(child.nt_suspend_requested());
        Err(())
    }, |_| unreachable!("failed native publication cannot enter PE"),
        || cancel_native_publication(&child));
    assert_eq!(result, Err(PublishError::Writeback));
    assert!(!table.contains(written.get()));
    assert!(!child.nt_creation_pending.load(Ordering::Acquire));
    assert!(!child.nt_suspend_requested(), "libc cleanup must not park behind failed CREATE_SUSPENDED");
    assert_eq!(child.nt_teb(), 0x7000_0000, "TEB remains borrowed until terminal pthread exit");
}

#[test]
fn resume_during_writeback_is_not_overwritten_at_commit() {
    let child = child();
    let table = NtHandleTable::new();
    publish(&child, &table, 0, true, |handle| {
        let target = table.get(handle, 0).unwrap().task().unwrap();
        assert_eq!(target.nt_resume(), 1);
        assert!(target.nt_creation_pending.load(Ordering::Acquire));
        assert!(!target.claim_nt_initial_wake());
        Ok(())
    }, |_| {}, || unreachable!()).unwrap();
    assert!(!child.nt_suspend_requested());
    assert!(!child.nt_creation_pending.load(Ordering::Acquire));
    assert!(child.claim_nt_initial_wake());
    assert!(!child.claim_nt_initial_wake(), "creator and concurrent resume must not both activate");
}

#[test]
fn suspend_during_writeback_is_preserved_at_commit() {
    let child = child();
    let table = NtHandleTable::new();
    publish(&child, &table, 0, false, |handle| {
        let target = table.get(handle, 0).unwrap().task().unwrap();
        assert_eq!(target.nt_suspend(), Ok(0));
        Ok(())
    }, |_| {}, || unreachable!()).unwrap();
    assert!(child.nt_suspend_requested());
    assert!(!child.nt_creation_pending.load(Ordering::Acquire));
    assert!(!child.claim_nt_initial_wake());
}

#[test]
fn concurrent_birth_and_resume_have_one_activation_owner() {
    extern crate std;
    let child = child();
    let table = NtHandleTable::new();
    publish(&child, &table, 0, false, |_| Ok(()), |_| {}, || unreachable!()).unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let mut workers = alloc::vec::Vec::new();
    for _ in 0..2 {
        let child = child.clone();
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || { barrier.wait(); child.claim_nt_initial_wake() }));
    }
    barrier.wait();
    let claims: usize = workers.into_iter().map(|worker| usize::from(worker.join().unwrap())).sum();
    assert_eq!(claims, 1);
    assert_eq!(child.state(), sched::TaskState::Waking);
}

#[test]
fn writeback_fault_rolls_back_private_teb_and_stack_after_closing_handle() {
    let mm = vmm::AddressSpace::new(0x80_000).unwrap();
    let stack = mm.mmap(None, 0x8000, vmm::VmaProt::READ | vmm::VmaProt::WRITE,
        vmm::VmaFlags::PRIVATE, vmm::VmaBacking::Anonymous, false).unwrap();
    let child = child();
    let teb = elf_load::process_env::build_thread_teb_with_stack(
        7, child.tid, child.nt_peb(), stack.as_u64(), stack.as_u64() + 0x8000, &mm).unwrap();
    child.set_nt_teb(teb.as_u64());
    let table = NtHandleTable::new();
    let handle = Cell::new(NtHandle::invalid());
    let rollbacks = Cell::new(0);
    let result = publish(&child, &table, 0, true, |native| {
        handle.set(native);
        assert!(mm.find_vma(teb).is_some());
        Err(())
    }, |_| unreachable!(), || {
        assert!(!table.contains(handle.get()));
        assert!(!child.claim_nt_initial_wake());
        assert!(elf_load::process_env::unmap_thread_teb(teb, &mm));
        mm.munmap(stack, 0x8000).unwrap();
        rollbacks.set(rollbacks.get() + 1);
    });
    assert_eq!(result, Err(PublishError::Writeback));
    assert_eq!(rollbacks.get(), 1);
    assert!(mm.find_vma(teb).is_none());
    assert!(mm.find_vma(stack).is_none());
    assert_eq!(mm.vma_count(), 0);
}
