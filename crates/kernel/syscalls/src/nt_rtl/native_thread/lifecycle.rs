use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use sched::{Task, nt_native_thread::{Child, Phase}};
use syscall::nt_native_thread as abi;

pub(super) fn prepare(task: &Task, creator: u64, generation: u64, output: u64) -> u64 {
    let Ok(creator) = u32::try_from(creator) else { return abi::INVALID; };
    let Some(parent) = sched::registry::lookup(creator) else { return abi::INVALID; };
    if parent.tid == task.tid || !Arc::ptr_eq(&parent.thread_group, &task.thread_group)
        || task.clear_child_tid.load(Ordering::Acquire) == 0 || task.nt_native_thread.lock().child.is_some() {
        return abi::INVALID;
    }
    let request = match parent.nt_native_thread.lock().request {
        Some(request) if request.generation == generation && request.child.is_none() => request,
        _ => return abi::INVALID,
    };
    // SAFETY: current pthread owns this mm; the Arc pins its mappings during preparation.
    let Some(mm) = (unsafe { task.mm_ref() }).cloned() else { return abi::INVALID; };
    let stack = match mm.mmap(None, request.stack_size as usize, vmm::VmaProt::READ | vmm::VmaProt::WRITE,
        vmm::VmaFlags::PRIVATE, vmm::VmaBacking::Anonymous, false) { Ok(stack) => stack, Err(_) => return abi::NO_MEMORY };
    let teb = match elf_load::process_env::build_thread_teb_with_stack(
        parent.tgid.load(Ordering::Acquire), task.tid, parent.nt_peb(), stack.as_u64(),
        stack.as_u64() + request.stack_size, &mm) {
        Ok(teb) => teb,
        Err(_) => { let _ = mm.munmap(stack, request.stack_size as usize); return abi::NO_MEMORY; }
    };
    let rollback = || { let _ = elf_load::process_env::unmap_thread_teb(teb, &mm); let _ = mm.munmap(stack, request.stack_size as usize); };
    if uaccess::put_user_u64(output, teb.as_u64()).is_err()
        || output.checked_add(8).is_none_or(|p| uaccess::put_user_u64(p, parent.nt_peb()).is_err()) { rollback(); return abi::INVALID; }
    let mut parent_state = parent.nt_native_thread.lock();
    let Some(pending) = parent_state.request.as_mut().filter(|pending| pending.generation == generation && pending.child.is_none()) else {
        drop(parent_state); rollback(); return abi::INVALID;
    };
    pending.child = Some(task.tid);
    task.nt_native_thread.lock().child = Some(Child { creator, generation, phase: Phase::Preparing,
        stack: stack.as_u64(), size: request.stack_size, start: request.start, parameter: request.parameter });
    drop(parent_state);
    let _ = sched::nt_object::ThreadDesktop::inherit_thread(&parent, task);
    task.set_nt_peb(parent.nt_peb()); task.set_nt_teb(teb.as_u64()); task.set_nt_start_address(request.start);
    task.set_nt_personality(true);
    sched::initialize_current_process(task);
    abi::SUCCESS
}

pub(super) fn publish(parent: &Task) -> u64 {
    let Some(request) = parent.nt_native_thread.lock().request else { return abi::INVALID; };
    let Some(child) = request.child.and_then(sched::registry::lookup) else { return abi::INVALID; };
    if !Arc::ptr_eq(&parent.thread_group, &child.thread_group) { return abi::INVALID; }
    let state = child.nt_native_thread.lock();
    if !state.child.is_some_and(|c| c.creator == parent.tid && c.generation == request.generation && c.phase == Phase::Ready) {
        return abi::NOT_READY;
    }
    drop(state);
    const THREAD_ALL_ACCESS: u32 = 0x001f_ffff;
    let table = parent.thread_group.nt_handles();
    match crate::nt_thread_lifecycle::publish(&child, &table, THREAD_ALL_ACCESS, request.suspended,
        |handle| uaccess::put_user_u32(request.output, handle.raw()).map_err(|_| ()),
        |child| { let _ = child.nt_native_thread.lock().advance(Phase::Ready, Phase::Published); },
        || crate::nt_thread_lifecycle::cancel_native_publication(&child)) {
        Ok(()) => abi::SUCCESS,
        Err(crate::nt_thread_lifecycle::PublishError::NoMemory) => abi::NO_MEMORY,
        Err(_) => abi::INVALID,
    }
}

pub(super) fn release(task: &Task) -> u64 {
    let mut state = task.nt_native_thread.lock();
    let Some(child) = state.child else { return abi::INVALID; };
    if child.phase == Phase::Running || state.resume.is_some() { return abi::INVALID; }
    // NTDLL's private pthread key borrows TEB until libc teardown completes.
    // Keep mappings owned by this Task until its terminal kernel exit hook.
    state.child.as_mut().unwrap().phase = Phase::Returning;
    abi::SUCCESS
}

/// Canonical do_exit hook after userspace pthread teardown, before mm release. # C: O(log N_vmas)
pub(crate) fn cleanup_at_exit(task: &Task) {
    let mut state = task.nt_native_thread.lock();
    let Some(child) = state.child.take() else { return; };
    state.resume = None; state.terminate = None;
    drop(state);
    // SAFETY: terminal task owns its mm until the canonical exit path drops it.
    let Some(mm) = (unsafe { task.mm_ref() }) else { return; };
    if let Some(teb) = hal::UserVirtAddr::new(task.nt_teb()) { let _ = elf_load::process_env::unmap_thread_teb(teb, mm); }
    if let Some(stack) = hal::UserVirtAddr::new(child.stack) { let _ = mm.munmap(stack, child.size as usize); }
    task.set_nt_teb(0);
    task.nt_creation_pending.store(false, Ordering::Release);
}

/// Queue native termination on its canonical Task; no process-fatal signal. # C: O(1)
pub(crate) fn request_termination(task: &Arc<Task>, status: u32) -> bool {
    let mut state = task.nt_native_thread.lock();
    if !state.request_termination(status) { return false; }
    drop(state);
    task.nt_suspend_count.store(0, Ordering::Release);
    sched::preempt::resched::set_tsk_need_resched(task);
    // SAFETY: canonical Task Arc pins the native target during scheduler-owned wake.
    unsafe { let _ = sched::live::ttwu::try_to_wake_up(task.clone()); }
    sched::live::ttwu::resched_curr(task.cpu.load(Ordering::Acquire) as u32);
    true
}

/// Primary return-to-user hook, before NT suspension. # C: O(1)
pub(crate) unsafe fn exit_to_user(task: &Task, frame: *mut crate::arch_frame::UserRegs) -> Option<u64> {
    if frame.is_null() { return None; }
    let state = task.nt_native_thread.lock();
    let status = state.terminate?;
    if !state.termination_ready(true) { return None; }
    drop(state);
    // SAFETY: return-to-user owns this live frame and the current Task's mm.
    let pe_pc = unsafe {
        #[cfg(target_arch = "x86_64")]
        let pc = (*frame).rip;
        #[cfg(target_arch = "aarch64")]
        let pc = (*frame).elr_el1;
        task.mm_ref().is_some_and(|mm| elf_load::pe_modules::find(mm.root_pa(), pc).is_some())
    };
    if !task.nt_native_thread.lock().termination_ready(pe_pc) { return None; }
    // SAFETY: primary return-to-user owner supplies its actual live IRQ/syscall frame.
    Some(unsafe { super::context::return_native_at(task, status, frame) })
}
