use sched::{Task, nt_callback::{Registration, RegistrationKind}, nt_native_thread::Request};
use syscall::nt_native_thread as abi;

pub(super) fn register(task: &Task, entry: u64, return_entry: u64, pe_return: u64, version: u64) -> u64 {
    if version != abi::VERSION || !task.is_nt_personality() { return abi::INVALID; }
    // SAFETY: running task pins its address space through callback registration.
    let Some(mm) = (unsafe { task.mm_ref() }) else { return abi::INVALID; };
    for address in [entry, return_entry, pe_return] {
        let Some(address) = hal::UserVirtAddr::new(address) else { return abi::INVALID; };
        if !mm.find_vma(address).is_some_and(|vma| vma.prot.contains(vmm::VmaProt::EXEC)) { return abi::INVALID; }
    }
    let mut registrations = task.thread_group.nt_callbacks.lock();
    if registrations.iter().any(|r| matches!(r.kind, RegistrationKind::NativeThreadFactory { .. })) { return abi::INVALID; }
    registrations.push(Registration { token: 0, callback: entry, context: 0,
        kind: RegistrationKind::NativeThreadFactory { return_entry, pe_return } });
    abi::SUCCESS
}

pub(crate) fn factory(task: &Task) -> Option<(u64, u64, u64)> {
    task.thread_group.nt_callbacks.lock().iter().find_map(|entry| match entry.kind {
        RegistrationKind::NativeThreadFactory { return_entry, pe_return } => Some((entry.callback, return_entry, pe_return)),
        _ => None,
    })
}

pub(crate) fn begin(task: &Task, output: u64, start: u64, parameter: u64, stack_size: u64, suspended: bool) -> u64 {
    let Some((entry, return_entry, _)) = factory(task) else { return abi::NOT_READY; };
    let generation = {
        let mut state = task.nt_native_thread.lock();
        if state.request.is_some() { return abi::INVALID; }
        let Some(generation) = state.generation.checked_add(1) else { return abi::INVALID; };
        state.generation = generation;
        state.request = Some(Request { generation, output, start, parameter, stack_size, suspended, child: None });
        generation
    };
    let request = abi::FactoryRequest { creator: task.tid as u64, generation };
    match super::context::factory(task, entry, return_entry, request) {
        Ok(value) => value,
        Err(status) => { task.nt_native_thread.lock().request = None; status }
    }
}
