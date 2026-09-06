use sched::{Task, nt_callback::{Registration, RegistrationKind}};
use syscall::{nt::{NtCall, NtService}, nt_native_gdi as abi};

pub(super) fn registration(task: &Task) -> Option<(u64, u64)> {
    task.thread_group.nt_callbacks.lock().iter().find(|r| r.token == abi::TOKEN
        && matches!(r.kind, RegistrationKind::Callback)).map(|r| (r.callback, r.context))
}

pub(crate) fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != NtService::QueryVirtualMemory || call.args.a2 != abi::INFO_CLASS { return None; }
    let Some(task) = sched::live::current() else { return Some(abi::INVALID); };
    if !task.is_nt_personality() { return Some(abi::INVALID); }
    Some(match call.args.a0 {
        abi::REGISTER => register(task, call.args.a1, call.args.a3, call.args.a4),
        abi::COMPLETE => super::context::complete(task, call.args.a1),
        abi::MEASURE_COPY => super::measure::copy_result(task, call.args.a1, call.args.a3),
        abi::QUERY_COPY => super::query::copy_result(task, call.args.a1, call.args.a3),
        abi::ALPHA_UPLOAD => crate::nt_gdi::blend_surface_for_current(call.args.a1, call.args.a3,
            call.args.a5 as u32 as i32, (call.args.a5 >> 32) as u32 as i32,
            call.args.a4 as u32, (call.args.a4 >> 32) as u32),
        _ => abi::INVALID,
    })
}

fn register(task: &Task, entry: u64, ret: u64, version: u64) -> u64 {
    if version != abi::VERSION as u64 || crate::nt_native_thread::factory(task).is_none() { return abi::NOT_READY; }
    // SAFETY: current Task owns mm until this synchronous registration finishes.
    let Some(mm) = (unsafe { task.mm_ref() }) else { return abi::INVALID; };
    for address in [entry, ret] {
        let Some(address) = hal::UserVirtAddr::new(address) else { return abi::INVALID; };
        if !mm.find_vma(address).is_some_and(|v| v.prot.contains(vmm::VmaProt::EXEC)) { return abi::INVALID; }
    }
    let mut entries = task.thread_group.nt_callbacks.lock();
    if entries.iter().any(|r| r.token == abi::TOKEN) || entries.try_reserve(1).is_err() { return abi::INVALID; }
    entries.push(Registration { token: abi::TOKEN, callback: entry, context: ret, kind: RegistrationKind::Callback });
    0
}
