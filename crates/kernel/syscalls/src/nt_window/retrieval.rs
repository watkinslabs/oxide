//! Nested message retrieval survives internal position callbacks on its owner Task.
use super::*;
use crate::nt_retrieval_policy as policy;
pub(super) use policy::Retrieval;

pub(super) fn pump(call: NtCall, raw: bool) -> Option<u64> {
    loop {
    if !send::has_current() && !position::has_remote_for_current() { return None; }
    let cur = sched::live::current()?;
    {
        let mut entries = GUI.lock();
        let entry = entries.iter_mut().find(|e| e.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
        if !policy::push(&mut entry.retrievals, Retrieval { tid: cur.tid as u64, call, raw }) { return Some(STATUS_QUOTA_EXCEEDED); }
    }
    let result = match send::pump_current() {
        Some(send::Outcome::Pending) => Some(STATUS_PENDING),
        Some(send::Outcome::Complete(_)) => Some(STATUS_SUCCESS),
        None => position::pump_position_current(),
    };
    if result == Some(STATUS_PENDING) { return result; }
    let _ = take();
    }
}

fn take() -> Option<Retrieval> {
    let cur = sched::live::current()?;
    let mut entries = GUI.lock();
    let entry = entries.iter_mut().find(|e| e.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
    policy::pop(&mut entry.retrievals, cur.tid as u64)
}

pub(crate) fn resume_position_message_current() -> u64 {
    let Some(saved) = take() else { return STATUS_INVALID_PARAMETER; };
    let status = dispatch::dispatch_mode(saved.call, saved.raw).unwrap_or(STATUS_INVALID_PARAMETER);
    if saved.raw { raw_result(saved.call, status) } else { status }
}

pub(crate) fn retrieve_raw(call: NtCall) -> u64 {
    let status = dispatch::dispatch_mode(call, true).unwrap_or(STATUS_INVALID_PARAMETER);
    raw_result(call, status)
}

fn raw_result(call: NtCall, status: u64) -> u64 {
    let get = call.service == nt::NtService::GetMessage;
    let message = if get && status == STATUS_SUCCESS {
        call.args.a0.checked_add(8).and_then(|address| uaccess::get_user_u32(address).ok())
    } else { None };
    let result = policy::raw_result(get, status, message);
    if get && result == 1 { crate::nt_milestone::message_get(); }
    result
}
