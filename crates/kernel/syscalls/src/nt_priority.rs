//! Native process/thread priority information classes.

use syscall::nt::{NtCall, NtService};

const CURRENT_PROCESS: u64 = u64::MAX;
const CURRENT_THREAD: u64 = u64::MAX - 1;
const THREAD_SET_INFORMATION: u32 = 0x0020;
const STATUS_SUCCESS: u64 = 0;
const STATUS_INFO_LENGTH_MISMATCH: u64 = 0xc000_0004;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const STATUS_PRIVILEGE_NOT_HELD: u64 = 0xc000_0061;

const PROCESS_BASE_PRIORITY: u64 = 5;
const PROCESS_PRIORITY_CLASS: u64 = 18;
const PROCESS_PRIORITY_BOOST: u64 = 22;
const THREAD_PRIORITY: u64 = 2;
const THREAD_BASE_PRIORITY: u64 = 3;
const THREAD_AFFINITY_MASK: u64 = 5;
const THREAD_PRIORITY_BOOST: u64 = 14;
const THREAD_AFFINITY_MASK_BYTES: u64 = 8;

pub(crate) fn dispatch(call: NtCall) -> Option<u64> {
    match call.service {
        NtService::SetInformationProcess => Some(set_process(call)),
        NtService::SetInformationThread => Some(set_thread(call)),
        _ => None,
    }
}

fn set_process(call: NtCall) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || call.args.a0 != CURRENT_PROCESS {
        return STATUS_INVALID_HANDLE;
    }
    let permit = cur.has_cap(sched::cap::SYS_NICE);
    let request = match call.args.a1 {
        PROCESS_BASE_PRIORITY => {
            if call.args.a3 != 4 { return STATUS_INFO_LENGTH_MISMATCH; }
            let Ok(raw) = uaccess::get_user_u32(call.args.a2) else { return STATUS_INVALID_PARAMETER; };
            let priority = raw & 0x7fff_ffff;
            if !(1..=31).contains(&priority) { return STATUS_INVALID_PARAMETER; }
            sched::NtProcessSchedRequest::BasePriority {
                priority: priority as u8, may_increase: permit }
        }
        PROCESS_PRIORITY_CLASS => {
            if call.args.a3 != 2 { return STATUS_INFO_LENGTH_MISMATCH; }
            let mut bytes = [0u8; 2];
            if uaccess::copy_from_user(&mut bytes, call.args.a2).is_err() {
                return STATUS_INVALID_PARAMETER;
            }
            let Some(class) = decode_class(bytes[1]) else { return STATUS_INVALID_PARAMETER; };
            sched::NtProcessSchedRequest::PriorityClass {
                class, foreground: Some(bytes[0] != 0), may_increase: permit }
        }
        PROCESS_PRIORITY_BOOST => {
            if call.args.a3 != 4 { return STATUS_INFO_LENGTH_MISMATCH; }
            let Ok(disabled) = uaccess::get_user_u32(call.args.a2) else {
                return STATUS_INVALID_PARAMETER;
            };
            sched::NtProcessSchedRequest::PriorityBoost { disabled: disabled != 0 }
        }
        _ => return STATUS_INVALID_PARAMETER,
    };
    status(sched::apply_nt_process(&cur.thread_group, request))
}

fn set_thread(call: NtCall) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let table = cur.thread_group.nt_handles();
    let target = if call.args.a0 == CURRENT_THREAD {
        match sched::registry::lookup(cur.tid) {
            Some(task) => task, None => return STATUS_INVALID_HANDLE,
        }
    } else {
        if call.args.a0 > u32::MAX as u64 { return STATUS_INVALID_HANDLE; }
        let handle = sched::nt_object::NtHandle::from_raw(call.args.a0 as u32);
        let Some(object) = table.get(handle, THREAD_SET_INFORMATION) else {
            return if table.contains(handle) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE };
        };
        if object.kind() != sched::nt_object::NtObjectType::Thread {
            return STATUS_INVALID_HANDLE;
        }
        let Some(task) = object.task() else { return STATUS_INVALID_HANDLE; };
        task
    };
    if call.args.a1 == THREAD_AFFINITY_MASK {
        if call.args.a3 != THREAD_AFFINITY_MASK_BYTES { return STATUS_INFO_LENGTH_MISMATCH; }
        let Ok(raw) = uaccess::get_user_u64(call.args.a2) else { return STATUS_INVALID_PARAMETER; };
        let want = cpu::CpuMask::from_words(&[raw]);
        let active = cpu::smp::online_cpumask();
        let active = if active.is_empty() { cpu::CpuMask::of(0) } else { active };
        let process = target.thread_group.leader_task()
            .map_or_else(|| target.cpus_allowed.load(core::sync::atomic::Ordering::Acquire),
                |leader| leader.cpus_allowed.load(core::sync::atomic::Ordering::Acquire));
        if crate::nt_thread_info_policy::affinity(
            want, process, active, target.no_setaffinity.load(core::sync::atomic::Ordering::Acquire)).is_err() {
            return STATUS_INVALID_PARAMETER;
        }
        sched::live::update_affinity(&target, Some(want), None);
        return crate::nt_thread_info_policy::success();
    }
    if call.args.a3 != 4 { return STATUS_INFO_LENGTH_MISMATCH; }
    let Ok(raw) = uaccess::get_user_u32(call.args.a2) else { return STATUS_INVALID_PARAMETER; };
    let value = raw as i32;
    let request = match call.args.a1 {
        THREAD_PRIORITY => {
            if !(1..=31).contains(&value) { return STATUS_INVALID_PARAMETER; }
            sched::NtThreadSchedRequest::Priority {
                priority: value as u8, may_increase: cur.has_cap(sched::cap::SYS_NICE) }
        }
        THREAD_BASE_PRIORITY => {
            let Ok(relative) = i8::try_from(value) else { return STATUS_INVALID_PARAMETER; };
            sched::NtThreadSchedRequest::BasePriority(relative)
        }
        THREAD_PRIORITY_BOOST => sched::NtThreadSchedRequest::PriorityBoost {
            disabled: value != 0 },
        _ => return STATUS_INVALID_PARAMETER,
    };
    status(sched::apply_nt_thread(&target, request))
}

fn decode_class(raw: u8) -> Option<sched::NtPriorityClass> {
    match raw { 1 => Some(sched::NtPriorityClass::Idle),
        2 => Some(sched::NtPriorityClass::Normal),
        3 => Some(sched::NtPriorityClass::High),
        4 => Some(sched::NtPriorityClass::Realtime),
        5 => Some(sched::NtPriorityClass::BelowNormal),
        6 => Some(sched::NtPriorityClass::AboveNormal), _ => None }
}

fn status(result: Result<(), sched::NtSchedError>) -> u64 {
    match result { Ok(()) => STATUS_SUCCESS,
        Err(sched::NtSchedError::InvalidPriority) => STATUS_INVALID_PARAMETER,
        Err(sched::NtSchedError::PrivilegeNotHeld) => STATUS_PRIVILEGE_NOT_HELD }
}
