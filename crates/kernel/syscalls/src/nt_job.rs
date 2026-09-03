//! Native NT job information over the scheduler-owned job object.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtService};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const STATUS_INFO_LENGTH_MISMATCH: u64 = 0xc000_0004;
const JOB_QUERY: u32 = 0x0004;
const JOB_SET: u32 = 0x0002;
const BASIC_LIMIT: u32 = 2;
const EXTENDED_LIMIT: u32 = 9;
const BASIC_ACCOUNTING: u32 = 1;
const BASIC_LIMIT_BYTES: usize = 64;
const EXTENDED_LIMIT_BYTES: usize = 144;
const BASIC_VALID_FLAGS: u32 = 0xff;
const EXTENDED_VALID_FLAGS: u32 = 0x7fff;

/// Dispatch the information classes implemented by Wine's ntdll job adapter.
/// The job object and its state remain owned by `sched::nt_object`.
pub fn dispatch(call: NtCall) -> Option<u64> {
    match call.service {
        NtService::SetInformationJobObject => Some(set_information(call)),
        NtService::QueryInformationJobObject => Some(query_information(call)),
        _ => None,
    }
}

fn job(call: NtCall, access: u32) -> Result<alloc::sync::Arc<sched::nt_object::NtJob>, u64> {
    let Some(current) = sched::live::current() else { return Err(STATUS_INVALID_PARAMETER); };
    if !current.is_nt_personality() || call.args.a0 > u32::MAX as u64 { return Err(STATUS_INVALID_PARAMETER); }
    let handle = sched::nt_object::NtHandle::from_raw(call.args.a0 as u32);
    let table = current.thread_group.nt_handles();
    let Some(object) = table.get(handle, access) else {
        return Err(if table.contains(handle) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE });
    };
    if object.kind() != sched::nt_object::NtObjectType::Job { return Err(STATUS_INVALID_HANDLE); }
    object.job().ok_or(STATUS_INVALID_HANDLE)
}

fn set_information(call: NtCall) -> u64 {
    let required = match call.args.a1 as u32 { BASIC_LIMIT => BASIC_LIMIT_BYTES, EXTENDED_LIMIT => EXTENDED_LIMIT_BYTES, _ => return STATUS_INVALID_PARAMETER };
    if call.args.a2 == 0 || call.args.a3 as usize != required { return STATUS_INVALID_PARAMETER; }
    let mut bytes = [0u8; EXTENDED_LIMIT_BYTES];
    if uaccess::copy_from_user(&mut bytes[..required], call.args.a2).is_err() { return STATUS_INVALID_PARAMETER; }
    let flags = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    let valid = if call.args.a1 as u32 == BASIC_LIMIT { BASIC_VALID_FLAGS } else { EXTENDED_VALID_FLAGS };
    if flags & !valid != 0 { return STATUS_INVALID_PARAMETER; }
    let limits = sched::nt_object::NtJobLimits {
        flags,
        active_process_limit: u32::from_le_bytes(bytes[40..44].try_into().unwrap()),
        process_memory_limit: if required == EXTENDED_LIMIT_BYTES { u64::from_le_bytes(bytes[112..120].try_into().unwrap()) } else { 0 },
        job_memory_limit: if required == EXTENDED_LIMIT_BYTES { u64::from_le_bytes(bytes[120..128].try_into().unwrap()) } else { 0 },
    };
    let job = match job(call, JOB_SET) { Ok(job) => job, Err(status) => return status };
    job.set_limits(limits);
    STATUS_SUCCESS
}

fn query_information(call: NtCall) -> u64 {
    let (required, accounting) = match call.args.a1 as u32 {
        BASIC_LIMIT => (BASIC_LIMIT_BYTES, false),
        EXTENDED_LIMIT => (EXTENDED_LIMIT_BYTES, false),
        BASIC_ACCOUNTING => (40, true),
        _ => return STATUS_INVALID_PARAMETER,
    };
    if call.args.a2 == 0 || (call.args.a3 as usize) < required { return STATUS_INFO_LENGTH_MISMATCH; }
    let job = match job(call, JOB_QUERY) { Ok(job) => job, Err(status) => return status };
    let limits = job.limits();
    let mut bytes = [0u8; EXTENDED_LIMIT_BYTES];
    if !accounting {
        bytes[16..20].copy_from_slice(&limits.flags.to_le_bytes());
        bytes[40..44].copy_from_slice(&limits.active_process_limit.to_le_bytes());
        if required == EXTENDED_LIMIT_BYTES {
            bytes[112..120].copy_from_slice(&limits.process_memory_limit.to_le_bytes());
            bytes[120..128].copy_from_slice(&limits.job_memory_limit.to_le_bytes());
        }
    }
    if uaccess::copy_to_user(call.args.a2, &bytes[..required]).is_err() { return STATUS_INVALID_PARAMETER; }
    if call.args.a4 != 0 && uaccess::put_user_u32(call.args.a4, required as u32).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}
