//! Native NT I/O completion-port operations.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtObjectCall, NtService};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const STATUS_TIMEOUT: u64 = 0x0000_0102;
const IO_COMPLETION_ALL_ACCESS: u32 = 0x001f_0003;
const IO_COMPLETION_MODIFY_STATE: u32 = 0x0002;
const SYNCHRONIZE: u32 = 0x0010_0000;

pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::NtRemoveIoCompletionEx { return Some(remove_io_completion_ex(call)); }
    if call.service == NtService::RtlSetIoCompletionCallback { return Some(set_io_callback(call)); }
    let Ok(object_call) = syscall::nt::decode_object(call) else { return None; };
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
    let table = cur.thread_group.nt_handles();
    match object_call {
        NtObjectCall::CreateIoCompletion { handle, desired_access, concurrency } => {
            if desired_access & !IO_COMPLETION_ALL_ACCESS != 0 { return Some(STATUS_INVALID_PARAMETER); }
            let object = table.new_completion_port(concurrency);
            let Some(native) = table.insert(object, desired_access) else { return Some(STATUS_INVALID_PARAMETER); };
            if uaccess::put_user_u32(handle.as_u64(), native.raw()).is_err() {
                let _ = table.close(native); return Some(STATUS_INVALID_PARAMETER);
            }
            Some(STATUS_SUCCESS)
        }
        NtObjectCall::SetIoCompletion { request } => {
            let base = request.as_u64();
            let (handle, key, overlapped, status, information) = match (read_u32(base), read_u64(base + 8), read_u64(base + 16), read_u32(base + 24), read_u64(base + 32)) {
                (Some(h), Some(k), Some(o), Some(s), Some(i)) => (h, k, o, s, i), _ => return Some(STATUS_INVALID_PARAMETER),
            };
            let native = sched::nt_object::NtHandle::from_raw(handle);
            let Some(object) = table.get(native, IO_COMPLETION_MODIFY_STATE) else { return Some(if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }); };
            let Some(port) = object.completion() else { return Some(STATUS_INVALID_HANDLE); };
            port.post(sched::nt_object::NtCompletionPacket { key, overlapped, status, information });
            Some(STATUS_SUCCESS)
        }
        NtObjectCall::RemoveIoCompletion { request } => {
            let base = request.as_u64();
            let Some(handle) = read_u32(base) else { return Some(STATUS_INVALID_PARAMETER); };
            let native = sched::nt_object::NtHandle::from_raw(handle);
            let Some(object) = table.get(native, SYNCHRONIZE) else { return Some(if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }); };
            let Some(port) = object.completion() else { return Some(STATUS_INVALID_HANDLE); };
            let timeout = match read_i64(base + 40).and_then(|raw| syscall::nt::decode_timeout(raw).ok()) {
                Some(syscall::nt::NtTimeout::Relative100ns(ticks)) => timekeeper::monotonic_ns().saturating_add(ticks.saturating_mul(100)),
                Some(syscall::nt::NtTimeout::Absolute100ns(_)) => return Some(STATUS_INVALID_PARAMETER),
                None => 0,
            };
            // SAFETY: the completion port remains alive through the wait and
            // owns the scheduler wait list used by this predicate.
            let packet = if let Some(packet) = port.try_remove() { packet } else {
                // SAFETY: the completion port remains alive through the wait.
                let outcome = unsafe { port.wait(timeout, timekeeper::monotonic_ns) };
                if matches!(outcome, sched::WaitOutcome::TimedOut) { return Some(STATUS_TIMEOUT); }
                let Some(packet) = port.try_remove() else { return Some(STATUS_TIMEOUT); };
                packet
            };
            if uaccess::put_user_u64(read_u64(base + 8)?, packet.key).is_err()
                || uaccess::put_user_u64(read_u64(base + 16)?, packet.overlapped).is_err()
                || uaccess::put_user_u32(read_u64(base + 24)?, packet.status).is_err()
                || uaccess::put_user_u64(read_u64(base + 32)?, packet.information).is_err() { return Some(STATUS_INVALID_PARAMETER); }
            Some(STATUS_SUCCESS)
        }
        _ => None,
    }
}

fn remove_io_completion_ex(call: NtCall) -> u64 {
    const STATUS_USER_APC: u64 = 0xc000_00c0;
    const MAX_PACKETS: u32 = 64;
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || call.args.a0 > u32::MAX as u64 || call.args.a1 == 0 || call.args.a3 == 0 || call.args.a2 == 0 || call.args.a2 > MAX_PACKETS as u64 { return STATUS_INVALID_PARAMETER; }
    let table = cur.thread_group.nt_handles();
    let native = sched::nt_object::NtHandle::from_raw(call.args.a0 as u32);
    let Some(object) = table.get(native, SYNCHRONIZE) else { return if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }; };
    let Some(port) = object.completion() else { return STATUS_INVALID_HANDLE; };
    let deadline = if call.args.a4 == 0 { 0 } else {
        let Ok(timeout) = syscall::UserPtr::<i64>::new(call.args.a4) else { return STATUS_INVALID_PARAMETER; };
        match crate::nt_dispatch::wait_deadline(Some(timeout)) { Ok(value) => value, Err(status) => return status }
    };
    let mut packets = alloc::vec::Vec::new();
    while packets.len() < call.args.a2 as usize {
        if let Some(packet) = port.try_remove() { packets.push(packet); continue; }
        if !packets.is_empty() { break; }
        // SAFETY: the completion port remains alive through the wait and owns the scheduler wait list used by this predicate.
        let outcome = unsafe { port.wait(deadline, timekeeper::monotonic_ns) };
        if matches!(outcome, sched::WaitOutcome::TimedOut) { return STATUS_TIMEOUT; }
        if matches!(outcome, sched::WaitOutcome::Interrupted) && call.args.a5 != 0 { return STATUS_USER_APC; }
        let Some(packet) = port.try_remove() else { return STATUS_TIMEOUT; };
        packets.push(packet);
    }
    for (index, packet) in packets.iter().enumerate() {
        let base = call.args.a1.saturating_add(index as u64 * 32);
        if uaccess::put_user_u64(base, packet.key).is_err()
            || uaccess::put_user_u64(base + 8, packet.overlapped).is_err()
            || uaccess::put_user_u64(base + 16, packet.status as u64).is_err()
            || uaccess::put_user_u64(base + 24, packet.information).is_err() { return STATUS_INVALID_PARAMETER; }
    }
    if uaccess::put_user_u32(call.args.a3, packets.len() as u32).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn set_io_callback(call: NtCall) -> u64 {
    if call.args.a0 > u32::MAX as u64 || call.args.a1 == 0 || call.args.a2 != 0 { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let handle = sched::nt_object::NtHandle::from_raw(call.args.a0 as u32);
    let table = cur.thread_group.nt_handles();
    let Some(file) = table.get(handle, 0) else { return STATUS_INVALID_HANDLE; };
    if file.file().is_none() && file.pipe_endpoint().is_none() { return STATUS_INVALID_HANDLE; }
    let port = if let Some(port) = cur.thread_group.nt_io_completion.lock().clone() { port } else {
        let Some(port) = table.new_completion_port(0).completion() else { return STATUS_INVALID_PARAMETER; };
        *cur.thread_group.nt_io_completion.lock() = Some(port.clone()); port
    };
    if !file.set_file_completion(port, call.args.a1) { return STATUS_INVALID_HANDLE; }
    STATUS_SUCCESS
}

fn read_u32(address: u64) -> Option<u32> { uaccess::get_user_u32(address).ok() }
fn read_u64(address: u64) -> Option<u64> { uaccess::get_user_u64(address).ok() }
fn read_i64(address: u64) -> Option<i64> { read_u64(address).map(|value| value as i64) }
