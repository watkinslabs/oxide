//! Native NT I/O completion-port operations.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtService};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const STATUS_TIMEOUT: u64 = 0x0000_0102;
const STATUS_NOT_IMPLEMENTED: u64 = 0xc000_0002;
const STATUS_NO_MEMORY: u64 = 0xc000_0017;
use crate::nt_access::{IO_COMPLETION, IO_COMPLETION_MODIFY_STATE};

pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::NtRemoveIoCompletionEx { return Some(remove_io_completion_ex(call)); }
    if call.service == NtService::RtlSetIoCompletionCallback { return Some(set_io_callback(call)); }
    if call.service == NtService::CreateIoCompletion { return Some(create_io_completion(call)); }
    if call.service == NtService::SetIoCompletion { return Some(set_io_completion(call)); }
    if call.service == NtService::RemoveIoCompletion { return Some(remove_io_completion(call)); }
    None
}

/// Create one completion port. The object attributes are the third argument
/// and the concurrent-thread count the fourth; reading the count from the
/// attributes pointer made every port's concurrency an address.
/// # C: O(1)
fn create_io_completion(call: NtCall) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || call.args.a0 == 0 { return STATUS_INVALID_PARAMETER; }
    // A named port needs a namespace owner for the completion type; claiming
    // the name silently would publish nothing under it.
    if call.args.a2 != 0 { return STATUS_NOT_IMPLEMENTED; }
    let Some(granted_access) = IO_COMPLETION.grant(crate::nt_obj_sig::ulong(call.args.a1)) else { return STATUS_INVALID_PARAMETER; };
    let table = cur.thread_group.nt_handles();
    let object = table.new_completion_port(crate::nt_obj_sig::ulong(call.args.a3));
    let Some(native) = table.insert(object, granted_access) else { return STATUS_NO_MEMORY; };
    if uaccess::put_user_u64(call.args.a0, u64::from(native.raw())).is_err() {
        let _ = table.close(native); return STATUS_INVALID_PARAMETER;
    }
    STATUS_SUCCESS
}

/// Post one completion packet from the five-argument service shape. The key,
/// value and byte count are pointer-width scalars and the status a 32-bit
/// `NTSTATUS`; reading them from a record the caller never built refused
/// every post.
/// # C: O(1)
fn set_io_completion(call: NtCall) -> u64 {
    let request = crate::nt_obj_sig::set_io_completion([call.args.a0, call.args.a1, call.args.a2, call.args.a3, call.args.a4]);
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let table = cur.thread_group.nt_handles();
    let native = sched::nt_object::NtHandle::from_raw(request.handle);
    let Some(object) = table.get(native, IO_COMPLETION_MODIFY_STATE) else { return if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }; };
    let Some(port) = object.completion() else { return STATUS_INVALID_HANDLE; };
    port.post(sched::nt_object::NtCompletionPacket { key: request.key, overlapped: request.value,
        status: request.status, information: request.information });
    STATUS_SUCCESS
}

/// Remove one completion packet into the caller's two scalar outputs and its
/// status block. A null timeout waits without a deadline; a timeout of zero
/// polls. The status block carries the status first and the byte count in the
/// pointer-width word after it.
/// # C: O(1) plus the wait
fn remove_io_completion(call: NtCall) -> u64 {
    let request = crate::nt_obj_sig::remove_io_completion([call.args.a0, call.args.a1, call.args.a2, call.args.a3, call.args.a4]);
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || request.key == 0 || request.value == 0 || request.io == 0 { return STATUS_INVALID_PARAMETER; }
    let table = cur.thread_group.nt_handles();
    let native = sched::nt_object::NtHandle::from_raw(request.handle);
    let Some(object) = table.get(native, IO_COMPLETION_MODIFY_STATE) else { return if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }; };
    let Some(port) = object.completion() else { return STATUS_INVALID_HANDLE; };
    let deadline = if request.timeout == 0 { 0 } else {
        let Ok(timeout) = syscall::UserPtr::<i64>::new(request.timeout) else { return STATUS_INVALID_PARAMETER; };
        match crate::nt_dispatch::wait_deadline(Some(timeout)) { Ok(value) => value, Err(status) => return status }
    };
    let packet = if let Some(packet) = port.try_remove() { packet } else {
        // SAFETY: the completion port remains alive through the wait and owns the scheduler wait list used by this predicate.
        let outcome = unsafe { port.wait(deadline, timekeeper::monotonic_ns) };
        if matches!(outcome, sched::WaitOutcome::TimedOut) { return STATUS_TIMEOUT; }
        let Some(packet) = port.try_remove() else { return STATUS_TIMEOUT; };
        packet
    };
    if uaccess::put_user_u64(request.key, packet.key).is_err()
        || uaccess::put_user_u64(request.value, packet.overlapped).is_err()
        || uaccess::put_user_u64(request.io, packet.status as u64).is_err()
        || put_user_u64_at(request.io, 8, packet.information).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn remove_io_completion_ex(call: NtCall) -> u64 {
    const STATUS_USER_APC: u64 = 0x0000_00c0;
    // The count is a `ULONG` frame word and the alertable flag one byte of
    // another; the count is the caller's array capacity, so no cap of this
    // adapter's own may refuse it.
    let request = crate::nt_obj_sig::remove_io_completion_ex([call.args.a0, call.args.a1, call.args.a2,
        call.args.a3, call.args.a4, call.args.a5]);
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || request.info == 0 || request.written == 0 || request.count == 0 { return STATUS_INVALID_PARAMETER; }
    let table = cur.thread_group.nt_handles();
    let native = sched::nt_object::NtHandle::from_raw(request.handle);
    let Some(object) = table.get(native, IO_COMPLETION_MODIFY_STATE) else { return if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }; };
    let Some(port) = object.completion() else { return STATUS_INVALID_HANDLE; };
    let deadline = if request.timeout == 0 { 0 } else {
        let Ok(timeout) = syscall::UserPtr::<i64>::new(request.timeout) else { return STATUS_INVALID_PARAMETER; };
        match crate::nt_dispatch::wait_deadline(Some(timeout)) { Ok(value) => value, Err(status) => return status }
    };
    let mut packets = alloc::vec::Vec::new();
    while packets.len() < request.count as usize {
        if let Some(packet) = port.try_remove() { packets.push(packet); continue; }
        if !packets.is_empty() { break; }
        if request.alertable && cur.nt_apc_queue.request_delivery() { return STATUS_USER_APC; }
        // SAFETY: the completion port remains alive through the wait and owns the scheduler wait list used by this predicate.
        let outcome = unsafe { port.wait(deadline, timekeeper::monotonic_ns) };
        if matches!(outcome, sched::WaitOutcome::TimedOut) { return STATUS_TIMEOUT; }
        if matches!(outcome, sched::WaitOutcome::Interrupted) && request.alertable
            && cur.nt_apc_queue.request_delivery() { return STATUS_USER_APC; }
        let Some(packet) = port.try_remove() else { return STATUS_TIMEOUT; };
        packets.push(packet);
    }
    for (index, packet) in packets.iter().enumerate() {
        let Some(base) = request.info.checked_add(index as u64 * 32) else { return STATUS_INVALID_PARAMETER; };
        if uaccess::put_user_u64(base, packet.key).is_err()
            || put_user_u64_at(base, 8, packet.overlapped).is_err()
            || put_user_u64_at(base, 16, packet.status as u64).is_err()
            || put_user_u64_at(base, 24, packet.information).is_err() { return STATUS_INVALID_PARAMETER; }
    }
    if uaccess::put_user_u32(request.written, packets.len() as u32).is_err() { return STATUS_INVALID_PARAMETER; }
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

fn put_user_u64_at(address: u64, offset: u64, value: u64) -> Result<(), ()> {
    let address = address.checked_add(offset).ok_or(())?;
    uaccess::put_user_u64(address, value).map_err(|_| ())
}
