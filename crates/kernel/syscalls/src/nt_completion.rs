//! Native NT I/O completion-port operations.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtObjectCall};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const STATUS_TIMEOUT: u64 = 0x0000_0102;
const IO_COMPLETION_ALL_ACCESS: u32 = 0x001f_0003;
const IO_COMPLETION_MODIFY_STATE: u32 = 0x0002;
const SYNCHRONIZE: u32 = 0x0010_0000;

pub fn dispatch(call: NtCall) -> Option<u64> {
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

fn read_u32(address: u64) -> Option<u32> { uaccess::get_user_u32(address).ok() }
fn read_u64(address: u64) -> Option<u64> { uaccess::get_user_u64(address).ok() }
fn read_i64(address: u64) -> Option<i64> { read_u64(address).map(|value| value as i64) }
