//! Keyed-event services: create, open, wait and release.
//!
//! A keyed event holds no state. Both operations block until a caller in the
//! same process names the same key with the opposite operation, so a release
//! with no waiter sleeps exactly as a wait with no releaser does. A null
//! handle names the default rendezvous point every process shares, which is
//! what the runtime's own one-time initialisation uses.

use syscall::nt::NtCall;
#[cfg(target_os = "oxide-kernel")]
use syscall::nt::NtService;

pub const STATUS_SUCCESS: u64 = 0x0000_0000;
pub const STATUS_TIMEOUT: u64 = 0x0000_0102;
pub const STATUS_ALERTED: u64 = 0x0000_0101;
pub const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
pub const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
pub const STATUS_INVALID_PARAMETER_1: u64 = 0xc000_00ef;
pub const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
pub const STATUS_NO_MEMORY: u64 = 0xc000_0017;
pub const STATUS_OBJECT_TYPE_MISMATCH: u64 = 0xc000_0024;
pub const STATUS_OBJECT_NAME_COLLISION: u64 = 0xc000_0035;
pub const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xc000_0034;

/// Wait for a partner on a key.
pub const KEYEDEVENT_WAIT: u32 = 0x0001;
/// Release a partner waiting on a key.
pub const KEYEDEVENT_WAKE: u32 = 0x0002;
/// Standard rights every named object grants together.
pub const STANDARD_RIGHTS_REQUIRED: u32 = 0x000f_0000;
pub const STANDARD_RIGHTS_READ: u32 = 0x0002_0000;
pub const STANDARD_RIGHTS_WRITE: u32 = 0x0002_0000;
pub const STANDARD_RIGHTS_EXECUTE: u32 = 0x0002_0000;
pub const KEYEDEVENT_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | KEYEDEVENT_WAIT | KEYEDEVENT_WAKE;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_EXECUTE: u32 = 0x2000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;

/// Replace the generic bits of a requested access mask with the rights a
/// keyed event grants for each of them. A keyed event grants no wait-object
/// synchronisation right, so a handle to one is never waitable as an object
/// even when every keyed-event right is granted.
/// # C: O(1)
pub fn granted_access(desired: u32) -> u32 {
    let mut access = desired;
    if desired & GENERIC_READ != 0 { access |= STANDARD_RIGHTS_READ | KEYEDEVENT_WAIT; }
    if desired & GENERIC_WRITE != 0 { access |= STANDARD_RIGHTS_WRITE | KEYEDEVENT_WAKE; }
    if desired & GENERIC_EXECUTE != 0 { access |= STANDARD_RIGHTS_EXECUTE; }
    if desired & GENERIC_ALL != 0 { access |= KEYEDEVENT_ALL_ACCESS; }
    access & !(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL)
}

/// The right one keyed-event operation needs. # C: O(1)
pub const fn required_access(release: bool) -> u32 {
    if release { KEYEDEVENT_WAKE } else { KEYEDEVENT_WAIT }
}

/// A key is an address the caller formed, so its low bit is always clear. An
/// odd key is rejected as the first argument, not as a generic parameter.
/// # C: O(1)
pub fn key_status(key: u64) -> Option<u64> {
    if sched::nt_object::key_is_aligned(key) { None } else { Some(STATUS_INVALID_PARAMETER_1) }
}

/// The rendezvous point every process shares, named by a null handle.
#[cfg(any(target_os = "oxide-kernel", test))]
pub static DEFAULT_KEYED_EVENT: sched::nt_object::NtKeyedEvent = sched::nt_object::NtKeyedEvent::new();

/// Dispatch the four keyed-event services. # C: O(1) plus the rendezvous
#[cfg(target_os = "oxide-kernel")]
pub fn dispatch(call: NtCall) -> Option<u64> {
    match call.service {
        NtService::NtCreateKeyedEvent =>
            Some(create(call.args.a0, call.args.a1 as u32, call.args.a2, call.args.a3)),
        NtService::NtOpenKeyedEvent =>
            Some(open(call.args.a0, call.args.a1 as u32, call.args.a2)),
        NtService::NtWaitForKeyedEvent =>
            Some(rendezvous(call.args.a0, call.args.a1, call.args.a3, false)),
        NtService::NtReleaseKeyedEvent =>
            Some(rendezvous(call.args.a0, call.args.a1, call.args.a3, true)),
        _ => None,
    }
}

#[cfg(not(target_os = "oxide-kernel"))]
pub fn dispatch(_call: NtCall) -> Option<u64> { None }

#[cfg(target_os = "oxide-kernel")]
fn create(handle: u64, desired_access: u32, attributes: u64, flags: u64) -> u64 {
    // The published flags argument carries no defined bit; a set bit names a
    // behaviour this service does not implement, so it is refused rather than
    // silently ignored.
    if flags != 0 { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let table = cur.thread_group.nt_handles();
    let access = granted_access(desired_access);
    if attributes != 0 {
        let Some(path) = crate::nt_directory::resolve_object_path(attributes, &table) else { return STATUS_INVALID_PARAMETER; };
        let (object, state) = sched::nt_object::create_keyed_event(&path);
        if state == sched::nt_object::NamedObjectState::TypeMismatch { return STATUS_OBJECT_TYPE_MISMATCH; }
        if state == sched::nt_object::NamedObjectState::ParentMissing { return STATUS_OBJECT_NAME_NOT_FOUND; }
        let Some(native) = table.insert(object, access) else { return STATUS_NO_MEMORY; };
        if uaccess::put_user_u32(handle, native.raw()).is_err() { let _ = table.close(native); return STATUS_INVALID_PARAMETER; }
        return if state == sched::nt_object::NamedObjectState::Existing { STATUS_OBJECT_NAME_COLLISION } else { STATUS_SUCCESS };
    }
    let object = table.new_keyed_event();
    let Some(native) = table.insert(object, access) else { return STATUS_NO_MEMORY; };
    if uaccess::put_user_u32(handle, native.raw()).is_err() { let _ = table.close(native); return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

#[cfg(target_os = "oxide-kernel")]
fn open(handle: u64, desired_access: u32, attributes: u64) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let table = cur.thread_group.nt_handles();
    if attributes == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(path) = crate::nt_directory::resolve_object_path(attributes, &table) else { return STATUS_INVALID_PARAMETER; };
    let Some(object) = sched::nt_object::lookup_object(&path, sched::nt_object::NtObjectType::KeyedEvent) else {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    };
    let Some(native) = table.insert(object, granted_access(desired_access)) else { return STATUS_NO_MEMORY; };
    if uaccess::put_user_u32(handle, native.raw()).is_err() { let _ = table.close(native); return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

#[cfg(target_os = "oxide-kernel")]
fn rendezvous(handle: u64, key: u64, timeout: u64, release: bool) -> u64 {
    if let Some(status) = key_status(key) { return status; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let event = if handle == 0 { None } else {
        if handle > u32::MAX as u64 { return STATUS_INVALID_HANDLE; }
        let table = cur.thread_group.nt_handles();
        let native = sched::nt_object::NtHandle::from_raw(handle as u32);
        let Some(object) = table.get(native, required_access(release)) else {
            return if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE };
        };
        if object.kind() != sched::nt_object::NtObjectType::KeyedEvent { return STATUS_OBJECT_TYPE_MISMATCH; }
        let Some(event) = object.keyed_event() else { return STATUS_INVALID_HANDLE; };
        Some(event)
    };
    let pointer = if timeout == 0 { None } else {
        match syscall::UserPtr::<i64>::new(timeout) { Ok(pointer) => Some(pointer), Err(_) => return STATUS_INVALID_PARAMETER }
    };
    let deadline = match crate::nt_dispatch::wait_deadline(pointer) { Ok(deadline) => deadline, Err(status) => return status };
    let process = cur.tgid.load(core::sync::atomic::Ordering::Acquire);
    // SAFETY: process context on a rendezvous point retained by this handle
    // or by the shared default, holding no lock a partner needs to pair.
    let outcome = unsafe {
        match event.as_deref() {
            Some(event) => event.rendezvous(process, key, release, deadline, timekeeper::monotonic_ns),
            None => DEFAULT_KEYED_EVENT.rendezvous(process, key, release, deadline, timekeeper::monotonic_ns),
        }
    };
    match outcome {
        sched::nt_object::KeyedOutcome::Paired => STATUS_SUCCESS,
        sched::nt_object::KeyedOutcome::TimedOut => STATUS_TIMEOUT,
        sched::nt_object::KeyedOutcome::Interrupted => STATUS_ALERTED,
    }
}

#[cfg(test)]
#[path = "nt_keyed_event/tests.rs"]
mod tests;
