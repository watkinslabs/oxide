//! Process-local Windows DLL-directory state.

#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use syscall::nt::{NtCall, NtService};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_BUFFER_TOO_SMALL: u64 = 0xc000_0023;
const UNICODE_STRING_BYTES: usize = 16;

pub fn dispatch(call: NtCall) -> Option<u64> {
    match call.service {
        NtService::RtlAcquirePebLock => Some(acquire_peb_lock()),
        NtService::RtlReleasePebLock => Some(release_peb_lock()),
        NtService::LdrGetDllDirectory => Some(get(call.args.a0)),
        NtService::LdrSetDllDirectory => Some(set(call.args.a0)),
        _ => None,
    }
}

fn acquire_peb_lock() -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || cur.tid == 0 { return STATUS_INVALID_PARAMETER; }
    let outcome = unsafe { cur.thread_group.nt_peb_lock.wait(cur.tid as u64, 0, timekeeper::monotonic_ns) };
    if outcome == sched::WaitOutcome::Ready { STATUS_SUCCESS } else { STATUS_INVALID_PARAMETER }
}

fn release_peb_lock() -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || cur.tid == 0 { return STATUS_INVALID_PARAMETER; }
    if cur.thread_group.nt_peb_lock.release(cur.tid as u64).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn get(descriptor: u64) -> u64 {
    if descriptor == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let mut raw = [0u8; UNICODE_STRING_BYTES];
    if uaccess::copy_from_user(&mut raw, descriptor).is_err() { return STATUS_INVALID_PARAMETER; }
    let maximum = u16::from_le_bytes([raw[2], raw[3]]) as usize;
    let buffer = u64::from_le_bytes(raw[8..16].try_into().unwrap());
    let value = cur.thread_group.nt_dll_directory.lock().clone();
    let required = value.len().saturating_add(2);
    if required > u16::MAX as usize { return STATUS_INVALID_PARAMETER; }
    if uaccess::copy_to_user(descriptor, &(required as u16).to_le_bytes()).is_err() { return STATUS_INVALID_PARAMETER; }
    if maximum < required {
        if maximum >= 2 && buffer != 0 { let _ = uaccess::copy_to_user(buffer, &[0, 0]); }
        return STATUS_BUFFER_TOO_SMALL;
    }
    if buffer == 0 { return STATUS_INVALID_PARAMETER; }
    let mut output = value;
    output.extend_from_slice(&[0, 0]);
    if uaccess::copy_to_user(buffer, &output).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn set(descriptor: u64) -> u64 {
    if descriptor == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let mut raw = [0u8; UNICODE_STRING_BYTES];
    if uaccess::copy_from_user(&mut raw, descriptor).is_err() { return STATUS_INVALID_PARAMETER; }
    let length = u16::from_le_bytes([raw[0], raw[1]]) as usize;
    let maximum = u16::from_le_bytes([raw[2], raw[3]]) as usize;
    let buffer = u64::from_le_bytes(raw[8..16].try_into().unwrap());
    if length > maximum || length & 1 != 0 || length != 0 && buffer == 0 { return STATUS_INVALID_PARAMETER; }
    let mut value = Vec::with_capacity(length);
    if length != 0 {
        value.resize(length, 0);
        if uaccess::copy_from_user(&mut value, buffer).is_err() { return STATUS_INVALID_PARAMETER; }
    }
    *cur.thread_group.nt_dll_directory.lock() = value;
    STATUS_SUCCESS
}
