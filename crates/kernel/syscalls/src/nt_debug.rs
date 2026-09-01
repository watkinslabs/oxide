//! Native Wine-compatible debug entry points used by the Windows personality.
#![cfg(target_os = "oxide-kernel")]

use syscall::{nt::{NtCall, NtService}, SyscallArgs};

const DEBUG_CLASS_COUNT: u64 = 4;
const DEBUG_INIT_FLAG: u8 = 1 << 7;
const DEFAULT_DEBUG_FLAGS: u8 = (1 << 0) | (1 << 1);

/// Dispatch the debug-header ABI while the per-thread output buffer is added.
/// # C: O(1) plus one user byte read
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::WineDbgStrdup { return Some(strdup(call.args.a0)); }
    if call.service == NtService::WineDbgOutput { return Some(output(call.args.a0)); }
    if call.service != NtService::WineDbgHeader { return None; }
    Some(header(call.args.a0, call.args.a1))
}

fn strdup(string: u64) -> u64 {
    let Some(task) = sched::live::current() else { return 0; };
    let Some(debug) = task.nt_teb().checked_add(elf_load::process_env::NT_DEBUG_INFO_OFFSET) else { return 0; };
    let mut source = alloc::vec::Vec::new();
    for index in 0..1020usize {
        let mut byte = [0u8; 1];
        if string == 0 || uaccess::copy_from_user(&mut byte, string.saturating_add(index as u64)).is_err() { return 0; }
        source.push(byte[0]);
        if byte[0] == 0 { break; }
        if index == 1019 { return 0; }
    }
    if source.last() != Some(&0) { return 0; }
    let position = uaccess::get_user_u32(debug).unwrap_or(0) as usize;
    let start = if position.saturating_add(source.len()) > 1020 { 0 } else { position };
    let Some(destination) = debug.checked_add(8).and_then(|base| base.checked_add(start as u64)) else { return 0; };
    if uaccess::copy_to_user(destination, &source).is_err() { return 0; }
    if uaccess::put_user_u32(debug, start.saturating_add(source.len()) as u32).is_err() { return 0; }
    destination
}

fn output(string: u64) -> u64 {
    if string == 0 { return 0; }
    let mut bytes = alloc::vec::Vec::new();
    for index in 0..4096usize {
        let mut byte = [0u8; 1];
        if uaccess::copy_from_user(&mut byte, string.saturating_add(index as u64)).is_err() { return 0; }
        if byte[0] == 0 { break; }
        bytes.push(byte[0]);
        if index == 4095 { return 0; }
    }
    if bytes.is_empty() { return 0; }
    let result = crate::s001_write::sys_write(&SyscallArgs { a0: 2, a1: string, a2: bytes.len() as u64, a3: 0, a4: 0, a5: 0 });
    if result < 0 { 0 } else { bytes.len() as u64 }
}

fn header(class: u64, channel: u64) -> u64 {
    if class >= DEBUG_CLASS_COUNT || channel == 0 { return (-1i64) as u64; }
    let mut channel_flags = [0u8; 1];
    if uaccess::copy_from_user(&mut channel_flags, channel).is_err() { return (-1i64) as u64; }
    let flags = channel_flags[0];
    let flags = if flags & DEBUG_INIT_FLAG != 0 { DEFAULT_DEBUG_FLAGS } else { flags };
    if flags & (1 << class) == 0 { (-1i64) as u64 } else { 0 }
}
