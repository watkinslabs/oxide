//! Small native NT power-information adapter.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtService};
use core::sync::atomic::{AtomicU32, Ordering};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_BUFFER_TOO_SMALL: u64 = 0xc000_0023;
const SYSTEM_EXECUTION_STATE: u32 = 16;
const ES_SYSTEM_REQUIRED: u32 = 1;
const ES_DISPLAY_REQUIRED: u32 = 2;
const ES_USER_PRESENT: u32 = 4;
const ES_CONTINUOUS: u32 = 0x8000_0000;
static THREAD_EXECUTION_STATE: AtomicU32 = AtomicU32::new(ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED | ES_USER_PRESENT);

/// Handle the compact execution-state query without changing Linux power
/// policy. Other power levels remain owned by the future NT power adapter.
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::SetThreadExecutionState {
        return Some(set_thread_execution_state(call.args.a0 as u32, call.args.a1));
    }
    if call.service != NtService::PowerInformation { return None; }
    Some(power_information(call.args.a0 as u32, call.args.a1, call.args.a2 as u32,
        call.args.a3, call.args.a4 as u32))
}

fn set_thread_execution_state(new_state: u32, old_state: u64) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || old_state == 0 { return STATUS_INVALID_PARAMETER; }
    let previous = THREAD_EXECUTION_STATE.load(Ordering::Acquire);
    if uaccess::put_user_u32(old_state, previous).is_err() { return STATUS_INVALID_PARAMETER; }
    if previous & ES_CONTINUOUS == 0 || new_state & ES_CONTINUOUS != 0 {
        THREAD_EXECUTION_STATE.store(new_state, Ordering::Release);
    }
    STATUS_SUCCESS
}

fn power_information(level: u32, input: u64, input_size: u32, output: u64, output_size: u32) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || level != SYSTEM_EXECUTION_STATE { return STATUS_INVALID_PARAMETER; }
    if input != 0 || input_size != 0 || output == 0 { return STATUS_INVALID_PARAMETER; }
    if output_size < core::mem::size_of::<u32>() as u32 { return STATUS_BUFFER_TOO_SMALL; }
    if uaccess::put_user_u32(output, ES_USER_PRESENT).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}
