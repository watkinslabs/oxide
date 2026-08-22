// sys_enter/sys_exit tracefs and raw-BPF consumers. One consumer mask owns
// hook installation and the per-task syscall-work family edge.

use super::*;

fn record_sys_enter(nr: u32, regs: &syscall::SyscallArgs) {
    raw_bpf::fire(&RAW_SYS_ENTER, &[regs as *const syscall::SyscallArgs as u64, nr as u64]);
    if !tracing_on() || !sys_enter_on() { return; }
    let (pid, comm) = cur_task();
    if FILTER_SYS_ENTER.has_filter() {
        let f = [
            ("id",         FieldVal::Int(nr as i64)),
            ("common_pid", FieldVal::Int(pid as i64)),
        ];
        if !FILTER_SYS_ENTER.passes(&EventRecord::new(&f)) { return; }
    }
    let mut pl = [0u8; PAYLOAD];
    pl[..16].copy_from_slice(&comm);
    pl[16..20].copy_from_slice(&nr.to_le_bytes());
    percpu_ring::record(this_cpu(), now_ns(), pid, KIND_SYS_ENTER, &pl[..20]);
}

fn record_sys_exit(nr: u32, ret: i64, regs: &syscall::SyscallArgs) {
    raw_bpf::fire(&RAW_SYS_EXIT, &[regs as *const syscall::SyscallArgs as u64, ret as u64]);
    if !tracing_on() || !sys_exit_on() { return; }
    let (pid, comm) = cur_task();
    if FILTER_SYS_EXIT.has_filter() {
        let f = [
            ("id",         FieldVal::Int(nr as i64)),
            ("ret",        FieldVal::Int(ret)),
            ("common_pid", FieldVal::Int(pid as i64)),
        ];
        if !FILTER_SYS_EXIT.passes(&EventRecord::new(&f)) { return; }
    }
    let mut pl = [0u8; PAYLOAD];
    pl[..16].copy_from_slice(&comm);
    pl[16..20].copy_from_slice(&nr.to_le_bytes());
    pl[20..28].copy_from_slice(&ret.to_le_bytes());
    percpu_ring::record(this_cpu(), now_ns(), pid, KIND_SYS_EXIT, &pl[..28]);
}

const EVENT_ENTER: u8 = 1 << 0;
const EVENT_EXIT: u8 = 1 << 1;
const BPF_ENTER: u8 = 1 << 2;
const BPF_EXIT: u8 = 1 << 3;

pub(crate) static RAW_SYS_ENTER: RawEvent = RawEvent::new(2, 0, set_bpf_sys_enter);
pub(crate) static RAW_SYS_EXIT:  RawEvent = RawEvent::new(2, 0, set_bpf_sys_exit);

static USERS: Spinlock<u8, TracepointClass> = Spinlock::new(0);

fn set_user(bit: u8, hook_mask: u8, on: bool, install: fn(bool)) {
    let mut users = USERS.lock();
    if (*users & bit != 0) == on { return; }
    let family_was_on = *users != 0;
    let hook_was_on = *users & hook_mask != 0;
    if on && !hook_was_on { install(true); }
    if on { *users |= bit; } else { *users &= !bit; }
    let family_is_on = *users != 0;
    if family_was_on != family_is_on {
        sched::syscall_work::set_tracepoint_active(family_is_on);
    }
    if !on && *users & hook_mask == 0 { install(false); }
}

fn install_enter(on: bool) {
    syscall::tracepoint::install_sys_enter_hook(if on { Some(record_sys_enter) } else { None });
}

fn install_exit(on: bool) {
    syscall::tracepoint::install_sys_exit_hook(if on { Some(record_sys_exit) } else { None });
}

pub(crate) fn set_sys_enter(on: bool) {
    set_user(EVENT_ENTER, EVENT_ENTER | BPF_ENTER, on, install_enter);
}

pub(crate) fn set_sys_exit(on: bool) {
    set_user(EVENT_EXIT, EVENT_EXIT | BPF_EXIT, on, install_exit);
}

fn set_bpf_sys_enter(on: bool) {
    set_user(BPF_ENTER, EVENT_ENTER | BPF_ENTER, on, install_enter);
}

fn set_bpf_sys_exit(on: bool) {
    set_user(BPF_EXIT, EVENT_EXIT | BPF_EXIT, on, install_exit);
}

pub(crate) fn sys_enter_on() -> bool { *USERS.lock() & EVENT_ENTER != 0 }
pub(crate) fn sys_exit_on() -> bool { *USERS.lock() & EVENT_EXIT != 0 }
