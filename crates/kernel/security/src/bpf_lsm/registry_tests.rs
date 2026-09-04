use super::*;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Mutex, MutexGuard};

/// The registry is process-wide state, so the scenarios that attach
/// programs take turns.
static SERIAL: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<sched::Task> = AtomicPtr::new(ptr::null_mut());

fn current() -> Option<&'static sched::Task> {
    let task = CURRENT.load(Ordering::Acquire);
    if task.is_null() { None } else {
        // SAFETY: SERIAL pins the task Arc until CURRENT is cleared after the call.
        Some(unsafe { &*task })
    }
}

struct Lane {
    _serial: MutexGuard<'static, ()>,
    links: Vec<u64>,
    pinned: Vec<InodeRef>,
}

impl Lane {
    fn new() -> Self {
        let serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        ATTACHED.lock().clear();
        Self { _serial: serial, links: Vec::new(), pinned: Vec::new() }
    }
    fn attach_to(&mut self, hook: Hook, insns: Vec<u8>) -> u64 {
        let prog = crate::bpf::make_bpf_prog_inode(crate::bpf::uapi::prog_type::LSM, insns);
        let id = register(hook, prog.clone()).expect("attach test BPF LSM program");
        self.pinned.push(prog);
        self.links.push(id);
        id
    }
    fn attach(&mut self, insns: Vec<u8>) -> u64 {
        self.attach_to(Hook::FileOpen, insns)
    }
}

impl Drop for Lane {
    fn drop(&mut self) { ATTACHED.lock().clear(); }
}

const OP_MOV64_IMM: u8 = 0xb7;
const OP_LDX_MEM_W: u8 = 0x61;
const OP_LDX_MEM_DW: u8 = 0x79;
const OP_EXIT: u8 = 0x95;
/// An opcode class the runner does not implement, so the program cannot
/// produce an answer of its own.
const OP_UNRUNNABLE: u8 = 0x20;

fn insn(opcode: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[0] = opcode;
    out[1] = dst & 0x0f | src << 4;
    out[2..4].copy_from_slice(&off.to_le_bytes());
    out[4..8].copy_from_slice(&imm.to_le_bytes());
    out
}

fn program(insns: &[[u8; 8]]) -> Vec<u8> {
    insns.iter().flatten().copied().collect()
}

/// Exits with a constant.
fn returns(value: i32) -> Vec<u8> {
    program(&[insn(OP_MOV64_IMM, 0, 0, 0, value), insn(OP_EXIT, 0, 0, 0, 0)])
}

/// Exits with the context slot at `off`.
fn returns_context_slot(off: i16) -> Vec<u8> {
    program(&[insn(OP_LDX_MEM_DW, 0, 1, off, 0), insn(OP_EXIT, 0, 0, 0, 0)])
}

/// Cannot be executed by the runner at all.
fn unrunnable() -> Vec<u8> {
    program(&[insn(OP_UNRUNNABLE, 0, 0, 0, 0), insn(OP_EXIT, 0, 0, 0, 0)])
}

const EPERM: i64 = -(syscall::errno::Errno::Eperm as i32 as i64);
const EACCES: i64 = -(syscall::errno::Errno::Eacces as i32 as i64);
const EBUSY: i64 = -(syscall::errno::Errno::Ebusy as i32 as i64);

fn write_u32(attr: &mut [u8], at: usize, value: u32) {
    attr[at..at + 4].copy_from_slice(&value.to_ne_bytes());
}

fn write_u64(attr: &mut [u8], at: usize, value: u64) {
    attr[at..at + 8].copy_from_slice(&value.to_ne_bytes());
}

fn no_perf(_: &InodeRef) -> bool { false }
fn no_prog(_: &InodeRef) -> Option<InodeRef> { None }
fn no_trace(_: &[u8], _: u64, _: InodeRef, _: u64) -> Result<&'static str, syscall::errno::Errno> {
    Err(syscall::errno::Errno::Enoent)
}
fn no_detach(_: &str, _: u64) {}

fn bpf_call(cmd: u32, attr: &mut [u8]) -> i64 {
    let args = syscall::SyscallArgs {
        a0: cmd as u64, a1: attr.as_mut_ptr() as u64, a2: attr.len() as u64,
        a3: 0, a4: 0, a5: 0,
    };
    crate::bpf::sys_bpf(&args, crate::bpf::PerfHooks {
        is_perf: no_perf, attached_prog: no_prog,
    }, crate::bpf::RawTracepointHooks { attach: no_trace, detach: no_detach })
}

#[test] fn an_empty_chain_allows() {
    let _lane = Lane::new();
    assert_eq!(run(Hook::FileOpen, &[0]), 0);
}

#[test] fn an_all_zero_chain_allows() {
    let mut lane = Lane::new();
    lane.attach(returns(0));
    lane.attach(returns(0));
    assert_eq!(run(Hook::FileOpen, &[0]), 0);
}

#[test] fn a_single_refusal_becomes_the_answer() {
    let mut lane = Lane::new();
    lane.attach(returns(EACCES as i32));
    assert_eq!(run(Hook::FileOpen, &[0]), EACCES);
}

#[test] fn the_newest_program_runs_first() {
    let mut lane = Lane::new();
    lane.attach(returns(EPERM as i32));
    lane.attach(returns(EACCES as i32));
    assert_eq!(run(Hook::FileOpen, &[0]), EACCES);
    drop(lane);

    // Control for the ordering claim: attaching the same two programs the
    // other way round must produce the other answer. An oldest-first or
    // an order-insensitive chain fails one of these two.
    let mut lane = Lane::new();
    lane.attach(returns(EACCES as i32));
    lane.attach(returns(EPERM as i32));
    assert_eq!(run(Hook::FileOpen, &[0]), EPERM);
}

#[test] fn the_first_non_zero_answer_ends_the_chain() {
    let mut lane = Lane::new();
    // Oldest cannot run at all; reaching it would answer EPERM-by-refusal
    // instead of the newest program's own answer.
    lane.attach(unrunnable());
    lane.attach(returns(EACCES as i32));
    assert_eq!(run(Hook::FileOpen, &[0]), EACCES);
}

#[test] fn a_zero_answer_does_not_end_the_chain() {
    let mut lane = Lane::new();
    lane.attach(returns(EACCES as i32));
    lane.attach(returns(0));
    assert_eq!(run(Hook::FileOpen, &[0]), EACCES);
}

#[test] fn a_program_the_runner_cannot_execute_refuses() {
    let mut lane = Lane::new();
    lane.attach(unrunnable());
    assert_eq!(run(Hook::FileOpen, &[0]), EPERM);
}

#[test] fn arguments_reach_the_context_and_the_return_slot_starts_clear() {
    let mut lane = Lane::new();
    lane.attach(returns_context_slot(0));
    assert_eq!(run(Hook::FileOpen, &[7]), 7);
    drop(lane);

    let mut lane = Lane::new();
    lane.attach(returns_context_slot(SLOT_BYTES as i16));
    assert_eq!(run(Hook::FileOpen, &[7]), 0);
}

#[test]
fn verified_loaded_task_program_reads_task_btf_and_runs_after_builtin_policy() {
    use crate::bpf::uapi;
    use crate::bpf_lsm::task_struct;
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    ATTACHED.lock().clear();
    // SAFETY: SERIAL makes this hosted framework initialization single-threaded.
    unsafe { crate::init().unwrap(); }

    let fdt = Arc::new(vfs::FdTable::new());
    let caller = Arc::new(sched::Task::new(0x7fff_ed01, "bpf-caller",
        sched::SchedClass::Normal { weight: 1024 }));
    // SAFETY: the fixture is unpublished and SERIAL excludes concurrent mutation.
    unsafe { caller.replace_fd_table(Some(Arc::clone(&fdt))); }
    CURRENT.store(Arc::as_ptr(&caller).cast_mut(), Ordering::Release);
    sched::set_current_hook(current);
    let target = sched::Task::new(0x7fff_ed02, "bpf-target",
        sched::SchedClass::Normal { weight: 1024 });
    target.security.creds.cap_permitted.store(1, Ordering::Release);

    let body = program(&[
        insn(OP_LDX_MEM_DW, 2, 1, 0, 0),
        insn(OP_LDX_MEM_W, 3, 2, task_struct::PID as i16, 0),
        insn(0x15, 3, 0, 2, target.tid as i32),
        insn(OP_MOV64_IMM, 0, 0, 0, 0),
        insn(OP_EXIT, 0, 0, 0, 0),
        insn(OP_MOV64_IMM, 0, 0, 0, EACCES as i32),
        insn(OP_EXIT, 0, 0, 0, 0),
    ]);
    let license = b"GPL\0";
    let hook_id = crate::bpf::lsm_hook_btf_id(Hook::TaskSetNice).unwrap();
    let mut load = alloc::vec![0u8; uapi::off::prog_load::LAST_END];
    write_u32(&mut load, uapi::off::prog_load::PROG_TYPE, uapi::prog_type::LSM);
    write_u32(&mut load, uapi::off::prog_load::INSN_CNT, (body.len() / 8) as u32);
    write_u64(&mut load, uapi::off::prog_load::INSNS, body.as_ptr() as u64);
    write_u64(&mut load, uapi::off::prog_load::LICENSE, license.as_ptr() as u64);
    write_u32(&mut load, uapi::off::prog_load::EXPECTED_ATTACH_TYPE,
        uapi::attach_type::LSM_MAC);
    write_u32(&mut load, uapi::off::prog_load::ATTACH_BTF_ID, hook_id);
    let prog_fd = bpf_call(uapi::cmd::PROG_LOAD, &mut load);
    assert!(prog_fd >= 0, "BPF_PROG_LOAD returned {prog_fd}");

    let mut link = alloc::vec![0u8; uapi::off::link_create::LAST_END];
    write_u32(&mut link, uapi::off::link_create::PROG_FD, prog_fd as u32);
    write_u32(&mut link, uapi::off::link_create::ATTACH_TYPE, uapi::attach_type::LSM_MAC);
    let link_fd = bpf_call(uapi::cmd::LINK_CREATE, &mut link);
    assert!(link_fd >= 0, "BPF_LINK_CREATE returned {link_fd}");
    assert_eq!(bpf_call(uapi::cmd::LINK_CREATE, &mut link), EBUSY,
        "one loaded program cannot be linked to its trampoline twice");
    caller.security.creds.cap_effective.store(0, Ordering::Release);
    caller.security.creds.cap_permitted.store(0, Ordering::Release);

    assert_eq!(crate::bpf_lsm::task_setnice_hook(&caller, &target, 7), Err(EACCES),
        "the verified program follows the concrete task pointer and denies its pid");
    let other = sched::Task::new(0x7fff_ed03, "bpf-other-target",
        sched::SchedClass::Normal { weight: 1024 });
    assert_eq!(crate::bpf_lsm::task_setnice_hook(&caller, &other, 7), Ok(()),
        "the verified field read also permits a nonmatching task pid");
    assert_eq!(crate::lsm::task_setnice(&caller, &target, 7), Err(EPERM),
        "the fixed-first capability provider refuses before BPF's later answer");
    fdt.close(link_fd as i32).unwrap();
    assert_eq!(crate::bpf_lsm::task_setnice_hook(&caller, &target, 7), Ok(()),
        "closing the production link detaches the program");
    let relink_fd = bpf_call(uapi::cmd::LINK_CREATE, &mut link);
    assert!(relink_fd >= 0, "detached BPF program must be attachable again: {relink_fd}");
    fdt.close(prog_fd as i32).unwrap();
    assert_eq!(crate::bpf_lsm::task_setnice_hook(&caller, &target, 7), Err(EACCES),
        "the replacement link pins the program after its program fd closes");
    fdt.close(relink_fd as i32).unwrap();
    CURRENT.store(ptr::null_mut(), Ordering::Release);
    ATTACHED.lock().clear();
}

#[test] fn one_hook_obeys_the_linux_trampoline_link_limit() {
    let mut lane = Lane::new();
    for _ in 0..BPF_MAX_TRAMP_LINKS { lane.attach(returns(0)); }
    let extra = crate::bpf::make_bpf_prog_inode(
        crate::bpf::uapi::prog_type::LSM, returns(0));
    assert_eq!(register(Hook::FileOpen, extra), Err(syscall::errno::Errno::E2big));
    assert_eq!(attached_count(Hook::FileOpen), BPF_MAX_TRAMP_LINKS);
}

#[test] fn detaching_removes_exactly_one_program() {
    let mut lane = Lane::new();
    let first = lane.attach(returns(EPERM as i32));
    let second = lane.attach(returns(EACCES as i32));
    assert_ne!(first, second);
    assert_eq!(attached_count(Hook::FileOpen), 2);
    unregister(second);
    assert_eq!(attached_count(Hook::FileOpen), 1);
    assert_eq!(run(Hook::FileOpen, &[0]), EPERM);
    unregister(first);
    assert_eq!(attached_count(Hook::FileOpen), 0);
    assert_eq!(run(Hook::FileOpen, &[0]), 0);
}

#[test] fn detaching_an_unknown_identity_changes_nothing() {
    let mut lane = Lane::new();
    let id = lane.attach(returns(EACCES as i32));
    unregister(id.wrapping_add(1000));
    assert_eq!(attached_count(Hook::FileOpen), 1);
    assert_eq!(run(Hook::FileOpen, &[0]), EACCES);
}
