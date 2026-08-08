use super::*;
use std::sync::{Mutex, MutexGuard};

/// The registry is process-wide state, so the scenarios that attach
/// programs take turns.
static SERIAL: Mutex<()> = Mutex::new(());

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
    fn attach(&mut self, insns: Vec<u8>) -> u64 {
        let prog = crate::bpf::make_bpf_prog_inode(crate::bpf::uapi::prog_type::LSM, insns);
        let id = register(Hook::FileOpen, prog.clone());
        self.pinned.push(prog);
        self.links.push(id);
        id
    }
}

impl Drop for Lane {
    fn drop(&mut self) { ATTACHED.lock().clear(); }
}

const OP_MOV64_IMM: u8 = 0xb7;
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

const EPERM: i64 = -1;
const EACCES: i64 = -13;

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
