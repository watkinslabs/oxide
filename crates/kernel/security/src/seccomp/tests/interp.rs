// The cBPF interpreter and `seccomp_run_filters`' chain walk.

use alloc::vec::Vec;
use crate::seccomp::insn::*;
use crate::seccomp::interp::*;
use crate::seccomp::uapi::*;

fn p(insns: &[(u16, u8, u8, u32)]) -> Vec<u64> {
    insns.iter().map(|&(c, jt, jf, k)| SockFilter::new(c, jt, jf, k).encode()).collect()
}
fn data(nr: i32, args: [u64; 6]) -> SeccompData {
    SeccompData { nr, arch: native_audit_arch(), ip: 0xdead_beef_1234_5678, args }
}

#[test]
fn a_filter_reads_nr_arch_ip_and_args_at_their_uapi_offsets() {
    let d = data(60, [0x1111_2222_3333_4444, 0, 0, 0, 0, 0xaaaa_bbbb_cccc_dddd]);
    let ld = |k: u32| run_filter(&p(&[(BPF_LD | BPF_W | BPF_ABS, 0, 0, k), (BPF_RET | BPF_A, 0, 0, 0)]), &d);
    assert_eq!(ld(0),  60);
    assert_eq!(ld(4),  native_audit_arch());
    assert_eq!(ld(8),  0x1234_5678);            // instruction_pointer, low half
    assert_eq!(ld(12), 0xdead_beef);            // instruction_pointer, high half
    assert_eq!(ld(16), 0x3333_4444);            // args[0] low
    assert_eq!(ld(20), 0x1111_2222);            // args[0] high
    assert_eq!(ld(56), 0xcccc_dddd);            // args[5] low
    assert_eq!(ld(60), 0xaaaa_bbbb);            // args[5] high
}

// `instruction_pointer` was hard-coded to 0, so any filter keying on the call
// site saw every syscall come from address 0.
#[test]
fn the_instruction_pointer_is_the_real_user_pc() {
    let d = data(1, [0; 6]);
    let saw_zero = run_filter(&p(&[
        (BPF_LD | BPF_W | BPF_ABS, 0, 0, 8),
        (BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
        (BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
        (BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW),
    ]), &d);
    assert_eq!(saw_zero, SECCOMP_RET_ALLOW);
}

// `BPF_RET|BPF_A` is 0x16. Selecting the return source with `BPF_SRC` (0x08)
// instead of `BPF_RVAL` (0x18) reads it as `BPF_RET|BPF_K` and returns `k` —
// 0, i.e. SECCOMP_RET_KILL_THREAD — instead of the accumulator.
#[test]
fn ret_a_returns_the_accumulator_not_k() {
    let d = data(0, [0; 6]);
    let rv = run_filter(&p(&[
        (BPF_LD | BPF_IMM, 0, 0, SECCOMP_RET_ALLOW),
        (BPF_RET | BPF_A, 0, 0, 0),
    ]), &d);
    assert_eq!(rv, SECCOMP_RET_ALLOW);
    assert_ne!(rv, SECCOMP_RET_KILL_THREAD);
}

#[test]
fn ret_k_returns_k() {
    let d = data(0, [0; 6]);
    assert_eq!(run_filter(&p(&[(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ERRNO | 13)]), &d),
               SECCOMP_RET_ERRNO | 13);
}

#[test]
fn scratch_alu_and_index_transfers_work() {
    let d = data(7, [0; 6]);
    assert_eq!(run_filter(&p(&[
        (BPF_LD | BPF_W | BPF_ABS, 0, 0, 0),     // A = nr = 7
        (BPF_ST, 0, 0, 5),                        // M[5] = 7
        (BPF_LD | BPF_IMM, 0, 0, 3),              // A = 3
        (BPF_MISC | BPF_TAX, 0, 0, 0),            // X = 3
        (BPF_LD | BPF_MEM, 0, 0, 5),              // A = 7
        (BPF_ALU | BPF_MUL | BPF_X, 0, 0, 0),     // A = 21
        (BPF_RET | BPF_A, 0, 0, 0),
    ]), &d), 21);
}

#[test]
fn conditional_jumps_take_the_right_arm() {
    let d = data(60, [0; 6]);
    let prog = p(&[
        (BPF_LD | BPF_W | BPF_ABS, 0, 0, 0),
        (BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 60),
        (BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW),
        (BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
    ]);
    assert_eq!(run_filter(&prog, &d), SECCOMP_RET_ALLOW);
    assert_eq!(run_filter(&prog, &data(61, [0; 6])), SECCOMP_RET_KILL_PROCESS);
}

// "Ensure unexpected behavior doesn't result in failing open": a program the
// verifier would have rejected must never yield ALLOW.
#[test]
fn an_unverified_program_never_fails_open() {
    let d = data(0, [0; 6]);
    // Falls off the end (no trailing RET).
    assert_eq!(run_filter(&p(&[(BPF_LD | BPF_IMM, 0, 0, 1)]), &d), SECCOMP_RET_KILL_PROCESS);
    // Undefined opcode.
    assert_eq!(run_filter(&p(&[(0x0f, 0, 0, 0)]), &d), SECCOMP_RET_KILL_PROCESS);
    // Scratch index out of range.
    assert_eq!(run_filter(&p(&[(BPF_LD | BPF_MEM, 0, 0, 99), (BPF_RET | BPF_A, 0, 0, 0)]), &d),
               SECCOMP_RET_KILL_PROCESS);
    // Jump backwards forever (`k` wraps the pc round).
    assert_eq!(run_filter(&p(&[(BPF_JMP | BPF_JA, 0, 0, u32::MAX), (BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW)]), &d),
               SECCOMP_RET_KILL_PROCESS);
    // An out-of-bounds seccomp_data load reads 0, never kernel memory.
    assert_eq!(run_filter(&p(&[(BPF_LD | BPF_W | BPF_ABS, 0, 0, 0x1000), (BPF_RET | BPF_A, 0, 0, 0)]), &d), 0);
}

// `seccomp_run_filters` keeps the LEAST permissive return across the whole
// chain, and the comparison must be signed so KILL_PROCESS wins.
#[test]
fn the_chain_keeps_the_least_permissive_action() {
    let d = data(0, [0; 6]);
    let ret = |v: u32| p(&[(BPF_RET | BPF_K, 0, 0, v)]);
    let chain = alloc::vec![ret(SECCOMP_RET_ALLOW), ret(SECCOMP_RET_ERRNO | 1), ret(SECCOMP_RET_LOG)];
    assert_eq!(run_chain(&chain, &d), SECCOMP_RET_ERRNO | 1);

    let chain = alloc::vec![ret(SECCOMP_RET_ERRNO | 1), ret(SECCOMP_RET_KILL_PROCESS), ret(SECCOMP_RET_ALLOW)];
    assert_eq!(run_chain(&chain, &d), SECCOMP_RET_KILL_PROCESS);

    // An earlier ALLOW cannot re-open a later TRAP.
    let chain = alloc::vec![ret(SECCOMP_RET_ALLOW), ret(SECCOMP_RET_TRAP | 7)];
    assert_eq!(run_chain(&chain, &d), SECCOMP_RET_TRAP | 7);
}

#[test]
fn an_all_allow_chain_allows() {
    let d = data(0, [0; 6]);
    let chain = alloc::vec![p(&[(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW)]); 3];
    assert_eq!(run_chain(&chain, &d), SECCOMP_RET_ALLOW);
}

#[test]
fn sock_filter_round_trips_through_the_packed_encoding() {
    for f in [SockFilter::new(0x15, 3, 200, 0xdead_beef),
              SockFilter::new(0xffff, 255, 255, u32::MAX),
              SockFilter::new(0, 0, 0, 0)] {
        assert_eq!(SockFilter::decode(f.encode()), f);
    }
}
