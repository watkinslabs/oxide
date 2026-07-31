// Classic-BPF interpreter for seccomp filters. No JIT.
//
// Programs reaching here have passed `verifier::check_seccomp_filter`, which
// is Linux's `bpf_check_classic` + `seccomp_check_filter` pair: every opcode
// is whitelisted, every jump lands inside the program, every scratch index is
// < BPF_MEMWORDS, every `BPF_LD|W|ABS` offset is 4-byte aligned and inside
// `struct seccomp_data`, and the last instruction is a RET. The defensive
// arms below therefore describe "impossible" states, and every one of them
// returns `SECCOMP_RET_KILL_PROCESS` — `seccomp_run_filters`' own comment,
// "Ensure unexpected behavior doesn't result in failing open".

use super::insn::*;
use super::uapi::*;

/// Run one verified filter program over `data`. Returns the raw 32-bit filter
/// return value (action | 16-bit data).
/// # C: O(I) instructions, bounded by the step budget
pub fn run_filter(prog: &[u64], data: &SeccompData) -> u32 {
    let img = data.bytes();
    let mut a: u32 = 0;
    let mut x: u32 = 0;
    let mut mem = [0u32; BPF_MEMWORDS];
    let n = prog.len();
    let mut pc: usize = 0;
    let mut steps: u32 = 0;
    // Verified programs cannot loop (all jumps are forward and bounded), so
    // this budget only ever fires for a program that skipped verification.
    let max_steps = (n as u32).saturating_mul(4).max(BPF_MAXINSNS as u32);
    while pc < n {
        steps = steps.saturating_add(1);
        if steps > max_steps { return SECCOMP_RET_KILL_PROCESS; }
        let ins = SockFilter::decode(prog[pc]);
        let class = ins.code & BPF_CLASS_MASK;
        let mode  = ins.code & BPF_MODE_MASK;
        let size  = ins.code & BPF_SIZE_MASK;
        let src   = ins.code & BPF_SRC_MASK;
        let op    = ins.code & BPF_OP_MASK;
        match class {
            BPF_LD => match (mode, size) {
                (BPF_ABS, BPF_W) => { a = data_word(&img, ins.k); pc += 1; }
                (BPF_IMM, _)     => { a = ins.k; pc += 1; }
                // `seccomp_check_filter` rewrites `BPF_LD|W|LEN` into
                // `BPF_LD|IMM` with k = sizeof(struct seccomp_data).
                (BPF_LEN, BPF_W) => { a = SECCOMP_DATA_BYTES; pc += 1; }
                (BPF_MEM, _) => {
                    if ins.k as usize >= BPF_MEMWORDS { return SECCOMP_RET_KILL_PROCESS; }
                    a = mem[ins.k as usize]; pc += 1;
                }
                _ => return SECCOMP_RET_KILL_PROCESS,
            },
            BPF_LDX => match (mode, size) {
                (BPF_IMM, _)     => { x = ins.k; pc += 1; }
                (BPF_LEN, BPF_W) => { x = SECCOMP_DATA_BYTES; pc += 1; }
                (BPF_MEM, _) => {
                    if ins.k as usize >= BPF_MEMWORDS { return SECCOMP_RET_KILL_PROCESS; }
                    x = mem[ins.k as usize]; pc += 1;
                }
                _ => return SECCOMP_RET_KILL_PROCESS,
            },
            BPF_ST => {
                if ins.k as usize >= BPF_MEMWORDS { return SECCOMP_RET_KILL_PROCESS; }
                mem[ins.k as usize] = a; pc += 1;
            }
            BPF_STX => {
                if ins.k as usize >= BPF_MEMWORDS { return SECCOMP_RET_KILL_PROCESS; }
                mem[ins.k as usize] = x; pc += 1;
            }
            BPF_ALU => {
                let v = if src == BPF_X { x } else { ins.k };
                a = match op {
                    BPF_ADD => a.wrapping_add(v),
                    BPF_SUB => a.wrapping_sub(v),
                    BPF_MUL => a.wrapping_mul(v),
                    BPF_OR  => a | v,
                    BPF_AND => a & v,
                    BPF_XOR => a ^ v,
                    // `bpf_check_classic` rejects a K-form shift >= 32 at
                    // load; an X-form shift is a runtime value, and Linux's
                    // interpreter masks it (`A <<= X & 31` would be UB in
                    // Rust, so shift-out-of-range yields 0 as the classic
                    // interpreter's `u32 << 32` does on the reference build).
                    BPF_LSH => if v < 32 { a << v } else { 0 },
                    BPF_RSH => if v < 32 { a >> v } else { 0 },
                    // Division/modulo by zero is rejected for the K form at
                    // load; the X form can still be 0 at run time, where
                    // Linux's interpreter yields 0.
                    BPF_DIV => if v == 0 { 0 } else { a / v },
                    BPF_MOD => if v == 0 { 0 } else { a % v },
                    BPF_NEG => 0u32.wrapping_sub(a),
                    _ => return SECCOMP_RET_KILL_PROCESS,
                };
                pc += 1;
            }
            BPF_JMP => {
                if op == BPF_JA {
                    pc = pc.wrapping_add(1).wrapping_add(ins.k as usize);
                } else {
                    let v = if src == BPF_X { x } else { ins.k };
                    let cond = match op {
                        BPF_JEQ  => a == v,
                        BPF_JGT  => a >  v,
                        BPF_JGE  => a >= v,
                        BPF_JSET => (a & v) != 0,
                        _ => return SECCOMP_RET_KILL_PROCESS,
                    };
                    let off = if cond { ins.jt as usize } else { ins.jf as usize };
                    pc = pc.wrapping_add(1).wrapping_add(off);
                }
            }
            // `BPF_RVAL`, not `BPF_SRC`: `BPF_RET|BPF_A` is 0x16 and masking
            // it with 0x08 reads as `BPF_RET|BPF_K`, returning `k` (0) —
            // i.e. `SECCOMP_RET_KILL_THREAD` — instead of the accumulator.
            BPF_RET => return if ins.code & BPF_RVAL_MASK == BPF_A { a } else { ins.k },
            BPF_MISC => match ins.code & BPF_MISCOP_MASK {
                BPF_TAX => { x = a; pc += 1; }
                BPF_TXA => { a = x; pc += 1; }
                _ => return SECCOMP_RET_KILL_PROCESS,
            },
            _ => return SECCOMP_RET_KILL_PROCESS,
        }
    }
    // Verification guarantees the last instruction is a RET, so falling off
    // the end is unreachable for a verified program.
    SECCOMP_RET_KILL_PROCESS
}

/// `seccomp_run_filters` — evaluate the whole chain and keep the LEAST
/// permissive return. The comparison is on `SECCOMP_RET_ACTION_FULL` read as
/// a SIGNED 32-bit value, which is the entire reason `SECCOMP_RET_KILL_PROCESS`
/// (0x80000000, i.e. negative) outranks every other action.
///
/// Starts at `SECCOMP_RET_ALLOW` exactly like Linux, and an EMPTY chain can
/// never reach here — `check` returns early on a task with no filters, the
/// way `__secure_computing` only calls `__seccomp_filter` in
/// `SECCOMP_MODE_FILTER`.
/// # C: O(F x I)
pub fn run_chain(chain: &[sched::seccomp_filter::SeccompFilter], data: &SeccompData) -> u32 {
    let mut ret = SECCOMP_RET_ALLOW;
    for f in chain.iter() {
        let cur = run_filter(&f.prog, data);
        if ((cur & SECCOMP_RET_ACTION_FULL) as i32) < ((ret & SECCOMP_RET_ACTION_FULL) as i32) {
            ret = cur;
        }
    }
    ret
}
