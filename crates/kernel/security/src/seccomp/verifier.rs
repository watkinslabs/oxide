// cBPF load-time verifier: the generic classic-BPF structural check
// followed by the seccomp-specific filter check, run as a pair for every
// `SECCOMP_SET_MODE_FILTER` install.
//
// UNGATED (`CLAUDE.md` phantom-test rule). An UNVERIFIED filter is itself a
// kernel primitive: without the `BPF_LD|BPF_W|BPF_ABS` bound an attacker
// reads past `struct seccomp_data`, and without the jump bounds a program
// loops or lands off the end.

use alloc::vec::Vec;
use syscall::errno::Errno;

use super::insn::*;
use super::uapi::*;

/// `bpf_check_classic` + `seccomp_check_filter`, in Linux's order. Every
/// failure is EINVAL, matching both.
/// # C: O(I)
pub fn check_seccomp_filter(prog: &[u64]) -> Result<(), Errno> {
    bpf_check_classic(prog)?;
    seccomp_check_filter(prog)
}

/// `bpf_check_classic` — no illegal opcodes, no out-of-range jumps or scratch
/// indexes, no K-form division by zero or shift >= 32, last instruction is a
/// RET, and no read of an uninitialised scratch cell.
/// # C: O(I)
pub fn bpf_check_classic(prog: &[u64]) -> Result<(), Errno> {
    let flen = prog.len();
    if flen == 0 || flen > BPF_MAXINSNS { return Err(Errno::Einval); }
    for pc in 0..flen {
        let i = SockFilter::decode(prog[pc]);
        if !code_allowed(i.code) { return Err(Errno::Einval); }
        match i.code {
            c if c == BPF_ALU | BPF_DIV | BPF_K || c == BPF_ALU | BPF_MOD | BPF_K =>
                if i.k == 0 { return Err(Errno::Einval); },
            c if c == BPF_ALU | BPF_LSH | BPF_K || c == BPF_ALU | BPF_RSH | BPF_K =>
                if i.k >= 32 { return Err(Errno::Einval); },
            c if c == BPF_LD | BPF_MEM || c == BPF_LDX | BPF_MEM
              || c == BPF_ST || c == BPF_STX =>
                if i.k as usize >= BPF_MEMWORDS { return Err(Errno::Einval); },
            c if c == BPF_JMP | BPF_JA => {
                // `k >= flen - pc - 1` is EINVAL: the target must be a real
                // instruction, and `flen - pc - 1` is the count of them left
                // after the jump itself.
                if i.k as usize >= flen - pc - 1 { return Err(Errno::Einval); }
            }
            c if is_cond_jump(c) => {
                if pc + i.jt as usize + 1 >= flen { return Err(Errno::Einval); }
                if pc + i.jf as usize + 1 >= flen { return Err(Errno::Einval); }
            }
            _ => {}
        }
    }
    // Last instruction must be a RET. `bpf_check_classic` returns EINVAL for
    // anything else BEFORE running the scratch-liveness pass.
    let last = SockFilter::decode(prog[flen - 1]).code;
    if last != BPF_RET | BPF_K && last != BPF_RET | BPF_A { return Err(Errno::Einval); }
    check_load_and_stores(prog)
}

/// `seccomp_check_filter` — the seccomp-specific opcode whitelist. Narrower
/// than `chk_code_allowed`: no packet loads, no `BPF_IND`, no `BPF_B`/`BPF_H`
/// sizes, and NO `BPF_MOD` (the socket-filter table permits it; seccomp's
/// does not). Also bounds every `BPF_LD|BPF_W|BPF_ABS` to a 4-byte-aligned
/// offset inside `struct seccomp_data`.
/// # C: O(I)
pub fn seccomp_check_filter(prog: &[u64]) -> Result<(), Errno> {
    for w in prog.iter() {
        let i = SockFilter::decode(*w);
        let c = i.code;
        if c == BPF_LD | BPF_W | BPF_ABS {
            if i.k >= SECCOMP_DATA_BYTES || i.k & 3 != 0 { return Err(Errno::Einval); }
            continue;
        }
        if c == BPF_LD | BPF_W | BPF_LEN || c == BPF_LDX | BPF_W | BPF_LEN { continue; }
        if !seccomp_code_allowed(c) { return Err(Errno::Einval); }
    }
    Ok(())
}

/// `seccomp_check_filter`'s explicit case list, minus the three handled by
/// the caller (`BPF_LD|W|ABS` and the two `BPF_W|BPF_LEN` forms).
fn seccomp_code_allowed(c: u16) -> bool {
    const ALU_OPS: [u16; 9] = [BPF_ADD, BPF_SUB, BPF_MUL, BPF_DIV, BPF_AND, BPF_OR, BPF_XOR, BPF_LSH, BPF_RSH];
    for op in ALU_OPS { if c == BPF_ALU | op | BPF_K || c == BPF_ALU | op | BPF_X { return true; } }
    if c == BPF_ALU | BPF_NEG { return true; }
    if c == BPF_RET | BPF_K || c == BPF_RET | BPF_A { return true; }
    if c == BPF_LD | BPF_IMM || c == BPF_LDX | BPF_IMM { return true; }
    if c == BPF_MISC | BPF_TAX || c == BPF_MISC | BPF_TXA { return true; }
    if c == BPF_LD | BPF_MEM || c == BPF_LDX | BPF_MEM { return true; }
    if c == BPF_ST || c == BPF_STX { return true; }
    if c == BPF_JMP | BPF_JA { return true; }
    is_cond_jump(c)
}

/// `chk_code_allowed`'s table, restricted to the classes a `sock_filter` can
/// legally carry. Packet-relative forms stay listed here because
/// `bpf_check_classic` is shared with socket filters; `seccomp_check_filter`
/// rejects them a moment later.
fn code_allowed(c: u16) -> bool {
    const ALU_OPS: [u16; 10] = [BPF_ADD, BPF_SUB, BPF_MUL, BPF_DIV, BPF_MOD, BPF_AND, BPF_OR, BPF_XOR, BPF_LSH, BPF_RSH];
    for op in ALU_OPS { if c == BPF_ALU | op | BPF_K || c == BPF_ALU | op | BPF_X { return true; } }
    if c == BPF_ALU | BPF_NEG { return true; }
    for sz in [BPF_W, BPF_H, BPF_B] {
        if c == BPF_LD | sz | BPF_ABS || c == BPF_LD | sz | BPF_IND { return true; }
    }
    if c == BPF_LD | BPF_W | BPF_LEN || c == BPF_LDX | BPF_W | BPF_LEN { return true; }
    if c == BPF_LD | BPF_IMM || c == BPF_LDX | BPF_IMM { return true; }
    if c == BPF_LD | BPF_MEM || c == BPF_LDX | BPF_MEM { return true; }
    if c == BPF_LDX | BPF_B | BPF_MSH { return true; }
    if c == BPF_ST || c == BPF_STX { return true; }
    if c == BPF_RET | BPF_K || c == BPF_RET | BPF_A { return true; }
    if c == BPF_JMP | BPF_JA { return true; }
    if c == BPF_MISC | BPF_TAX || c == BPF_MISC | BPF_TXA { return true; }
    is_cond_jump(c)
}

/// `BPF_LDX|BPF_B|BPF_MSH` — packet-relative IP-header-length load. Listed by
/// `chk_code_allowed`, rejected by `seccomp_check_filter`.
const BPF_MSH: u16 = 0xa0;

fn is_cond_jump(c: u16) -> bool {
    for op in [BPF_JEQ, BPF_JGT, BPF_JGE, BPF_JSET] {
        if c == BPF_JMP | op | BPF_K || c == BPF_JMP | op | BPF_X { return true; }
    }
    false
}

/// `check_load_and_stores` — reject a program that can read a scratch cell
/// along a path that never wrote it, so `M[]` cannot leak whatever the
/// interpreter's stack frame happened to hold.
///
/// `masks[pc]` is the set of cells guaranteed live on EVERY path reaching
/// `pc`; a jump intersects the jumper's live set into each target's mask and
/// then resets the fall-through set to "all live" (the next instruction is
/// only reachable through some jump, whose mask already constrains it).
/// # C: O(I)
fn check_load_and_stores(prog: &[u64]) -> Result<(), Errno> {
    let flen = prog.len();
    let mut masks: Vec<u16> = alloc::vec![u16::MAX; flen];
    let mut memvalid: u16 = 0;
    for pc in 0..flen {
        memvalid &= masks[pc];
        let i = SockFilter::decode(prog[pc]);
        let c = i.code;
        if c == BPF_ST || c == BPF_STX {
            memvalid |= 1u16 << (i.k as usize % BPF_MEMWORDS);
        } else if c == BPF_LD | BPF_MEM || c == BPF_LDX | BPF_MEM {
            if memvalid & (1u16 << (i.k as usize % BPF_MEMWORDS)) == 0 { return Err(Errno::Einval); }
        } else if c == BPF_JMP | BPF_JA {
            let t = pc + 1 + i.k as usize;
            if t >= flen { return Err(Errno::Einval); }
            masks[t] &= memvalid;
            memvalid = u16::MAX;
        } else if is_cond_jump(c) {
            let (tt, tf) = (pc + 1 + i.jt as usize, pc + 1 + i.jf as usize);
            if tt >= flen || tf >= flen { return Err(Errno::Einval); }
            masks[tt] &= memvalid;
            masks[tf] &= memvalid;
            memvalid = u16::MAX;
        }
    }
    Ok(())
}
