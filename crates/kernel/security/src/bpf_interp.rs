//! eBPF interpreter — core subset.
//!
//! Walks verified insns from `bpf_verify` against an 11-register
//! file (R0..R10, R10 is the read-only frame pointer in Linux —
//! v1 leaves it zero) and a 512-byte stack. Programs return R0.
//!
//! Opcode coverage (imm + reg variants):
//!
//!   ALU64 / ALU (32-bit, zero-extends): MOV ADD SUB MUL DIV MOD OR AND
//!          XOR LSH RSH ARSH NEG (DIV/MOD unsigned; /0→0, %0→dst)
//!   JMP / JMP32 (compares low 32): JA JEQ JNE JSET JGT JGE JLT JLE
//!          JSGT JSGE JSLT JSLE, EXIT
//!   LDX:   load size B/H/W/DW from [src+off] — the 512-byte stack
//!          (R10-relative) or the read-only ctx (R1/pkt)
//!   STX / ST: store reg / imm size B/H/W/DW to the writable stack
//!   LD:    LD_IMM_DW (the 16-byte wide load — slot count 2)
//!   CALL:  helper dispatch (R1..R5 → helper, R0 = result)
//!
//! Programs hitting any other opcode return None so callers see
//! "unsupported" distinct from "ran and returned". Map-pointer helper
//! args + the full verifier breadth ride follow-ups.
//!
//! Step budget is 1M dispatches per call (Linux's `BPF_COMPLEXITY_
//! LIMIT_INSNS` is also 1M); exceed it and we bail with None.

extern crate alloc;

pub const NUM_REGS: usize = 11;
pub const STACK_BYTES: usize = 512;
pub const STEP_BUDGET: u32 = 1_000_000;

const BPF_CLASS_MASK: u8 = 0x07;
const BPF_ALU64: u8 = 0x07;
const BPF_JMP:   u8 = 0x05;
const BPF_LD:    u8 = 0x00;
const BPF_LDX:   u8 = 0x01;

// BPF_LDX | BPF_MEM | <size>

const BPF_CALL: u8 = 0x85;

/// Helper-call descriptor: a (helper-id, fn) pair. The interpreter
/// hands R1..R5 to `f` and stores its return in R0. Helpers live
/// outside the interpreter so the kernel can plug in ones that
/// touch sched/time/per-cpu state without dragging those deps
/// into the bpf crate.
pub type HelperFn = fn(i64, i64, i64, i64, i64) -> i64;
pub struct Helper { pub id: u32, pub f: HelperFn }

/// Context register. Linux passes the program's context (skb /
/// xdp_md / etc.) in R1 on entry. v1 models that as "R1 is an
/// offset into `pkt`"; any other src reg on a LDX is rejected.

const BPF_SRC_X: u8 = 0x08; // bit 3 — 0=use imm, 1=use src reg

const BPF_LD_IMM_DW: u8 = 0x18;

// ALU op (bits 4..7), shared by BPF_ALU64 (0x07) and BPF_ALU 32-bit (0x04).
const BPF_OP_ADD:  u8 = 0x00;
const BPF_OP_SUB:  u8 = 0x10;
const BPF_OP_MUL:  u8 = 0x20;
const BPF_OP_DIV:  u8 = 0x30;
const BPF_OP_OR:   u8 = 0x40;
const BPF_OP_AND:  u8 = 0x50;
const BPF_OP_LSH:  u8 = 0x60;
const BPF_OP_RSH:  u8 = 0x70;
const BPF_OP_NEG:  u8 = 0x80;
const BPF_OP_MOD:  u8 = 0x90;
const BPF_OP_XOR:  u8 = 0xa0;
const BPF_OP_MOV:  u8 = 0xb0;
const BPF_OP_ARSH: u8 = 0xc0;

// JMP op (bits 4..7), shared by BPF_JMP (0x05) and BPF_JMP32 (0x06).
const BPF_OP_JA:   u8 = 0x00;
const BPF_OP_JEQ:  u8 = 0x10;
const BPF_OP_JGT:  u8 = 0x20;
const BPF_OP_JGE:  u8 = 0x30;
const BPF_OP_JSET: u8 = 0x40;
const BPF_OP_JNE:  u8 = 0x50;
const BPF_OP_JSGT: u8 = 0x60;
const BPF_OP_JSGE: u8 = 0x70;
const BPF_OP_JLT:  u8 = 0xa0;
const BPF_OP_JLE:  u8 = 0xb0;
const BPF_OP_JSLT: u8 = 0xc0;
const BPF_OP_JSLE: u8 = 0xd0;
const BPF_OP_EXIT_RAW: u8 = 0x90; // opcode = JMP | EXIT_op = 0x05 | 0x90 = 0x95

const BPF_ALU:   u8 = 0x04; // 32-bit ALU class
const BPF_JMP32: u8 = 0x06; // 32-bit JMP class
const BPF_ST:    u8 = 0x02; // store immediate to memory
const BPF_STX:   u8 = 0x03; // store register to memory

/// 512-byte BPF stack mapped at a distinct high address range so memory ops
/// route to it vs the read-only ctx (pkt). R10 = STACK_BASE + STACK_SIZE.
const STACK_SIZE: usize = 512;

/// Access size of a MEM opcode (bits 3..4): W=4, H=2, B=1, DW=8.
fn mem_size(opcode: u8) -> Option<usize> {
    if opcode & 0xe0 != 0x60 { return None; } // must be BPF_MEM mode
    Some(match (opcode >> 3) & 0x03 { 0 => 4, 1 => 2, 2 => 1, 3 => 8, _ => return None })
}

/// Read `size` bytes from a BPF address — the stack or the read-only ctx
/// (pkt) — zero-extended to i64. None on OOB. # C: O(size)
fn mem_read(addr: i64, size: usize, stack: &[u8], pkt: &[u8]) -> Option<i64> {
    let a = addr as u64;
    let (buf, off): (&[u8], usize) = if a >= crate::bpf_layout::STACK_BASE && a < crate::bpf_layout::STACK_BASE + STACK_SIZE as u64 {
        (stack, (a - crate::bpf_layout::STACK_BASE) as usize)
    } else {
        (pkt, usize::try_from(addr).ok()?)
    };
    if off.checked_add(size)? > buf.len() { return None; }
    Some(match size {
        1 => buf[off] as i64,
        2 => u16::from_le_bytes([buf[off], buf[off + 1]]) as i64,
        4 => u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) as i64,
        8 => u64::from_le_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3],
                                 buf[off+4], buf[off+5], buf[off+6], buf[off+7]]) as i64,
        _ => return None,
    })
}

/// Write `size` bytes of `val` to a BPF stack address. Only the stack is
/// writable — a store to ctx is rejected. None on OOB. # C: O(size)
fn mem_write(addr: i64, size: usize, val: i64, stack: &mut [u8]) -> Option<()> {
    let a = addr as u64;
    if a < crate::bpf_layout::STACK_BASE || a >= crate::bpf_layout::STACK_BASE + STACK_SIZE as u64 { return None; }
    let off = (a - crate::bpf_layout::STACK_BASE) as usize;
    if off.checked_add(size)? > stack.len() { return None; }
    let v = val as u64;
    for k in 0..size { stack[off + k] = (v >> (k * 8)) as u8; }
    Some(())
}

/// Apply an ALU op. `is64` false → 32-bit (operate on low 32, zero-extend).
/// DIV/MOD are UNSIGNED (eBPF); div-by-0 → 0, mod-by-0 → dst (Linux). NEG is
/// unary. # C: O(1)
fn alu(op: u8, dst: i64, rhs: i64, is64: bool) -> Option<i64> {
    if is64 {
        let (a, b) = (dst, rhs);
        let r = match op {
            BPF_OP_ADD => a.wrapping_add(b),
            BPF_OP_SUB => a.wrapping_sub(b),
            BPF_OP_MUL => a.wrapping_mul(b),
            BPF_OP_DIV => if b == 0 { 0 } else { ((a as u64) / (b as u64)) as i64 },
            BPF_OP_MOD => if b == 0 { a } else { ((a as u64) % (b as u64)) as i64 },
            BPF_OP_OR  => a | b,
            BPF_OP_AND => a & b,
            BPF_OP_XOR => a ^ b,
            BPF_OP_LSH => ((a as u64) << ((b as u64) & 63)) as i64,
            BPF_OP_RSH => ((a as u64) >> ((b as u64) & 63)) as i64,
            BPF_OP_ARSH => a >> ((b as u64) & 63),
            BPF_OP_NEG => a.wrapping_neg(),
            BPF_OP_MOV => b,
            _ => return None,
        };
        Some(r)
    } else {
        let (a, b) = (dst as u32, rhs as u32);
        let r: u32 = match op {
            BPF_OP_ADD => a.wrapping_add(b),
            BPF_OP_SUB => a.wrapping_sub(b),
            BPF_OP_MUL => a.wrapping_mul(b),
            BPF_OP_DIV => if b == 0 { 0 } else { a / b },
            BPF_OP_MOD => if b == 0 { a } else { a % b },
            BPF_OP_OR  => a | b,
            BPF_OP_AND => a & b,
            BPF_OP_XOR => a ^ b,
            BPF_OP_LSH => a << (b & 31),
            BPF_OP_RSH => a >> (b & 31),
            BPF_OP_ARSH => ((a as i32) >> (b & 31)) as u32,
            BPF_OP_NEG => a.wrapping_neg(),
            BPF_OP_MOV => b,
            _ => return None,
        };
        Some(r as i64) // 32-bit results are zero-extended to 64
    }
}

/// Evaluate a conditional-jump predicate. `is64` false → compare low 32 bits.
/// # C: O(1)
fn jmp_take(op: u8, lhs: i64, rhs: i64, is64: bool) -> Option<bool> {
    let take = if is64 {
        let (lu, ru) = (lhs as u64, rhs as u64);
        match op {
            BPF_OP_JA   => true,
            BPF_OP_JEQ  => lhs == rhs,
            BPF_OP_JNE  => lhs != rhs,
            BPF_OP_JSET => (lhs & rhs) != 0,
            BPF_OP_JGT  => lu > ru,
            BPF_OP_JGE  => lu >= ru,
            BPF_OP_JLT  => lu < ru,
            BPF_OP_JLE  => lu <= ru,
            BPF_OP_JSGT => lhs > rhs,
            BPF_OP_JSGE => lhs >= rhs,
            BPF_OP_JSLT => lhs < rhs,
            BPF_OP_JSLE => lhs <= rhs,
            _ => return None,
        }
    } else {
        let (ls, rs) = (lhs as i32, rhs as i32);
        let (lu, ru) = (lhs as u32, rhs as u32);
        match op {
            BPF_OP_JA   => true,
            BPF_OP_JEQ  => lu == ru,
            BPF_OP_JNE  => lu != ru,
            BPF_OP_JSET => (lu & ru) != 0,
            BPF_OP_JGT  => lu > ru,
            BPF_OP_JGE  => lu >= ru,
            BPF_OP_JLT  => lu < ru,
            BPF_OP_JLE  => lu <= ru,
            BPF_OP_JSGT => ls > rs,
            BPF_OP_JSGE => ls >= rs,
            BPF_OP_JSLT => ls < rs,
            BPF_OP_JSLE => ls <= rs,
            _ => return None,
        }
    };
    Some(take)
}

#[derive(Copy, Clone)]
struct Insn { opcode: u8, dst: u8, src: u8, off: i16, imm: i32 }

fn decode(bytes: &[u8]) -> Insn {
    Insn {
        opcode: bytes[0],
        dst:    bytes[1] & 0x0f,
        src:    (bytes[1] >> 4) & 0x0f,
        off:    i16::from_le_bytes([bytes[2], bytes[3]]),
        imm:    i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
    }
}

/// Run an eBPF program. Returns `Some(r0)` on EXIT, `None` on
/// unsupported opcode, step-budget exhaustion, out-of-bounds pc,
/// or an out-of-bounds packet load. R1 is initialized to 0 and
/// LDX_MEM with src=R1 reads pkt[r1+off..r1+off+size] (bounds-
/// checked). LDX with any other src reg is rejected — v1 doesn't
/// track reg types, so we can't tell a packet pointer from a
/// scalar otherwise.
/// # C: O(insn count × step budget)
pub fn run(insns: &[u8], pkt: &[u8]) -> Option<i64> {
    run_with_helpers(insns, pkt, &[])
}

/// Variant of `run` that admits helper-call dispatch. Programs
/// that issue BPF_CALL with an unknown helper id return None.
/// # C: O(insn count × step budget)
pub fn run_with_helpers(insns: &[u8], pkt: &[u8], helpers: &[Helper]) -> Option<i64> {
    if insns.is_empty() || insns.len() % 8 != 0 { return None; }
    let n = insns.len() / 8;

    let mut regs = [0i64; NUM_REGS];
    // R10 = frame pointer at the TOP of a 512-byte stack (Linux: programs
    // address locals as [R10 + negative off]). The stack lives in a distinct
    // high address range so mem ops route to it vs the read-only ctx (pkt).
    let mut stack = [0u8; STACK_SIZE];
    regs[10] = (crate::bpf_layout::STACK_BASE + STACK_SIZE as u64) as i64;
    let mut pc: usize = 0;
    let mut budget = STEP_BUDGET;

    while pc < n {
        if budget == 0 { return None; }
        budget -= 1;
        let i = decode(&insns[pc * 8 .. pc * 8 + 8]);
        // Opcode dispatch on (class, op, src). EXIT is special
        // because it's not class-derived sensibly via tables.
        if i.opcode == 0x95 {
            return Some(regs[0]);
        }
        if i.opcode == BPF_CALL {
            let id = i.imm as u32;
            let h = helpers.iter().find(|h| h.id == id)?;
            regs[0] = (h.f)(regs[1], regs[2], regs[3], regs[4], regs[5]);
            pc += 1;
            continue;
        }
        let class = i.opcode & BPF_CLASS_MASK;
        match class {
            BPF_ALU64 | BPF_ALU => {
                let is64 = class == BPF_ALU64;
                let op  = i.opcode & 0xf0;
                let src_is_reg = (i.opcode & BPF_SRC_X) != 0;
                let dst = i.dst as usize;
                // NEG is unary (no source operand); others take imm or src reg.
                let rhs: i64 = if op == BPF_OP_NEG { 0 }
                               else if src_is_reg { regs[i.src as usize] }
                               else { i.imm as i64 };
                regs[dst] = alu(op, regs[dst], rhs, is64)?;
                pc += 1;
            }
            BPF_JMP | BPF_JMP32 => {
                let op = i.opcode & 0xf0;
                if op == BPF_OP_EXIT_RAW { return Some(regs[0]); } // double-guard
                let is64 = class == BPF_JMP;
                let src_is_reg = (i.opcode & BPF_SRC_X) != 0;
                let lhs = regs[i.dst as usize];
                let rhs: i64 = if src_is_reg { regs[i.src as usize] } else { i.imm as i64 };
                if jmp_take(op, lhs, rhs, is64)? {
                    let tgt = (pc as i64) + 1 + i.off as i64;
                    if tgt < 0 || tgt >= n as i64 { return None; }
                    pc = tgt as usize;
                } else {
                    pc += 1;
                }
            }
            BPF_LDX => {
                // Load size bytes from [src_reg + off] — stack (R10-relative)
                // or read-only ctx (R1/pkt) per the address range.
                let size = mem_size(i.opcode)?;
                let addr = regs[i.src as usize].wrapping_add(i.off as i64);
                regs[i.dst as usize] = mem_read(addr, size, &stack, pkt)?;
                pc += 1;
            }
            BPF_STX => {
                // Store src_reg to [dst_reg + off] (writable stack only).
                let size = mem_size(i.opcode)?;
                let addr = regs[i.dst as usize].wrapping_add(i.off as i64);
                mem_write(addr, size, regs[i.src as usize], &mut stack)?;
                pc += 1;
            }
            BPF_ST => {
                // Store imm to [dst_reg + off] (writable stack only).
                let size = mem_size(i.opcode)?;
                let addr = regs[i.dst as usize].wrapping_add(i.off as i64);
                mem_write(addr, size, i.imm as i64, &mut stack)?;
                pc += 1;
            }
            BPF_LD => {
                if i.opcode != BPF_LD_IMM_DW { return None; }
                if pc + 1 >= n { return None; }
                let nxt = decode(&insns[(pc + 1) * 8 .. (pc + 2) * 8]);
                let lo = i.imm as u32 as u64;
                let hi = nxt.imm as u32 as u64;
                regs[i.dst as usize] = ((hi << 32) | lo) as i64;
                pc += 2;
            }
            _ => return None,
        }
    }
    // Fell off the end without EXIT — verifier should have caught
    // this, but the interpreter refuses to assume.
    None
}

#[cfg(test)]
#[path = "bpf_interp_tests.rs"]
mod tests;
