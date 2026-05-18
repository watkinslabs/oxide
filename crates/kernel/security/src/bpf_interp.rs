//! eBPF interpreter — core subset.
//!
//! Walks verified insns from `bpf_verify` against an 11-register
//! file (R0..R10, R10 is the read-only frame pointer in Linux —
//! v1 leaves it zero) and a 512-byte stack. Programs return R0.
//!
//! v1 opcode set covers what a "load const, do arithmetic, return"
//! program needs:
//!
//!   ALU64: MOV/ADD/SUB/AND/OR/XOR (imm + reg variants)
//!   JMP:   JA, JEQ, JNE (imm variants), EXIT
//!   LD:    LD_IMM_DW (the 16-byte wide load — only opcode whose
//!          slot count is 2)
//!
//! BPF_LDX/STX (packet/map loads) ride F109; helper CALL rides
//! after that. Programs hitting any other opcode return None so
//! callers see "unsupported" distinct from "ran and returned".
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
const BPF_LDX_MEM_B:  u8 = 0x71;
const BPF_LDX_MEM_H:  u8 = 0x69;
const BPF_LDX_MEM_W:  u8 = 0x61;
const BPF_LDX_MEM_DW: u8 = 0x79;

/// Context register. Linux passes the program's context (skb /
/// xdp_md / etc.) in R1 on entry. v1 models that as "R1 is an
/// offset into `pkt`"; any other src reg on a LDX is rejected.
const CTX_REG: u8 = 1;

const BPF_SRC_X: u8 = 0x08; // bit 3 — 0=use imm, 1=use src reg

const BPF_LD_IMM_DW: u8 = 0x18;

const BPF_OP_ADD: u8 = 0x00;
const BPF_OP_SUB: u8 = 0x10;
const BPF_OP_OR:  u8 = 0x40;
const BPF_OP_AND: u8 = 0x50;
const BPF_OP_XOR: u8 = 0xa0;
const BPF_OP_MOV: u8 = 0xb0;

const BPF_OP_JA:  u8 = 0x00;
const BPF_OP_JEQ: u8 = 0x10;
const BPF_OP_JNE: u8 = 0x50;
const BPF_OP_EXIT_RAW: u8 = 0x90; // opcode = JMP | EXIT_op = 0x05 | 0x90 = 0x95

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
    if insns.is_empty() || insns.len() % 8 != 0 { return None; }
    let n = insns.len() / 8;

    let mut regs = [0i64; NUM_REGS];
    // R10 is the frame pointer in Linux; leave it 0 here — we
    // don't admit LDX/STX yet so no one observes it.
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
        let class = i.opcode & BPF_CLASS_MASK;
        match class {
            BPF_ALU64 => {
                let op  = i.opcode & 0xf0;
                let src_is_reg = (i.opcode & BPF_SRC_X) != 0;
                let dst = i.dst as usize;
                let rhs: i64 = if src_is_reg { regs[i.src as usize] } else { i.imm as i64 };
                regs[dst] = match op {
                    BPF_OP_ADD => regs[dst].wrapping_add(rhs),
                    BPF_OP_SUB => regs[dst].wrapping_sub(rhs),
                    BPF_OP_OR  => regs[dst] | rhs,
                    BPF_OP_AND => regs[dst] & rhs,
                    BPF_OP_XOR => regs[dst] ^ rhs,
                    BPF_OP_MOV => rhs,
                    _ => return None,
                };
                pc += 1;
            }
            BPF_JMP => {
                let op = i.opcode & 0xf0;
                let src_is_reg = (i.opcode & BPF_SRC_X) != 0;
                let lhs = regs[i.dst as usize];
                let rhs: i64 = if src_is_reg { regs[i.src as usize] } else { i.imm as i64 };
                let take = match op {
                    BPF_OP_JA  => true,
                    BPF_OP_JEQ => lhs == rhs,
                    BPF_OP_JNE => lhs != rhs,
                    BPF_OP_EXIT_RAW => return Some(regs[0]), // double-guard
                    _ => return None,
                };
                if take {
                    let tgt = (pc as i64) + 1 + i.off as i64;
                    if tgt < 0 || tgt >= n as i64 { return None; }
                    pc = tgt as usize;
                } else {
                    pc += 1;
                }
            }
            BPF_LDX => {
                if i.src != CTX_REG { return None; }
                let base = regs[CTX_REG as usize];
                let off = base.wrapping_add(i.off as i64);
                if off < 0 { return None; }
                let off = off as usize;
                let val: i64 = match i.opcode {
                    BPF_LDX_MEM_B => {
                        if off >= pkt.len() { return None; }
                        pkt[off] as i64
                    }
                    BPF_LDX_MEM_H => {
                        if off + 2 > pkt.len() { return None; }
                        u16::from_le_bytes([pkt[off], pkt[off + 1]]) as i64
                    }
                    BPF_LDX_MEM_W => {
                        if off + 4 > pkt.len() { return None; }
                        u32::from_le_bytes([
                            pkt[off], pkt[off + 1], pkt[off + 2], pkt[off + 3]
                        ]) as i64
                    }
                    BPF_LDX_MEM_DW => {
                        if off + 8 > pkt.len() { return None; }
                        u64::from_le_bytes([
                            pkt[off], pkt[off + 1], pkt[off + 2], pkt[off + 3],
                            pkt[off + 4], pkt[off + 5], pkt[off + 6], pkt[off + 7],
                        ]) as i64
                    }
                    _ => return None,
                };
                regs[i.dst as usize] = val;
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
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn raw(opc: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
        let off_le = off.to_le_bytes();
        let imm_le = imm.to_le_bytes();
        [opc, (src << 4) | (dst & 0x0f), off_le[0], off_le[1],
         imm_le[0], imm_le[1], imm_le[2], imm_le[3]]
    }
    fn cat(parts: &[[u8; 8]]) -> Vec<u8> {
        let mut v = Vec::with_capacity(parts.len() * 8);
        for p in parts { v.extend_from_slice(p); }
        v
    }

    #[test]
    fn mov_imm_then_exit_returns_imm() {
        // MOV64 R0, 42 ; EXIT
        let p = cat(&[
            raw(0xb7, 0, 0, 0, 42),
            raw(0x95, 0, 0, 0, 0),
        ]);
        assert_eq!(run(&p, &[]), Some(42));
    }

    #[test]
    fn add_imm_accumulates() {
        // MOV R0, 1 ; ADD64 R0, 41 ; EXIT
        let p = cat(&[
            raw(0xb7, 0, 0, 0, 1),
            raw(0x07, 0, 0, 0, 41),
            raw(0x95, 0, 0, 0, 0),
        ]);
        assert_eq!(run(&p, &[]), Some(42));
    }

    #[test]
    fn mov_reg_copies_register() {
        // MOV R1, 7 ; MOV64_REG R0, R1 ; EXIT
        let p = cat(&[
            raw(0xb7, 1, 0, 0, 7),
            raw(0xbf, 0, 1, 0, 0),
            raw(0x95, 0, 0, 0, 0),
        ]);
        assert_eq!(run(&p, &[]), Some(7));
    }

    #[test]
    fn jeq_imm_taken_skips() {
        // MOV R0, 5 ; JEQ R0, 5, +1 ; MOV R0, 999 ; EXIT
        // Should skip the MOV 999 and return 5.
        let p = cat(&[
            raw(0xb7, 0, 0, 0, 5),
            raw(0x15, 0, 0, 1, 5),
            raw(0xb7, 0, 0, 0, 999),
            raw(0x95, 0, 0, 0, 0),
        ]);
        assert_eq!(run(&p, &[]), Some(5));
    }

    #[test]
    fn jne_not_taken_falls_through() {
        // MOV R0, 1 ; JNE R0, 1, +1 ; MOV R0, 42 ; EXIT
        // R0!=1 false → fall through → R0=42.
        let p = cat(&[
            raw(0xb7, 0, 0, 0, 1),
            raw(0x55, 0, 0, 1, 1),
            raw(0xb7, 0, 0, 0, 42),
            raw(0x95, 0, 0, 0, 0),
        ]);
        assert_eq!(run(&p, &[]), Some(42));
    }

    #[test]
    fn ja_jumps_forward() {
        // MOV R0, 1 ; JA +1 ; MOV R0, 999 ; EXIT
        let p = cat(&[
            raw(0xb7, 0, 0, 0, 1),
            raw(0x05, 0, 0, 1, 0),
            raw(0xb7, 0, 0, 0, 999),
            raw(0x95, 0, 0, 0, 0),
        ]);
        assert_eq!(run(&p, &[]), Some(1));
    }

    #[test]
    fn ld_imm_dw_loads_64bit() {
        // LD_IMM_DW R0, 0xDEADBEEF_CAFEBABEu64 ; EXIT
        // lo half goes in slot 0 .imm, hi half in slot 1 .imm.
        let p = cat(&[
            raw(0x18, 0, 0, 0, 0xCAFEBABEu32 as i32),
            raw(0x00, 0, 0, 0, 0xDEADBEEFu32 as i32),
            raw(0x95, 0, 0, 0, 0),
        ]);
        assert_eq!(run(&p, &[]), Some(0xDEADBEEFCAFEBABEu64 as i64));
    }

    #[test]
    fn unsupported_opcode_returns_none() {
        // 0xFF is not a defined opcode in our subset.
        let p = cat(&[raw(0xff, 0, 0, 0, 0), raw(0x95, 0, 0, 0, 0)]);
        assert_eq!(run(&p, &[]), None);
    }

    #[test]
    fn ldx_mem_b_reads_packet_byte() {
        // LDX_MEM_B R0, [R1 + 2] ; EXIT — R1 = 0 on entry.
        let p = cat(&[
            raw(0x71, 0, 1, 2, 0),
            raw(0x95, 0, 0, 0, 0),
        ]);
        assert_eq!(run(&p, &[0x10, 0x20, 0x30, 0x40]), Some(0x30));
    }

    #[test]
    fn ldx_mem_w_reads_little_endian_word() {
        // LDX_MEM_W R0, [R1 + 0] ; EXIT
        let p = cat(&[
            raw(0x61, 0, 1, 0, 0),
            raw(0x95, 0, 0, 0, 0),
        ]);
        let pkt = [0x78, 0x56, 0x34, 0x12];
        assert_eq!(run(&p, &pkt), Some(0x12345678));
    }

    #[test]
    fn ldx_mem_b_out_of_bounds_returns_none() {
        // LDX_MEM_B R0, [R1 + 99] ; EXIT — pkt too short.
        let p = cat(&[
            raw(0x71, 0, 1, 99, 0),
            raw(0x95, 0, 0, 0, 0),
        ]);
        assert_eq!(run(&p, &[0x10]), None);
    }

    #[test]
    fn ldx_from_non_ctx_reg_rejected() {
        // LDX_MEM_B R0, [R2 + 0] ; EXIT — only R1 is the ctx ptr.
        let p = cat(&[
            raw(0x71, 0, 2, 0, 0),
            raw(0x95, 0, 0, 0, 0),
        ]);
        assert_eq!(run(&p, &[0x10, 0x20]), None);
    }

    #[test]
    fn infinite_loop_hits_step_budget() {
        // JA -1 (back to itself). Each step decrements budget.
        let p = cat(&[
            raw(0x05, 0, 0, -1, 0),
            raw(0x95, 0, 0, 0, 0),
        ]);
        assert_eq!(run(&p, &[]), None);
    }
}
