//! eBPF verifier — first slice (structural checks).
//!
//! Linux's full verifier path-walks the program with a state
//! machine that tracks register types, scalar bounds, and stack
//! liveness. v1 is the structural subset Linux performs before the
//! flow-analysis phase even runs:
//!
//!   - non-empty insn buffer, length is a multiple of 8
//!   - insn count matches `insns.len() / 8`
//!   - every dst/src register fits in `R0..=R10`
//!   - every conditional/unconditional jump lands inside the
//!     program (no falling out of the end, no negative pc)
//!   - the final insn is `BPF_EXIT` (return path terminator)
//!   - 16-byte BPF_LD_IMM64 wide loads' pseudo-insn must be the
//!     immediately following 8-byte slot (no straddling end)
//!
//! Path-sensitive register/scalar tracking + JIT ride follow-up
//! PRs. The verifier rejects programs the JIT couldn't safely
//! lower, so failing eagerly here keeps the JIT honest.

extern crate alloc;
use alloc::vec::Vec;

pub const BPF_INSN_SIZE: usize = 8;
pub const MAX_REG: u8 = 10;

// BPF instruction class (low 3 bits of opcode)
const BPF_CLASS_MASK: u8 = 0x07;
const BPF_LD:    u8 = 0x00;
const BPF_JMP:   u8 = 0x05;
const BPF_JMP32: u8 = 0x06;

// BPF_LD | BPF_IMM | BPF_DW = 0x18 — the 16-byte wide load
const BPF_LD_IMM_DW: u8 = 0x18;

// BPF_EXIT opcode
const BPF_EXIT: u8 = 0x95;

// BPF_JMP "op" subfield carried in the upper 4 bits of opcode for
// jump-class insns. We only need to recognize CALL + JA + EXIT to
// classify whether an insn is "a jump that consumes off".
const BPF_JA:   u8 = 0x05; // BPF_JMP | BPF_JA  = 0x05<<4 | 0x05 ? — see notes below
// In Linux: opcode = (BPF_JMP << 0) | (op << 4) | (src << 8?). We
// match the raw byte. JA = 0x05, EXIT = 0x95, CALL = 0x85.
const BPF_OP_JA:   u8 = 0x05;
const BPF_OP_EXIT: u8 = 0x95;
const BPF_OP_CALL: u8 = 0x85;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VerifyError {
    Empty,
    UnalignedSize,
    TooManyInsns,
    BadReg,
    JumpOutOfBounds,
    LastNotExit,
    TruncatedWideLoad,
}

const MAX_INSNS: usize = 4096;

#[derive(Copy, Clone, Debug)]
struct Insn { opcode: u8, dst: u8, src: u8, off: i16, _imm: i32 }

fn decode(bytes: &[u8]) -> Insn {
    Insn {
        opcode: bytes[0],
        dst:    bytes[1] & 0x0f,
        src:    (bytes[1] >> 4) & 0x0f,
        off:    i16::from_le_bytes([bytes[2], bytes[3]]),
        _imm:   i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
    }
}

/// Run the structural verifier on a raw insn buffer (little-endian
/// 8-byte slots). Returns Ok on accept, Err on reject. No mutation.
/// # C: O(insn_cnt)
pub fn verify(insns: &[u8]) -> Result<(), VerifyError> {
    if insns.is_empty() { return Err(VerifyError::Empty); }
    if insns.len() % BPF_INSN_SIZE != 0 { return Err(VerifyError::UnalignedSize); }
    let n = insns.len() / BPF_INSN_SIZE;
    if n > MAX_INSNS { return Err(VerifyError::TooManyInsns); }

    let decoded: Vec<Insn> = (0..n)
        .map(|i| decode(&insns[i * BPF_INSN_SIZE .. (i + 1) * BPF_INSN_SIZE]))
        .collect();

    let mut pc = 0usize;
    while pc < n {
        let insn = decoded[pc];
        if insn.dst > MAX_REG || insn.src > MAX_REG {
            return Err(VerifyError::BadReg);
        }
        let class = insn.opcode & BPF_CLASS_MASK;
        match insn.opcode {
            // Wide load: occupies 2 slots, second slot is a pseudo
            // (opcode 0). It only needs to fit inside the program.
            BPF_LD_IMM_DW => {
                if pc + 1 >= n { return Err(VerifyError::TruncatedWideLoad); }
                pc += 2;
                continue;
            }
            BPF_OP_EXIT => {}
            BPF_OP_CALL => {} // helper call; arg validation rides verifier-v2
            _ => {}
        }
        // Jump-class insns (excluding EXIT and CALL handled above).
        // off is signed: target = pc + 1 + off; must land in [0, n).
        let is_jump = (class == BPF_JMP || class == BPF_JMP32)
            && insn.opcode != BPF_OP_EXIT
            && insn.opcode != BPF_OP_CALL;
        if is_jump {
            let target = (pc as i64) + 1 + insn.off as i64;
            if target < 0 || target >= n as i64 {
                return Err(VerifyError::JumpOutOfBounds);
            }
        }
        // Suppress unused-variable warnings for now; future PR
        // uses these on path-sensitive analysis.
        let _ = (class, BPF_LD, BPF_JA);
        pc += 1;
    }

    // Final reachable insn must be EXIT. We use last-insn check as
    // the structural proxy; path-walker upgrade comes later.
    let last = decoded[n - 1];
    if last.opcode != BPF_EXIT { return Err(VerifyError::LastNotExit); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn empty_program_rejected() {
        assert_eq!(verify(&[]), Err(VerifyError::Empty));
    }

    #[test]
    fn unaligned_size_rejected() {
        assert_eq!(verify(&[0u8; 7]), Err(VerifyError::UnalignedSize));
    }

    #[test]
    fn single_exit_accepted() {
        // BPF_EXIT (0x95)
        let p = cat(&[raw(0x95, 0, 0, 0, 0)]);
        assert_eq!(verify(&p), Ok(()));
    }

    #[test]
    fn missing_exit_rejected() {
        // BPF_MOV64_IMM (0xb7) with no exit
        let p = cat(&[raw(0xb7, 0, 0, 0, 1)]);
        assert_eq!(verify(&p), Err(VerifyError::LastNotExit));
    }

    #[test]
    fn bad_reg_rejected() {
        // dst=12 invalid
        let p = cat(&[raw(0xb7, 12, 0, 0, 0), raw(0x95, 0, 0, 0, 0)]);
        assert_eq!(verify(&p), Err(VerifyError::BadReg));
    }

    #[test]
    fn jump_out_of_bounds_rejected() {
        // BPF_JA (0x05) with off=50; n=2 → target=52 out of [0,2).
        let p = cat(&[raw(0x05, 0, 0, 50, 0), raw(0x95, 0, 0, 0, 0)]);
        assert_eq!(verify(&p), Err(VerifyError::JumpOutOfBounds));
    }

    #[test]
    fn valid_forward_jump_accepted() {
        // pc=0: JA off=1 (skip insn 1) → target=2 (after EXIT)
        // Need n>=3: JA, NOP-ish (mov), EXIT.
        let p = cat(&[
            raw(0x05, 0, 0, 1, 0),    // JA off=1 → pc=2
            raw(0xb7, 0, 0, 0, 0),    // (skipped)
            raw(0x95, 0, 0, 0, 0),    // EXIT
        ]);
        assert_eq!(verify(&p), Ok(()));
    }

    #[test]
    fn wide_load_two_slot_accepted() {
        // BPF_LD_IMM_DW (0x18) takes two slots. Second is a
        // pseudo-insn (opcode 0). Then EXIT.
        let p = cat(&[
            raw(0x18, 0, 0, 0, 0),
            raw(0x00, 0, 0, 0, 0),
            raw(0x95, 0, 0, 0, 0),
        ]);
        assert_eq!(verify(&p), Ok(()));
    }

    #[test]
    fn wide_load_truncated_rejected() {
        // 0x18 in the last slot — no pseudo-insn following.
        let p = cat(&[raw(0x18, 0, 0, 0, 0)]);
        assert_eq!(verify(&p), Err(VerifyError::TruncatedWideLoad));
    }
}
