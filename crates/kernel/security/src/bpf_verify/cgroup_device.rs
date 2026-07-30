//! `BPF_PROG_TYPE_CGROUP_DEVICE` verifier.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use super::*;
use crate::bpf::uapi::func_id;

const ALU: u8 = 0x04;
const ALU64: u8 = 0x07;
const ST: u8 = 0x02;
const STX: u8 = 0x03;
const STACK_BYTES: i32 = crate::bpf_interp::STACK_BYTES as i32;
const STEP_BUDGET: u64 = crate::bpf_interp::STEP_BUDGET as u64;

// Scalar helpers from cgroup_common_func_proto / bpf_base_func_proto that have
// real owners in this kernel. Map-, storage-, ringbuf-, perf-, callback-, and
// pointer-output helpers are intentionally absent. get/set_retval are absent
// because the canonical VFS hook cannot carry an arbitrary BPF errno.
const SUPPORTED_HELPERS: &[i32] = &[
    func_id::KTIME_GET_NS as i32,
    func_id::GET_SMP_PROCESSOR_ID as i32,
    func_id::GET_CURRENT_PID_TGID as i32,
    func_id::GET_CURRENT_UID_GID as i32,
    func_id::GET_NUMA_NODE_ID as i32,
    func_id::GET_CURRENT_CGROUP_ID as i32,
    func_id::KTIME_GET_BOOT_NS as i32,
];

#[derive(Copy, Clone, Eq, PartialEq)]
struct State {
    initialized: u16,
    context: u16,
    stack_initialized: [u64; 8],
    context_spills: u64,
}

impl State {
    fn entry() -> Self {
        Self {
            initialized: bit(1) | bit(10),
            context: bit(1),
            stack_initialized: [0; 8],
            context_spills: 0,
        }
    }

    fn intersect(mut self, other: Self) -> Self {
        self.initialized &= other.initialized;
        self.context &= other.context;
        for (dst, src) in self.stack_initialized.iter_mut()
            .zip(other.stack_initialized.iter()) {
            *dst &= *src;
        }
        self.context_spills &= other.context_spills;
        self
    }
}

const fn bit(reg: u8) -> u16 { 1u16 << reg }

fn mem_size(opcode: u8) -> Option<usize> {
    if opcode & 0xe0 != 0x60 { return None; }
    Some(match (opcode >> 3) & 3 { 0 => 4, 1 => 2, 2 => 1, 3 => 8, _ => return None })
}

fn stack_range(off: i16, size: usize) -> Result<usize, VerifyError> {
    let start = STACK_BYTES + off as i32;
    if off >= 0 || start < 0 || start + size as i32 > STACK_BYTES
        || start % size as i32 != 0 {
        return Err(VerifyError::UnsafeStackAccess);
    }
    Ok(start as usize)
}

fn stack_bytes(state: &State, start: usize, size: usize) -> bool {
    (start..start + size).all(|i| state.stack_initialized[i / 64] & (1 << (i % 64)) != 0)
}

fn mark_stack(state: &mut State, start: usize, size: usize) {
    for i in start..start + size {
        state.stack_initialized[i / 64] |= 1 << (i % 64);
    }
    let first = start / 8;
    let last = (start + size - 1) / 8;
    for slot in first..=last { state.context_spills &= !(1 << slot); }
}

fn valid_context_access(off: i16, size: usize) -> bool {
    let off = off as i32;
    if off < 0 || off % size as i32 != 0 { return false; }
    (off < 4 && off + size as i32 <= 4) || (size == 4 && matches!(off, 4 | 8))
}

fn validate_wide_and_loops(decoded: &[Insn]) -> Result<Vec<bool>, VerifyError> {
    let mut pseudo = try_filled_vec(decoded.len(), false)?;
    let mut pc = 0;
    while pc < decoded.len() {
        if decoded[pc].opcode == BPF_LD_IMM_DW {
            let next = decoded.get(pc + 1).ok_or(VerifyError::TruncatedWideLoad)?;
            if decoded[pc].src != 0 || decoded[pc].off != 0 || decoded[pc].dst == 10
                || next.opcode != 0 || next.dst != 0 || next.src != 0 || next.off != 0 {
                return Err(VerifyError::UnsupportedOpcode);
            }
            pseudo[pc + 1] = true;
            pc += 2;
        } else {
            pc += 1;
        }
    }
    super::loops::validate(decoded, &pseudo)?;
    Ok(pseudo)
}

fn merge(
    states: &mut [Option<State>],
    queue: &mut VecDeque<usize>,
    pseudo: &[bool],
    pc: usize,
    state: State,
) -> Result<(), VerifyError> {
    if pc >= states.len() { return Err(VerifyError::JumpOutOfBounds); }
    if pseudo[pc] { return Err(VerifyError::UnsupportedOpcode); }
    let merged = states[pc].map_or(state, |old| old.intersect(state));
    if states[pc] != Some(merged) {
        states[pc] = Some(merged);
        queue.try_reserve(1).map_err(|_| VerifyError::NoMemory)?;
        queue.push_back(pc);
    }
    Ok(())
}

/// Verify the ordinary scalar, stack, control-flow, and supported-helper
/// surface executed by the cgroup-device runner. # C: O(insns × state updates)
pub fn verify_cgroup_device(insns: &[u8]) -> Result<(), VerifyError> {
    verify(insns)?;
    let decoded = decode_all(insns)?;
    let pseudo = validate_wide_and_loops(&decoded)?;
    let mut states = try_filled_vec(decoded.len(), None)?;
    let mut queue = try_queue(decoded.len())?;
    states[0] = Some(State::entry());
    queue.push_back(0);
    let mut processed = 0u64;

    while let Some(pc) = queue.pop_front() {
        if processed >= STEP_BUDGET { return Err(VerifyError::UnsupportedOpcode); }
        processed += 1;
        let mut state = states[pc].ok_or(VerifyError::UnreachableInsn)?;
        let insn = decoded[pc];
        let class = insn.opcode & BPF_CLASS_MASK;
        let op = insn.opcode & 0xf0;
        let x = insn.opcode & 0x08 != 0;
        let has = |r: u8, s: &State| s.initialized & bit(r) != 0;
        let is_ctx = |r: u8, s: &State| s.context & bit(r) != 0;

        match class {
            ALU | ALU64 => {
                if insn.dst == 10 { return Err(VerifyError::UnsupportedOpcode); }
                if class == ALU && op == 0xd0 {
                    if insn.src != 0 || insn.off != 0 || !matches!(insn.imm, 16 | 32 | 64)
                        || !has(insn.dst, &state) {
                        return Err(VerifyError::UnsupportedOpcode);
                    }
                } else {
                    if !matches!(op, 0x00 | 0x10 | 0x20 | 0x30 | 0x40 | 0x50 | 0x60
                        | 0x70 | 0x80 | 0x90 | 0xa0 | 0xb0 | 0xc0)
                        || (op == 0x80 && x) || insn.off != 0
                        || (x && insn.imm != 0) || (!x && insn.src != 0)
                        || (op == 0x80 && (insn.src != 0 || insn.imm != 0))
                        || (matches!(op, 0x30 | 0x90) && !x && insn.imm == 0)
                        || (matches!(op, 0x60 | 0x70 | 0xc0) && !x
                            && !(0..if class == ALU64 { 64 } else { 32 }).contains(&insn.imm))
                        || (op != 0xb0 && !has(insn.dst, &state))
                        || (x && !has(insn.src, &state)) {
                        return Err(VerifyError::UninitializedReg);
                    }
                }
                let copy_ctx = class == ALU64 && op == 0xb0 && x && is_ctx(insn.src, &state);
                state.initialized |= bit(insn.dst);
                state.context &= !bit(insn.dst);
                if copy_ctx { state.context |= bit(insn.dst); }
                merge(&mut states, &mut queue, &pseudo, pc + 1, state)?;
            }
            BPF_JMP | BPF_JMP32 => {
                if insn.opcode == BPF_OP_EXIT {
                    if !has(0, &state) { return Err(VerifyError::UninitializedReg); }
                    continue;
                }
                if insn.opcode == BPF_OP_CALL {
                    if insn.dst != 0 || insn.src != 0 || insn.off != 0
                        || !SUPPORTED_HELPERS.contains(&insn.imm) {
                        return Err(VerifyError::UnsupportedOpcode);
                    }
                    state.initialized &= !(bit(1) | bit(2) | bit(3) | bit(4) | bit(5));
                    state.context &= !(bit(1) | bit(2) | bit(3) | bit(4) | bit(5));
                    state.initialized |= bit(0);
                    merge(&mut states, &mut queue, &pseudo, pc + 1, state)?;
                    continue;
                }
                if !matches!(op, 0x00 | 0x10 | 0x20 | 0x30 | 0x40 | 0x50 | 0x60
                    | 0x70 | 0xa0 | 0xb0 | 0xc0 | 0xd0)
                    || (op == 0 && (class != BPF_JMP || x || insn.dst != 0
                        || insn.src != 0 || insn.imm != 0))
                    || (op != 0 && ((x && insn.imm != 0) || (!x && insn.src != 0)
                        || !has(insn.dst, &state) || (x && !has(insn.src, &state)))) {
                    return Err(VerifyError::UnsupportedOpcode);
                }
                let target = (pc as i64 + 1 + insn.off as i64) as usize;
                if op != 0 { merge(&mut states, &mut queue, &pseudo, pc + 1, state)?; }
                merge(&mut states, &mut queue, &pseudo, target, state)?;
            }
            BPF_LDX => {
                let size = mem_size(insn.opcode).ok_or(VerifyError::UnsupportedOpcode)?;
                if insn.imm != 0 || insn.dst == 10 || !has(insn.src, &state) {
                    return Err(VerifyError::UnsupportedOpcode);
                }
                let loaded_ctx = if insn.src == 10 {
                    let start = stack_range(insn.off, size)?;
                    if !stack_bytes(&state, start, size) {
                        return Err(VerifyError::UninitializedStack);
                    }
                    size == 8 && state.context_spills & (1 << (start / 8)) != 0
                } else {
                    if !is_ctx(insn.src, &state) || !valid_context_access(insn.off, size) {
                        return Err(VerifyError::UnsafeContextAccess);
                    }
                    false
                };
                state.initialized |= bit(insn.dst);
                state.context &= !bit(insn.dst);
                if loaded_ctx { state.context |= bit(insn.dst); }
                merge(&mut states, &mut queue, &pseudo, pc + 1, state)?;
            }
            ST | STX => {
                let size = mem_size(insn.opcode).ok_or(VerifyError::UnsupportedOpcode)?;
                if insn.dst != 10 || (class == ST && insn.src != 0)
                    || (class == STX && (insn.imm != 0 || !has(insn.src, &state))) {
                    return Err(VerifyError::UnsafeStackAccess);
                }
                let start = stack_range(insn.off, size)?;
                let spill_ctx = class == STX && size == 8 && is_ctx(insn.src, &state);
                mark_stack(&mut state, start, size);
                if spill_ctx { state.context_spills |= 1 << (start / 8); }
                merge(&mut states, &mut queue, &pseudo, pc + 1, state)?;
            }
            BPF_LD if insn.opcode == BPF_LD_IMM_DW => {
                state.initialized |= bit(insn.dst);
                state.context &= !bit(insn.dst);
                merge(&mut states, &mut queue, &pseudo, pc + 2, state)?;
            }
            _ => return Err(VerifyError::UnsupportedOpcode),
        }
    }
    if states.iter().enumerate().any(|(pc, state)| !pseudo[pc] && state.is_none()) {
        return Err(VerifyError::UnreachableInsn);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAP_LOOKUP_ELEM_HELPER: i32 = 1;
    const GET_RETVAL_HELPER: i32 = 186;

    fn raw(opc: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
        let off = off.to_le_bytes();
        let imm = imm.to_le_bytes();
        [opc, (src << 4) | dst, off[0], off[1], imm[0], imm[1], imm[2], imm[3]]
    }

    fn cat(insns: &[[u8; 8]]) -> Vec<u8> {
        insns.iter().flat_map(|insn| insn.iter().copied()).collect()
    }

    #[test]
    fn accepts_systemd_context_and_branch_shape() {
        let p = cat(&[
            raw(0x61, 2, 1, 0, 0), raw(0x54, 2, 0, 0, 0xffff),
            raw(0x61, 4, 1, 4, 0), raw(0xbc, 1, 2, 0, 0),
            raw(0x55, 4, 0, 2, 1), raw(0xb7, 0, 0, 0, 1),
            raw(0x05, 0, 0, 1, 0), raw(0xb7, 0, 0, 0, 0),
            raw(0x95, 0, 0, 0, 0),
        ]);
        assert_eq!(verify_cgroup_device(&p), Ok(()));
    }

    #[test]
    fn accepts_stack_sizes_spills_lddw_helpers_and_bounded_loop() {
        let p = cat(&[
            raw(0x7b, 10, 1, -8, 0), raw(0x79, 6, 10, -8, 0),
            raw(0x61, 0, 6, 4, 0), raw(0x72, 10, 0, -9, 7),
            raw(0x71, 2, 10, -9, 0), raw(0x6a, 10, 0, -12, 8),
            raw(0x69, 3, 10, -12, 0), raw(0x62, 10, 0, -16, 9),
            raw(0x61, 4, 10, -16, 0), raw(0x18, 3, 0, 0, 42),
            raw(0x00, 0, 0, 0, 1),
            raw(0x85, 0, 0, 0, func_id::GET_CURRENT_PID_TGID as i32),
            raw(0xb7, 7, 0, 0, 0), raw(0x07, 7, 0, 0, 1),
            raw(0xa5, 7, 0, -2, 4), raw(0xb7, 0, 0, 0, 1),
            raw(0x95, 0, 0, 0, 0),
        ]);
        assert_eq!(verify_cgroup_device(&p), Ok(()));
    }

    #[test]
    fn rejects_uninitialized_stack_unknown_helper_and_unproved_loop() {
        let stack = cat(&[raw(0x79, 0, 10, -8, 0), raw(0x95, 0, 0, 0, 0)]);
        assert_eq!(verify_cgroup_device(&stack), Err(VerifyError::UninitializedStack));
        let helper = cat(&[
            raw(0x85, 0, 0, 0, MAP_LOOKUP_ELEM_HELPER),
            raw(0x95, 0, 0, 0, 0),
        ]);
        assert_eq!(verify_cgroup_device(&helper), Err(VerifyError::UnsupportedOpcode));
        let retval = cat(&[
            raw(0x85, 0, 0, 0, GET_RETVAL_HELPER),
            raw(0x95, 0, 0, 0, 0),
        ]);
        assert_eq!(verify_cgroup_device(&retval), Err(VerifyError::UnsupportedOpcode));
        let looped = cat(&[
            raw(0xb7, 0, 0, 0, 1), raw(0x05, 0, 0, -1, 0),
            raw(0x95, 0, 0, 0, 0),
        ]);
        assert_eq!(verify_cgroup_device(&looped), Err(VerifyError::UnsupportedOpcode));
        let over_budget = cat(&[
            raw(0xb7, 2, 0, 0, 0), raw(0x07, 2, 0, 0, 1),
            raw(0xa5, 2, 0, -2, 500_000), raw(0xb7, 0, 0, 0, 1),
            raw(0x95, 0, 0, 0, 0),
        ]);
        assert_eq!(verify_cgroup_device(&over_budget), Err(VerifyError::UnsupportedOpcode));
    }
}
