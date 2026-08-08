//! The path-sensitive program verifier — the one owner of instruction
//! admission for every loadable program type.
//!
//! Module manifest:
//!
//!   state.rs     abstract register/stack state and pointer domains
//!   context.rs   per-program-type context field access rules
//!   helpers.rs   per-program-type helper argument contracts
//!   limits.rs    scalar ranges and per-type return ranges
//!   worklist.rs  the per-instruction state set driving the fixpoint

use alloc::collections::VecDeque;

use vfs::InodeRef;

use super::*;
use crate::bpf::uapi;

#[path = "program/limits.rs"]
mod limits;
#[path = "program/worklist.rs"]
mod worklist;
#[path = "program/state.rs"]
mod state;
#[path = "program/context.rs"]
pub mod context;
#[path = "program/helpers.rs"]
mod helpers;

use limits::{Scalar, return_range};
use state::{
    Kind, State, mark_stack, memory_size, range, scalar, stack_ready, value_range,
    wide_slots,
};

pub use context::SK_FILTER_CONTEXT_BYTES;

fn enqueue(
    states: &mut [worklist::StateSet<State>],
    queue: &mut VecDeque<(usize, State)>,
    pseudo: &[bool],
    pc: usize,
    state: State,
) -> Result<(), VerifyError> {
    if pc >= states.len() { return Err(VerifyError::JumpOutOfBounds); }
    if pseudo[pc] { return Err(VerifyError::UnsupportedOpcode); }
    worklist::enqueue(states, queue, pc, state)
}

/// Verify one program against its type's context, helper and return
/// contract. Returns whether the verifier proved the expected attach type
/// is part of the program's contract.
/// # C: O(instructions × control-flow state updates)
pub fn verify_program(
    prog_type: u32,
    expected_attach_type: u32,
    insns: &[u8],
    maps: &[InodeRef],
) -> Result<bool, VerifyError> {
    verify(insns)?;
    let decoded = decode_all(insns)?;
    let pseudo = wide_slots(&decoded, maps)?;
    let reachable = super::loops::reachable(&decoded, &pseudo)?;
    let context_bytes = context::context_size(prog_type);
    let mut states = worklist::state_sets(decoded.len())?;
    let mut queue = try_queue(decoded.len())?;
    enqueue(&mut states, &mut queue, &pseudo, 0, State::entry())?;
    let mut processed = 0u32;
    let mut enforce_expected_attach_type = false;

    while let Some((pc, mut state)) = queue.pop_front() {
        if processed >= crate::bpf_interp::STEP_BUDGET {
            return Err(VerifyError::UnsupportedOpcode);
        }
        processed += 1;
        let insn = decoded[pc];
        let class = insn.opcode & BPF_CLASS_MASK;
        let op = insn.opcode & 0xf0;
        let x = insn.opcode & 0x08 != 0;

        match class {
            0x04 | 0x07 => {
                if insn.dst == 10 || insn.off != 0 { return Err(VerifyError::UnsupportedOpcode); }
                let dst = insn.dst as usize;
                if class == 0x04 && op == 0xd0 {
                    scalar(state.regs[dst])?;
                    if insn.src != 0 || !matches!(insn.imm, 16 | 32 | 64) {
                        return Err(VerifyError::UnsupportedOpcode);
                    }
                    state.regs[dst] = Kind::Scalar(Scalar::unknown());
                } else if op == 0xb0 {
                    let source = if x {
                        if insn.imm != 0 { return Err(VerifyError::UnsupportedOpcode); }
                        state.regs[insn.src as usize]
                    } else {
                        if insn.src != 0 { return Err(VerifyError::UnsupportedOpcode); }
                        Kind::Scalar(Scalar::exact(insn.imm as i64))
                    };
                    state.regs[dst] = if class == 0x07 {
                        source
                    } else {
                        Kind::Scalar(match source {
                            Kind::Scalar(value)
                                if value.min >= 0 && value.max <= u32::MAX as i64 => value,
                            Kind::Scalar(value) => value.value()
                                .map(|v| Scalar::exact(v as u32 as i64))
                                .unwrap_or_else(Scalar::unknown),
                            Kind::Uninit => return Err(VerifyError::UninitializedReg),
                            _ => Scalar::unknown(),
                        })
                    };
                } else if class == 0x07 && !x && matches!(op, 0x00 | 0x10)
                    && matches!(state.regs[dst],
                        Kind::Context(_) | Kind::Stack(_) | Kind::Value { .. }) {
                    let delta = if op == 0 { insn.imm } else { insn.imm.wrapping_neg() };
                    state.regs[dst] = match state.regs[dst] {
                        Kind::Context(base) => Kind::Context(base.wrapping_add(delta)),
                        Kind::Stack(base) => Kind::Stack(base.wrapping_add(delta)),
                        Kind::Value { map, offset, nullable } => Kind::Value {
                            map, offset: offset.wrapping_add(delta), nullable,
                        },
                        _ => unreachable!(),
                    };
                } else {
                    let left = scalar(state.regs[dst])?;
                    let right = if x {
                        if insn.imm != 0 { return Err(VerifyError::UnsupportedOpcode); }
                        scalar(state.regs[insn.src as usize])?
                    } else {
                        if insn.src != 0 { return Err(VerifyError::UnsupportedOpcode); }
                        Scalar::exact(insn.imm as i64)
                    };
                    if !matches!(op, 0x00 | 0x10 | 0x20 | 0x30 | 0x40 | 0x50
                        | 0x60 | 0x70 | 0x80 | 0x90 | 0xa0 | 0xb0 | 0xc0)
                        || matches!(op, 0x30 | 0x90) && right.value() == Some(0) {
                        return Err(VerifyError::UnsupportedOpcode);
                    }
                    state.regs[dst] = Kind::Scalar(match left.value().zip(right.value()) {
                        Some((a, b)) => crate::bpf_interp::verify_alu(
                            op, a, b, class == 0x07,
                        ).map(Scalar::exact).unwrap_or_else(Scalar::unknown),
                        None => Scalar::unknown(),
                    });
                }
                enqueue(&mut states, &mut queue, &pseudo, pc + 1, state)?;
            }
            BPF_JMP | BPF_JMP32 => {
                if insn.opcode == BPF_OP_EXIT {
                    // R0 must be a readable, non-pointer value at every exit;
                    // only then does the per-type return range apply.
                    let actual = scalar(state.regs[0])?;
                    if let Some(allowed) = return_range(prog_type, expected_attach_type) {
                        if actual.min < allowed.min || actual.max > allowed.max {
                            return Err(VerifyError::UnsupportedOpcode);
                        }
                        if actual.min >= 2 && actual.max <= 3
                            && prog_type == uapi::prog_type::CGROUP_SKB
                            && expected_attach_type == uapi::attach_type::CGROUP_INET_EGRESS {
                            enforce_expected_attach_type = true;
                        }
                    }
                    continue;
                }
                if insn.opcode == BPF_OP_CALL {
                    helpers::verify_helper(prog_type, insn, &mut state, maps)?;
                    enqueue(&mut states, &mut queue, &pseudo, pc + 1, state)?;
                    continue;
                }
                if op != 0 {
                    if matches!(state.regs[insn.dst as usize], Kind::Uninit) {
                        return Err(VerifyError::UninitializedReg);
                    }
                    if x && matches!(state.regs[insn.src as usize], Kind::Uninit) {
                        return Err(VerifyError::UninitializedReg);
                    }
                }
                let target = (pc as i64 + 1 + insn.off as i64) as usize;
                let mut fallthrough = state;
                let mut taken = state;
                if !x && insn.imm == 0 && matches!(op, 0x10 | 0x50) {
                    let dst = insn.dst as usize;
                    if let Kind::Value { map, offset, nullable: true } = state.regs[dst] {
                        let nonnull = Kind::Value { map, offset, nullable: false };
                        if op == 0x10 {
                            taken.regs[dst] = Kind::Scalar(Scalar::exact(0));
                            fallthrough.regs[dst] = nonnull;
                        } else {
                            taken.regs[dst] = nonnull;
                            fallthrough.regs[dst] = Kind::Scalar(Scalar::exact(0));
                        }
                    }
                }
                let right = if x { state.regs[insn.src as usize] }
                    else { Kind::Scalar(Scalar::exact(insn.imm as i64)) };
                let decision = scalar(state.regs[insn.dst as usize]).ok()
                    .and_then(Scalar::value).zip(scalar(right).ok().and_then(Scalar::value))
                    .and_then(|(left, right)| crate::bpf_interp::verify_jump(
                        op, left, right, class == BPF_JMP,
                    ));
                if op != 0 && decision != Some(true) {
                    enqueue(&mut states, &mut queue, &pseudo, pc + 1, fallthrough)?;
                }
                if decision != Some(false) {
                    enqueue(&mut states, &mut queue, &pseudo, target, taken)?;
                }
            }
            BPF_LDX => {
                if insn.opcode & 0xe0 != 0x60 || insn.imm != 0 || insn.dst == 10 {
                    return Err(VerifyError::UnsupportedOpcode);
                }
                let size = memory_size(insn.opcode).ok_or(VerifyError::UnsupportedOpcode)?;
                match state.regs[insn.src as usize] {
                    Kind::Context(base) => {
                        let at = range(base, insn.off, size, context_bytes)
                            .map_err(|_| VerifyError::UnsafeContextAccess)?;
                        if !context::valid_context(
                            prog_type, expected_attach_type, at, size, false,
                        ) {
                            return Err(VerifyError::UnsafeContextAccess);
                        }
                    }
                    Kind::Stack(base) => {
                        let at = range(base, insn.off, size, crate::bpf_interp::STACK_BYTES)?;
                        if !stack_ready(&state, at, size) {
                            return Err(VerifyError::UninitializedStack);
                        }
                    }
                    Kind::Value { map, offset, nullable: false } => {
                        value_range(maps, map, offset, insn.off, size, true, false)?;
                    }
                    Kind::Value { nullable: true, .. } => {
                        return Err(VerifyError::UnsafeContextAccess);
                    }
                    Kind::Uninit => return Err(VerifyError::UninitializedReg),
                    _ => return Err(VerifyError::UnsupportedOpcode),
                }
                state.regs[insn.dst as usize] = Kind::Scalar(Scalar::unknown());
                enqueue(&mut states, &mut queue, &pseudo, pc + 1, state)?;
            }
            0x02 | 0x03 => {
                let atomic = class == 0x03 && insn.opcode & 0xe0 == 0xc0;
                if !atomic && insn.opcode & 0xe0 != 0x60 {
                    return Err(VerifyError::UnsupportedOpcode);
                }
                let size = memory_size(insn.opcode).ok_or(VerifyError::UnsupportedOpcode)?;
                if class == 0x03 && matches!(state.regs[insn.src as usize], Kind::Uninit) {
                    return Err(VerifyError::UninitializedReg);
                }
                match state.regs[insn.dst as usize] {
                    Kind::Stack(base) if !atomic => {
                        let at = range(base, insn.off, size, crate::bpf_interp::STACK_BYTES)?;
                        mark_stack(&mut state, at, size);
                    }
                    Kind::Context(base) if !atomic => {
                        let at = range(base, insn.off, size, context_bytes)
                            .map_err(|_| VerifyError::UnsafeContextAccess)?;
                        if !context::valid_context(
                            prog_type, expected_attach_type, at, size, true,
                        ) {
                            return Err(VerifyError::UnsafeContextAccess);
                        }
                    }
                    Kind::Value { map, offset, nullable: false } => {
                        if atomic && (insn.imm != 0 || !matches!(size, 4 | 8)) {
                            return Err(VerifyError::UnsupportedOpcode);
                        }
                        value_range(
                            maps, map, offset, insn.off, size, atomic, true,
                        )?;
                    }
                    _ => return Err(VerifyError::UnsafeStackAccess),
                }
                enqueue(&mut states, &mut queue, &pseudo, pc + 1, state)?;
            }
            BPF_LD if insn.opcode == BPF_LD_IMM_DW => {
                let next = decoded[pc + 1];
                state.regs[insn.dst as usize] = match insn.src {
                    0 => Kind::Scalar(Scalar::exact(
                        ((next.imm as u32 as u64) << 32 | insn.imm as u32 as u64) as i64,
                    )),
                    uapi::pseudo::MAP_FD => Kind::Map(insn.imm as usize),
                    uapi::pseudo::MAP_VALUE => Kind::Value {
                        map: insn.imm as usize, offset: next.imm, nullable: false,
                    },
                    _ => return Err(VerifyError::UnsupportedOpcode),
                };
                enqueue(&mut states, &mut queue, &pseudo, pc + 2, state)?;
            }
            _ => return Err(VerifyError::UnsupportedOpcode),
        }
    }
    if reachable.iter().enumerate().any(|(pc, seen)| !pseudo[pc] && !seen) {
        return Err(VerifyError::UnreachableInsn);
    }
    Ok(enforce_expected_attach_type)
}

#[cfg(test)]
#[path = "program/tests.rs"]
mod tests;
