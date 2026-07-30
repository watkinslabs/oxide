//! Verifier for the cgroup skb and socket-address execution domains.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use vfs::InodeRef;

use super::*;
use crate::bpf::{BpfMapInode, uapi};

#[path = "cgroup_network/limits.rs"]
mod limits;
use limits::{Scalar, return_range};
#[path = "cgroup_network/worklist.rs"]
mod worklist;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Kind {
    Uninit,
    Scalar(Scalar),
    Context(i32),
    Stack(i32),
    Map(usize),
    Value { map: usize, offset: i32, nullable: bool },
}

#[derive(Copy, Clone, Eq, PartialEq)]
struct State {
    regs: [Kind; 11],
    stack: [u64; 8],
}

impl State {
    fn entry() -> Self {
        let mut regs = [Kind::Uninit; 11];
        regs[1] = Kind::Context(0);
        regs[10] = Kind::Stack(crate::bpf_interp::STACK_BYTES as i32);
        Self { regs, stack: [0; 8] }
    }
}

fn scalar(kind: Kind) -> Result<Scalar, VerifyError> {
    match kind {
        Kind::Scalar(value) => Ok(value),
        Kind::Uninit => Err(VerifyError::UninitializedReg),
        _ => Err(VerifyError::UnsupportedOpcode),
    }
}

fn range(base: i32, offset: i16, size: usize, limit: usize) -> Result<usize, VerifyError> {
    let start = base.checked_add(offset as i32).ok_or(VerifyError::UnsafeStackAccess)?;
    if start < 0 || (start as usize).checked_add(size).is_none_or(|end| end > limit) {
        return Err(VerifyError::UnsafeStackAccess);
    }
    Ok(start as usize)
}

fn stack_ready(state: &State, start: usize, size: usize) -> bool {
    (start..start + size).all(|byte| state.stack[byte / 64] & (1 << (byte % 64)) != 0)
}

fn mark_stack(state: &mut State, start: usize, size: usize) {
    for byte in start..start + size { state.stack[byte / 64] |= 1 << (byte % 64); }
}

fn memory_size(opcode: u8) -> Option<usize> {
    Some(match (opcode >> 3) & 3 {
        0 => 4,
        1 => 2,
        2 => 1,
        3 => 8,
        _ => return None,
    })
}

fn valid_context(
    prog_type: u32,
    expected_attach_type: u32,
    offset: usize,
    size: usize,
    write: bool,
) -> bool {
    use uapi::attach_type as a;
    use uapi::prog_type as p;
    if prog_type == p::CGROUP_SKB {
        return !write && size == 4 && matches!(offset, 0 | 16 | 40);
    }
    if prog_type != p::CGROUP_SOCK_ADDR { return false; }
    if offset % size != 0 { return false; }
    let within = |start, end| offset >= start
        && offset.checked_add(size).is_some_and(|after| after <= end);
    let inet4 = matches!(expected_attach_type, a::CGROUP_INET4_BIND | a::CGROUP_INET4_CONNECT);
    let inet6 = matches!(expected_attach_type, a::CGROUP_INET6_BIND | a::CGROUP_INET6_CONNECT);
    if write {
        return size == 4 && offset == 24
            || inet4 && size == 4 && offset == 4
            || inet6 && matches!(size, 4 | 8) && within(8, 24);
    }
    size == 4 && matches!(offset, 0 | 28 | 32 | 36)
        || matches!(size, 1 | 2 | 4) && within(24, 28)
        || inet4 && matches!(size, 1 | 2 | 4) && within(4, 8)
        || inet6 && matches!(size, 1 | 2 | 4 | 8) && within(8, 24)
}

fn map_at<'a>(maps: &'a [InodeRef], index: usize) -> Result<&'a BpfMapInode, VerifyError> {
    maps.get(index).and_then(|inode| inode.private::<BpfMapInode>())
        .ok_or(VerifyError::UnsupportedOpcode)
}

fn value_range(
    maps: &[InodeRef],
    map: usize,
    base: i32,
    offset: i16,
    size: usize,
    read: bool,
    write: bool,
) -> Result<(), VerifyError> {
    let object = map_at(maps, map)?;
    let start = base.checked_add(offset as i32).ok_or(VerifyError::UnsafeContextAccess)?;
    if start < 0 || start as usize % size != 0
        || (start as usize).checked_add(size)
            .is_none_or(|end| end > object.value_size as usize)
        || write && object.map_flags & uapi::map_flags::RDONLY_PROG != 0
        || read && object.map_flags & uapi::map_flags::WRONLY_PROG != 0 {
        return Err(VerifyError::UnsafeContextAccess);
    }
    Ok(())
}

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

fn wide_slots(decoded: &[Insn], maps: &[InodeRef]) -> Result<Vec<bool>, VerifyError> {
    let mut pseudo = try_filled_vec(decoded.len(), false)?;
    let mut pc = 0;
    while pc < decoded.len() {
        let insn = decoded[pc];
        if insn.opcode != BPF_LD_IMM_DW {
            pc += 1;
            continue;
        }
        let next = *decoded.get(pc + 1).ok_or(VerifyError::TruncatedWideLoad)?;
        if insn.dst == 10 || insn.off != 0 || next.opcode != 0
            || next.dst != 0 || next.src != 0 || next.off != 0 {
            return Err(VerifyError::UnsupportedOpcode);
        }
        match insn.src {
            0 => {}
            uapi::pseudo::MAP_FD => {
                map_at(maps, usize::try_from(insn.imm).map_err(|_| VerifyError::UnsupportedOpcode)?)?;
                if next.imm != 0 { return Err(VerifyError::UnsupportedOpcode); }
            }
            uapi::pseudo::MAP_VALUE => {
                let map = map_at(
                    maps,
                    usize::try_from(insn.imm).map_err(|_| VerifyError::UnsupportedOpcode)?,
                )?;
                if map.map_type != uapi::map_type::ARRAY || next.imm < 0
                    || next.imm as u32 >= map.value_size {
                    return Err(VerifyError::UnsupportedOpcode);
                }
            }
            _ => return Err(VerifyError::UnsupportedOpcode),
        }
        pseudo[pc + 1] = true;
        pc += 2;
    }
    super::loops::validate(decoded, &pseudo)?;
    Ok(pseudo)
}

/// Verify the type/pointer/helper contract shared by cgroup network programs.
/// # C: O(instructions × control-flow state updates)
pub fn verify_cgroup_network(
    prog_type: u32,
    expected_attach_type: u32,
    insns: &[u8],
    maps: &[InodeRef],
) -> Result<bool, VerifyError> {
    verify(insns)?;
    let decoded = decode_all(insns)?;
    let pseudo = wide_slots(&decoded, maps)?;
    let reachable = super::loops::reachable(&decoded, &pseudo)?;
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
                    let actual = scalar(state.regs[0])?;
                    let allowed = return_range(prog_type, expected_attach_type);
                    if actual.min < allowed.min || actual.max > allowed.max {
                        return Err(VerifyError::UnsupportedOpcode);
                    }
                    if actual.min >= 2 && actual.max <= 3
                        && prog_type == uapi::prog_type::CGROUP_SKB
                        && expected_attach_type == uapi::attach_type::CGROUP_INET_EGRESS {
                        enforce_expected_attach_type = true;
                    }
                    continue;
                }
                if insn.opcode == BPF_OP_CALL {
                    verify_helper(prog_type, insn, &mut state, maps)?;
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
                        let at = range(base, insn.off, size, 64)
                            .map_err(|_| VerifyError::UnsafeContextAccess)?;
                        if !valid_context(prog_type, expected_attach_type, at, size, false) {
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
                        let at = range(base, insn.off, size, 64)
                            .map_err(|_| VerifyError::UnsafeContextAccess)?;
                        if !valid_context(prog_type, expected_attach_type, at, size, true) {
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

fn verify_helper(
    prog_type: u32,
    insn: Insn,
    state: &mut State,
    maps: &[InodeRef],
) -> Result<(), VerifyError> {
    if insn.dst != 0 || insn.src != 0 || insn.off != 0 {
        return Err(VerifyError::UnsupportedOpcode);
    }
    let result = match insn.imm as u32 {
        uapi::func_id::MAP_LOOKUP_ELEM => {
            let Kind::Map(map) = state.regs[1] else {
                return Err(VerifyError::UnsupportedOpcode);
            };
            let object = map_at(maps, map)?;
            let Kind::Stack(base) = state.regs[2] else {
                return Err(VerifyError::UnsafeStackAccess);
            };
            let start = range(base, 0, object.key_size as usize, crate::bpf_interp::STACK_BYTES)?;
            if !stack_ready(state, start, object.key_size as usize) {
                return Err(VerifyError::UninitializedStack);
            }
            Kind::Value { map, offset: 0, nullable: true }
        }
        uapi::func_id::SKB_LOAD_BYTES if prog_type == uapi::prog_type::CGROUP_SKB => {
            if !matches!(state.regs[1], Kind::Context(_))
                || scalar(state.regs[2])?.value().is_none() {
                return Err(VerifyError::UnsupportedOpcode);
            }
            let Kind::Stack(base) = state.regs[3] else {
                return Err(VerifyError::UnsafeStackAccess);
            };
            let size = scalar(state.regs[4])?.value()
                .and_then(|v| usize::try_from(v).ok())
                .ok_or(VerifyError::UnsafeStackAccess)?;
            let start = range(base, 0, size, crate::bpf_interp::STACK_BYTES)?;
            mark_stack(state, start, size);
            Kind::Scalar(Scalar::range(
                -(syscall::errno::Errno::Efault.as_i32() as i64), 0,
            ))
        }
        uapi::func_id::GET_RETVAL if prog_type == uapi::prog_type::CGROUP_SOCK_ADDR => {
            Kind::Scalar(Scalar::range(-4095, 0))
        }
        uapi::func_id::SET_RETVAL if prog_type == uapi::prog_type::CGROUP_SOCK_ADDR => {
            if !scalar(state.regs[1])?.i32_within(-4095, 0) {
                return Err(VerifyError::UnsupportedOpcode);
            }
            Kind::Scalar(Scalar::exact(0))
        }
        _ => return Err(VerifyError::UnsupportedOpcode),
    };
    state.regs[1..=5].fill(Kind::Uninit);
    state.regs[0] = result;
    Ok(())
}

#[cfg(test)]
#[path = "cgroup_network_tests.rs"]
mod tests;
