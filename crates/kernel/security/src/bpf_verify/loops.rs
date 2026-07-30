//! Shared proof for backward control-flow edges.

use super::*;

const ALU: u8 = 0x04;
const ALU64: u8 = 0x07;
const STEP_BUDGET: u64 = crate::bpf_interp::STEP_BUDGET as u64;

fn writes_reg(insn: Insn, reg: u8) -> bool {
    let class = insn.opcode & BPF_CLASS_MASK;
    matches!(class, ALU | ALU64 | BPF_LDX) && insn.dst == reg
        || insn.opcode == BPF_LD_IMM_DW && insn.dst == reg
}

fn jump_target(at: usize, insn: Insn, len: usize) -> Result<usize, VerifyError> {
    let raw = at as i64 + 1 + insn.off as i64;
    if raw < 0 || raw >= len as i64 { return Err(VerifyError::JumpOutOfBounds); }
    Ok(raw as usize)
}

fn successors(decoded: &[Insn], pseudo: &[bool], at: usize) -> Result<[Option<usize>; 2], VerifyError> {
    let insn = decoded[at];
    if insn.opcode == BPF_OP_EXIT { return Ok([None, None]); }
    if insn.opcode == BPF_LD_IMM_DW {
        return Ok([(at + 2 < decoded.len()).then_some(at + 2), None]);
    }
    let class = insn.opcode & BPF_CLASS_MASK;
    if matches!(class, BPF_JMP | BPF_JMP32) && insn.opcode != BPF_OP_CALL {
        let target = jump_target(at, insn, decoded.len())?;
        if pseudo[target] { return Err(VerifyError::UnsupportedOpcode); }
        if insn.opcode & 0xf0 == 0 { return Ok([Some(target), None]); }
        return Ok([Some(target), (at + 1 < decoded.len()).then_some(at + 1)]);
    }
    Ok([(at + 1 < decoded.len()).then_some(at + 1), None])
}

/// Mark structural CFG reachability independently of verifier-state feasibility.
/// # C: O(instructions + edges)
pub(super) fn reachable(decoded: &[Insn], pseudo: &[bool]) -> Result<Vec<bool>, VerifyError> {
    let mut seen = try_filled_vec(decoded.len(), false)?;
    let mut pending = try_vec(decoded.len())?;
    seen[0] = true;
    pending.push(0);
    while let Some(at) = pending.pop() {
        for next in successors(decoded, pseudo, at)?.into_iter().flatten() {
            if !seen[next] {
                seen[next] = true;
                pending.push(next);
            }
        }
    }
    Ok(seen)
}

fn path_exists(
    decoded: &[Insn],
    pseudo: &[bool],
    start: usize,
    goal: usize,
    avoid: Option<usize>,
    seen: &mut [u32],
    pending: &mut Vec<usize>,
    generation: &mut u32,
) -> Result<bool, VerifyError> {
    if Some(start) == avoid { return Ok(false); }
    *generation = generation.checked_add(1).ok_or(VerifyError::UnsupportedOpcode)?;
    pending.clear();
    seen[start] = *generation;
    pending.push(start);
    let mut steps = 0u64;
    while let Some(at) = pending.pop() {
        if at == goal { return Ok(true); }
        steps += 1;
        if steps > STEP_BUDGET { return Err(VerifyError::UnsupportedOpcode); }
        for next in successors(decoded, pseudo, at)?.into_iter().flatten() {
            if Some(next) != avoid && seen[next] != *generation {
                seen[next] = *generation;
                pending.push(next);
            }
        }
    }
    Ok(false)
}

fn inverse(op: u8) -> Option<u8> {
    Some(match op {
        0x10 => 0x50,
        0x20 => 0xb0,
        0x30 => 0xa0,
        0xa0 => 0x30,
        0xb0 => 0x20,
        _ => return None,
    })
}

fn loop_condition(
    decoded: &[Insn],
    pc: usize,
) -> Result<(Insn, u8, usize), VerifyError> {
    let latch = decoded[pc];
    let class = latch.opcode & BPF_CLASS_MASK;
    if matches!(class, BPF_JMP | BPF_JMP32) && latch.opcode & 0xf0 != 0 {
        if pc == 0 { return Err(VerifyError::UnsupportedOpcode); }
        return Ok((latch, latch.opcode & 0xf0, pc - 1));
    }
    if latch.opcode != 0x05 || pc < 2 { return Err(VerifyError::UnsupportedOpcode); }
    let guard = decoded[pc - 1];
    let guard_class = guard.opcode & BPF_CLASS_MASK;
    let guard_target = jump_target(pc - 1, guard, decoded.len())?;
    if !matches!(guard_class, BPF_JMP | BPF_JMP32)
        || guard.opcode & 0x08 != 0 || guard_target != pc + 1 {
        return Err(VerifyError::UnsupportedOpcode);
    }
    Ok((
        guard,
        inverse(guard.opcode & 0xf0).ok_or(VerifyError::UnsupportedOpcode)?,
        pc - 2,
    ))
}

/// Prove a constant-counter loop, including clang's forward-break plus
/// unconditional-back-edge form used by systemd network programs.
fn loop_cost(decoded: &[Insn], pc: usize, target: usize) -> Result<(u64, usize), VerifyError> {
    if target == 0 || pc < target + 1 { return Err(VerifyError::UnsupportedOpcode); }
    let (condition, op, update_at) = loop_condition(decoded, pc)?;
    if condition.opcode & 0x08 != 0
        || !matches!(op, 0x20 | 0x30 | 0x50 | 0xa0 | 0xb0) {
        return Err(VerifyError::UnsupportedOpcode);
    }
    let counter = condition.dst;
    let update = decoded[update_at];
    let condition_class = condition.opcode & BPF_CLASS_MASK;
    let alu_class = if condition_class == BPF_JMP { ALU64 } else { ALU };
    let init_at = (0..target).rev().find(|at| writes_reg(decoded[*at], counter))
        .ok_or(VerifyError::UnsupportedOpcode)?;
    let init = decoded[init_at];
    if init.opcode != alu_class | 0xb0 || init.dst != counter || init.src != 0 || init.off != 0
        || update.opcode & BPF_CLASS_MASK != alu_class || update.dst != counter
        || update.opcode & 0x08 != 0 || update.src != 0 || update.off != 0
        || !matches!(update.opcode & 0xf0, 0x00 | 0x10) || update.imm <= 0 {
        return Err(VerifyError::UnsupportedOpcode);
    }
    for insn in decoded.iter().take(target).skip(init_at + 1) {
        if matches!(insn.opcode & BPF_CLASS_MASK, BPF_JMP | BPF_JMP32)
            || writes_reg(*insn, counter) {
            return Err(VerifyError::UnsupportedOpcode);
        }
    }
    for (at, insn) in decoded.iter().enumerate().take(update_at).skip(target) {
        if writes_reg(*insn, counter)
            || insn.opcode == BPF_OP_CALL && counter <= 5 {
            return Err(VerifyError::UnsupportedOpcode);
        }
        let class = insn.opcode & BPF_CLASS_MASK;
        if matches!(class, BPF_JMP | BPF_JMP32) && insn.opcode != BPF_OP_CALL {
            let destination = jump_target(at, *insn, decoded.len())?;
            if destination <= at || (destination > update_at && destination <= pc) {
                return Err(VerifyError::UnsupportedOpcode);
            }
        }
    }
    if init.imm < 0 || condition.imm < 0 { return Err(VerifyError::UnsupportedOpcode); }
    let start = init.imm as u64;
    let bound = condition.imm as u64;
    let step = update.imm as u64;
    let add = update.opcode & 0xf0 == 0;
    let iterations = match (add, op) {
        (true, 0xa0) if start < bound => (bound - start).div_ceil(step),
        (true, 0xa0) => 1,
        (true, 0xb0) if start <= bound => (bound - start) / step + 1,
        (true, 0x50) if bound > start && (bound - start) % step == 0 => {
            (bound - start) / step
        }
        (false, 0x20) if start > bound => (start - bound).div_ceil(step),
        (false, 0x30) if start >= bound => (start - bound) / step + 1,
        (false, 0x50) if start > bound && (start - bound) % step == 0 => {
            (start - bound) / step
        }
        _ => return Err(VerifyError::UnsupportedOpcode),
    };
    let travel = iterations.checked_mul(step).ok_or(VerifyError::UnsupportedOpcode)?;
    if !add && travel > start
        || add && condition_class == BPF_JMP32
            && start.checked_add(travel).is_none_or(|value| value > u32::MAX as u64)
        || add && condition_class == BPF_JMP && start.checked_add(travel).is_none() {
        return Err(VerifyError::UnsupportedOpcode);
    }
    let cost = iterations.checked_mul((pc - target + 1) as u64)
        .ok_or(VerifyError::UnsupportedOpcode)?;
    Ok((cost, init_at))
}

/// Validate every jump target and prove each actual backward cycle bounded.
/// A backward edge directly to EXIT is terminating, not a cycle.
/// # C: O(instructions²) cross-edge validation
pub(super) fn validate(decoded: &[Insn], pseudo: &[bool]) -> Result<(), VerifyError> {
    let mut seen = try_filled_vec(decoded.len(), 0u32)?;
    let mut pending = try_vec(decoded.len())?;
    let mut generation = 0u32;
    let mut loop_dispatches = 0u64;
    let mut cross_checks = 0u64;
    for (at, insn) in decoded.iter().enumerate() {
        let class = insn.opcode & BPF_CLASS_MASK;
        if !matches!(class, BPF_JMP | BPF_JMP32)
            || matches!(insn.opcode, BPF_OP_EXIT | BPF_OP_CALL) {
            continue;
        }
        let target = jump_target(at, *insn, decoded.len())?;
        if pseudo[target] { return Err(VerifyError::UnsupportedOpcode); }
        if target > at || !path_exists(
            decoded, pseudo, target, at, None,
            &mut seen, &mut pending, &mut generation,
        )? {
            continue;
        }
        for (src, other) in decoded.iter().enumerate() {
            if cross_checks >= STEP_BUDGET { return Err(VerifyError::UnsupportedOpcode); }
            cross_checks += 1;
            let other_class = other.opcode & BPF_CLASS_MASK;
            if src == at || !matches!(other_class, BPF_JMP | BPF_JMP32)
                || matches!(other.opcode, BPF_OP_EXIT | BPF_OP_CALL) {
                continue;
            }
            let other_target = src as i64 + 1 + other.off as i64;
            if (src < target || src > at)
                && (target as i64..=at as i64).contains(&other_target) {
                return Err(VerifyError::UnsupportedOpcode);
            }
        }
        let (cost, init) = loop_cost(decoded, at, target)?;
        if !path_exists(
            decoded, pseudo, 0, init, None,
            &mut seen, &mut pending, &mut generation,
        )? || path_exists(
            decoded, pseudo, 0, target, Some(init),
            &mut seen, &mut pending, &mut generation,
        )? || path_exists(
            decoded, pseudo, 0, at, Some(init),
            &mut seen, &mut pending, &mut generation,
        )? {
            return Err(VerifyError::UnsupportedOpcode);
        }
        loop_dispatches = loop_dispatches.checked_add(cost)
            .ok_or(VerifyError::UnsupportedOpcode)?;
    }
    if loop_dispatches.checked_add(decoded.len() as u64)
        .is_none_or(|count| count > STEP_BUDGET) {
        return Err(VerifyError::UnsupportedOpcode);
    }
    Ok(())
}
