//! Bounded DWARF CFA evaluation for the NT builtin-unwind runtime.

use crate::dwarf::{sleb128, uleb128, DwarfError};

const REGISTER_COUNT: usize = 17;
const RIP: usize = 16;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CfaContext {
    /// DWARF x86-64 integer registers 0..16 (RAX..RIP), in Wine's order.
    pub registers: [u64; REGISTER_COUNT],
    pub cfa: u64,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Rule { Same, Undefined, Offset(i64) }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct State { cfa_register: usize, cfa_offset: i64, rules: [Rule; REGISTER_COUNT] }

/// Apply call-frame instructions through `target_delta` and recover registers
/// with the supplied bounded stack reader. The closure is invoked only for
/// addresses derived from the computed CFA; it is never used for metadata.
pub fn evaluate<F>(program: &[u8], initial: CfaContext, code_align: u64,
    data_align: i64, target_delta: u64, mut read_word: F) -> Result<CfaContext, DwarfError>
where F: FnMut(u64) -> Option<u64> {
    if code_align == 0 { return Err(DwarfError::InvalidRecord); }
    let mut state = State { cfa_register: 7, cfa_offset: 0, rules: [Rule::Same; REGISTER_COUNT] };
    let mut pc = 0u64;
    let mut cursor = 0;
    let mut saved = [state; 4];
    let mut saved_count = 0usize;
    while cursor < program.len() {
        let op = program[cursor]; cursor += 1;
        let kind = op & 0xc0;
        if kind == 0x40 {
            let delta = (op & 0x3f) as u64 * code_align;
            if pc.checked_add(delta).ok_or(DwarfError::Overflow)? > target_delta { break; }
            pc += delta; continue;
        }
        if kind == 0x80 {
            let reg = (op & 0x3f) as usize;
            let (value, used) = uleb128(&program[cursor..])?; cursor += used;
            if reg >= REGISTER_COUNT { return Err(DwarfError::InvalidRecord); }
            state.rules[reg] = Rule::Offset((value as i64).checked_mul(data_align).ok_or(DwarfError::Overflow)?);
            continue;
        }
        if kind == 0xc0 {
            let reg = (op & 0x3f) as usize;
            if reg >= REGISTER_COUNT { return Err(DwarfError::InvalidRecord); }
            state.rules[reg] = Rule::Same; continue;
        }
        match op {
            0x00 | 0x02..=0x04 => {
                let delta = match op { 0 => 0, 2 => program.get(cursor).copied().ok_or(DwarfError::Truncated)? as u64,
                    3 => { let v = program.get(cursor..cursor + 2).ok_or(DwarfError::Truncated)?;
                        u16::from_le_bytes([v[0], v[1]]) as u64 },
                    _ => { let v = program.get(cursor..cursor + 4).ok_or(DwarfError::Truncated)?;
                        u32::from_le_bytes([v[0], v[1], v[2], v[3]]) as u64 } } * code_align;
                cursor += match op { 0 => 0, 2 => 1, 3 => 2, _ => 4 };
                if pc.checked_add(delta).ok_or(DwarfError::Overflow)? > target_delta { break; }
                pc += delta;
            }
            0x05 | 0x11 => { let (reg, used) = uleb128(&program[cursor..])?; cursor += used;
                let (offset, used) = if op == 0x05 { let (v, n) = uleb128(&program[cursor..])?; (v as i64, n) }
                    else { sleb128(&program[cursor..])? }; cursor += used;
                if reg as usize >= REGISTER_COUNT { return Err(DwarfError::InvalidRecord); }
                state.rules[reg as usize] = Rule::Offset(offset.checked_mul(data_align).ok_or(DwarfError::Overflow)?); }
            0x07 | 0x08 => { let (reg, used) = uleb128(&program[cursor..])?; cursor += used;
                if reg as usize >= REGISTER_COUNT { return Err(DwarfError::InvalidRecord); }
                state.rules[reg as usize] = if op == 7 { Rule::Undefined } else { Rule::Same }; }
            0x0a => { if saved_count == saved.len() { return Err(DwarfError::InvalidRecord); }
                saved[saved_count] = state; saved_count += 1; }
            0x0b => { if saved_count == 0 { return Err(DwarfError::InvalidRecord); }
                saved_count -= 1; state = saved[saved_count]; }
            0x0c => { let (reg, used) = uleb128(&program[cursor..])?; cursor += used;
                let (offset, used) = uleb128(&program[cursor..])?; cursor += used;
                if reg as usize >= REGISTER_COUNT { return Err(DwarfError::InvalidRecord); }
                state.cfa_register = reg as usize; state.cfa_offset = offset as i64; }
            0x0d => { let (reg, used) = uleb128(&program[cursor..])?; cursor += used;
                if reg as usize >= REGISTER_COUNT { return Err(DwarfError::InvalidRecord); }
                state.cfa_register = reg as usize; }
            0x0e => { let (offset, used) = uleb128(&program[cursor..])?; cursor += used; state.cfa_offset = offset as i64; }
            0x0f | 0x10 | 0x12..=0x16 => return Err(DwarfError::UnsupportedEncoding),
            0x01 | 0x06 | 0x09 => return Err(DwarfError::UnsupportedEncoding),
            _ => return Err(DwarfError::InvalidRecord),
        }
    }
    let cfa_base = initial.registers.get(state.cfa_register).copied().ok_or(DwarfError::InvalidRecord)?;
    let cfa = add_signed(cfa_base, state.cfa_offset)?;
    let mut result = initial; result.cfa = cfa;
    for (reg, rule) in state.rules.iter().enumerate() {
        result.registers[reg] = match *rule {
            Rule::Same => initial.registers[reg], Rule::Undefined => 0,
            Rule::Offset(offset) => read_word(add_signed(cfa, offset)?).ok_or(DwarfError::Truncated)?,
        };
    }
    if matches!(state.rules[RIP], Rule::Undefined) { return Err(DwarfError::InvalidRecord); }
    Ok(result)
}

/// Execute a validated Wine CIE+FDE program against one register context.
/// The reader remains owned by the caller so process-memory validation cannot
/// be bypassed by the shared format layer.
pub fn evaluate_frame<F>(program: &crate::dwarf::FrameProgram, initial: CfaContext,
    target_delta: u64, read_word: F) -> Result<CfaContext, DwarfError>
where F: FnMut(u64) -> Option<u64> {
    evaluate(&program.instructions, initial, program.code_align, program.data_align,
        target_delta, read_word)
}

fn add_signed(base: u64, offset: i64) -> Result<u64, DwarfError> {
    if offset >= 0 { base.checked_add(offset as u64).ok_or(DwarfError::Overflow) }
    else { base.checked_sub(offset.unsigned_abs()).ok_or(DwarfError::Overflow) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovers_return_ip_from_cfa_offset() {
        let initial = CfaContext { registers: [0; REGISTER_COUNT], cfa: 0 };
        let mut regs = initial.registers; regs[7] = 0x8000;
        let initial = CfaContext { registers: regs, cfa: 0 };
        let result = evaluate(&[0x0c, 7, 8, 0x90, 1], initial, 1, -8, 0,
            |address| (address == 0x8000).then_some(0x401234)).unwrap();
        assert_eq!(result.cfa, 0x8008); assert_eq!(result.registers[RIP], 0x401234);
    }

    #[test]
    fn rejects_unreadable_saved_return_ip() {
        let mut registers = [0; REGISTER_COUNT]; registers[7] = 0x1000;
        assert_eq!(evaluate(&[0x0c, 7, 8, 0x90, 1], CfaContext { registers, cfa: 0 }, 1, -8, 0, |_| None),
            Err(DwarfError::Truncated));
    }

    #[test]
    fn rejects_expression_rules() {
        let initial = CfaContext { registers: [0; REGISTER_COUNT], cfa: 0 };
        assert_eq!(evaluate(&[0x0f], initial, 1, -8, 0, |_| None), Err(DwarfError::UnsupportedEncoding));
    }

    #[test]
    fn executes_a_validated_cie_fde_program() {
        let mut registers = [0; REGISTER_COUNT];
        registers[7] = 0x9000;
        let program = crate::dwarf::FrameProgram {
            code_align: 1, data_align: -8,
            instructions: alloc::vec![0x0c, 7, 8, 0x90, 1],
        };
        let result = evaluate_frame(&program, CfaContext { registers, cfa: 0 }, 0,
            |address| (address == 0x9000).then_some(0xfeed_face)).unwrap();
        assert_eq!(result.cfa, 0x9008);
        assert_eq!(result.registers[RIP], 0xfeed_face);
    }
}
