//! Register/stack abstract state for the path-sensitive program verifier.

use alloc::vec::Vec;

use vfs::InodeRef;

use super::super::{Insn, VerifyError, BPF_LD_IMM_DW, try_filled_vec};
use super::limits::Scalar;
use crate::bpf::{BpfMapInode, uapi};

/// Abstract value of one register. Mirrors the pointer domains the runner
/// can actually resolve: the program context, the frame-pointer stack, a
/// relocated map object, and a map value (nullable until compared).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) enum Kind {
    Uninit,
    Scalar(Scalar),
    Context(i32),
    Stack(i32),
    Map(usize),
    Value { map: usize, offset: i32, nullable: bool },
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub(super) struct State {
    pub(super) regs: [Kind; 11],
    pub(super) stack: [u64; 8],
}

impl State {
    /// Entry state: R1 holds the context pointer, R10 the frame pointer,
    /// every other register is unreadable until written. # C: O(1)
    pub(super) fn entry() -> Self {
        let mut regs = [Kind::Uninit; 11];
        regs[1] = Kind::Context(0);
        regs[10] = Kind::Stack(crate::bpf_interp::STACK_BYTES as i32);
        Self { regs, stack: [0; 8] }
    }
}

/// # C: O(1)
pub(super) fn scalar(kind: Kind) -> Result<Scalar, VerifyError> {
    match kind {
        Kind::Scalar(value) => Ok(value),
        Kind::Uninit => Err(VerifyError::UninitializedReg),
        _ => Err(VerifyError::UnsupportedOpcode),
    }
}

/// Fold a base pointer offset and an instruction offset into an in-bounds
/// byte range, or reject. # C: O(1)
pub(super) fn range(base: i32, offset: i16, size: usize, limit: usize)
    -> Result<usize, VerifyError>
{
    let start = base.checked_add(offset as i32).ok_or(VerifyError::UnsafeStackAccess)?;
    if start < 0 || (start as usize).checked_add(size).is_none_or(|end| end > limit) {
        return Err(VerifyError::UnsafeStackAccess);
    }
    Ok(start as usize)
}

/// # C: O(size)
pub(super) fn stack_ready(state: &State, start: usize, size: usize) -> bool {
    (start..start + size).all(|byte| state.stack[byte / 64] & (1 << (byte % 64)) != 0)
}

/// # C: O(size)
pub(super) fn mark_stack(state: &mut State, start: usize, size: usize) {
    for byte in start..start + size { state.stack[byte / 64] |= 1 << (byte % 64); }
}

/// Access width encoded in a MEM opcode's size field. # C: O(1)
pub(super) fn memory_size(opcode: u8) -> Option<usize> {
    Some(match (opcode >> 3) & 3 {
        0 => 4,
        1 => 2,
        2 => 1,
        3 => 8,
        _ => return None,
    })
}

/// # C: O(1)
pub(super) fn map_at(maps: &[InodeRef], index: usize) -> Result<&BpfMapInode, VerifyError> {
    maps.get(index).and_then(|inode| inode.private::<BpfMapInode>())
        .ok_or(VerifyError::UnsupportedOpcode)
}

/// Bound and permission check for one access inside a map value.
/// A map created read-only-from-program refuses a store, and one created
/// write-only-from-program refuses a load. # C: O(1)
pub(super) fn value_range(
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

/// Mark the second slot of every wide load and validate its relocation
/// against the program's map set. # C: O(instructions)
pub(super) fn wide_slots(decoded: &[Insn], maps: &[InodeRef]) -> Result<Vec<bool>, VerifyError> {
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
    super::super::loops::validate(decoded, &pseudo)?;
    Ok(pseudo)
}
