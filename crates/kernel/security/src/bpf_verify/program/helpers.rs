//! Helper-call argument contracts, one entry per helper the runner owns.
//!
//! A helper is admitted for a program type only when that type's proto
//! table names it AND the interpreter has an implementation, so a verified
//! call can never reach a missing helper at run time.

use vfs::InodeRef;

use super::super::{Insn, VerifyError};
use super::limits::{MAX_ERRNO, Scalar};
use super::state::{Kind, State, map_at, mark_stack, range, scalar, stack_ready};
use crate::bpf::uapi;

/// Helpers reachable from every program type this kernel loads: the shared
/// base proto set.
fn base_proto(func: u32) -> bool {
    matches!(func, uapi::func_id::MAP_LOOKUP_ELEM | uapi::func_id::KTIME_GET_COARSE_NS)
}

/// Whether `func` is in this program type's proto table. # C: O(1)
fn in_proto(prog_type: u32, func: u32) -> bool {
    use uapi::prog_type as p;
    if base_proto(func) { return true; }
    match func {
        uapi::func_id::SKB_LOAD_BYTES =>
            matches!(prog_type, p::SOCKET_FILTER | p::CGROUP_SKB),
        uapi::func_id::GET_RETVAL | uapi::func_id::SET_RETVAL =>
            prog_type == p::CGROUP_SOCK_ADDR,
        _ => false,
    }
}

/// Type-check one helper call and install its result in R0, clobbering the
/// argument registers the calling convention does not preserve.
/// # C: O(helper argument count)
pub(super) fn verify_helper(
    prog_type: u32,
    insn: Insn,
    state: &mut State,
    maps: &[InodeRef],
) -> Result<(), VerifyError> {
    if insn.dst != 0 || insn.src != 0 || insn.off != 0 {
        return Err(VerifyError::UnsupportedOpcode);
    }
    let func = insn.imm as u32;
    if !in_proto(prog_type, func) { return Err(VerifyError::UnsupportedOpcode); }
    let result = match func {
        uapi::func_id::MAP_LOOKUP_ELEM => map_lookup(state, maps)?,
        uapi::func_id::KTIME_GET_COARSE_NS => Kind::Scalar(Scalar::unknown()),
        uapi::func_id::SKB_LOAD_BYTES => skb_load_bytes(state)?,
        uapi::func_id::GET_RETVAL => Kind::Scalar(Scalar::range(-MAX_ERRNO, 0)),
        uapi::func_id::SET_RETVAL => {
            if !scalar(state.regs[1])?.i32_within(-(MAX_ERRNO as i32), 0) {
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

/// R1 must be a map, R2 an initialized stack slice at least `key_size`
/// wide; the result is a nullable pointer into that map's value.
fn map_lookup(state: &State, maps: &[InodeRef]) -> Result<Kind, VerifyError> {
    let Kind::Map(map) = state.regs[1] else {
        return Err(VerifyError::UnsupportedOpcode);
    };
    let object = map_at(maps, map)?;
    let Kind::Stack(base) = state.regs[2] else {
        return Err(VerifyError::UnsafeStackAccess);
    };
    let key = object.key_size as usize;
    let start = range(base, 0, key, crate::bpf_interp::STACK_BYTES)?;
    if !stack_ready(state, start, key) { return Err(VerifyError::UninitializedStack); }
    Ok(Kind::Value { map, offset: 0, nullable: true })
}

/// R1 context, R2 constant packet offset, R3 stack destination, R4 constant
/// length; the destination becomes initialized whether or not the copy
/// faults, because the runner clears it first.
fn skb_load_bytes(state: &mut State) -> Result<Kind, VerifyError> {
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
    Ok(Kind::Scalar(Scalar::range(
        -(syscall::errno::Errno::Efault.as_i32() as i64), 0,
    )))
}
