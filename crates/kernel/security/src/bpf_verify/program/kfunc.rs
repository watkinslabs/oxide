//! Kernel-function call contracts admitted by the interpreter.

use vfs::InodeRef;

use super::super::{Insn, VerifyError};
use super::limits::{MAX_ERRNO, Scalar};
use super::state::{Kind, State, map_at, range, scalar, stack_ready, value_range};
use crate::bpf::StreamKfunc;

const MAX_ARGS_BYTES: usize = 12 * 8;

/// Type-check one `BPF_PSEUDO_KFUNC_CALL`. # C: O(argument count)
pub(super) fn verify(
    insn: Insn,
    state: &mut State,
    maps: &[InodeRef],
) -> Result<(), VerifyError> {
    if insn.dst != 0 || insn.off != 0 { return Err(VerifyError::UnsupportedOpcode); }
    let kfunc = crate::bpf::stream_kfunc_by_btf_id(insn.imm as u32)
        .ok_or(VerifyError::UnsupportedOpcode)?;
    match kfunc {
        StreamKfunc::Vprintk => verify_vprintk(state, maps)?,
    }
    state.regs[1..=5].fill(Kind::Uninit);
    state.regs[0] = Kind::Scalar(Scalar::range(-MAX_ERRNO, 0));
    Ok(())
}

fn verify_vprintk(state: &State, maps: &[InodeRef]) -> Result<(), VerifyError> {
    let stream = scalar(state.regs[1])?;
    if stream.value().is_some_and(|id| !matches!(id, 1 | 2)) {
        return Err(VerifyError::UnsupportedOpcode);
    }
    const_string(maps, state.regs[2])?;
    let len = scalar(state.regs[4])?.value()
        .and_then(|v| usize::try_from(v).ok())
        .ok_or(VerifyError::UnsupportedOpcode)?;
    if len % 8 != 0 || len > MAX_ARGS_BYTES { return Err(VerifyError::UnsupportedOpcode); }
    if len != 0 { readable(state, maps, state.regs[3], len)?; }
    Ok(())
}

fn const_string(maps: &[InodeRef], kind: Kind) -> Result<(), VerifyError> {
    let Kind::Value { map, offset, nullable: false } = kind else {
        return Err(VerifyError::UnsupportedOpcode);
    };
    let object = map_at(maps, map)?;
    if object.map_flags & crate::bpf::uapi::map_flags::RDONLY_PROG == 0
        || !object.storage.frozen() || offset < 0 {
        return Err(VerifyError::UnsupportedOpcode);
    }
    let value = object.array_value(0).ok_or(VerifyError::UnsupportedOpcode)?;
    let bytes = value.copy_out().map_err(|_| VerifyError::UnsupportedOpcode)?;
    let bytes = bytes.get(offset as usize..).ok_or(VerifyError::UnsafeContextAccess)?;
    if !bytes.contains(&0) { return Err(VerifyError::UnsupportedOpcode); }
    Ok(())
}

fn readable(state: &State, maps: &[InodeRef], kind: Kind, size: usize)
    -> Result<(), VerifyError>
{
    match kind {
        Kind::Stack(base) => {
            let start = range(base, 0, size, crate::bpf_interp::STACK_BYTES)?;
            if !stack_ready(state, start, size) { return Err(VerifyError::UninitializedStack); }
            Ok(())
        }
        Kind::Value { map, offset, nullable: false } =>
            value_range(maps, map, offset, 0, size, true, false),
        _ => Err(VerifyError::UnsupportedOpcode),
    }
}
