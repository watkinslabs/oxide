//! Raw and descriptor GDI calls share typed decoding and canonical execution.
#[cfg(target_os = "oxide-kernel")]
use super::gdi_raw;
#[cfg(not(target_os = "oxide-kernel"))]
use crate::nt_wine_gdi_contract as gdi_raw;
#[cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;

#[cfg(target_os = "oxide-kernel")]
pub(super) fn descriptor(ordinal: u64, args: &[u64; 17]) -> Option<u64> {
    let mut packed = [0; 9];
    packed.copy_from_slice(&args[..9]);
    gdi_raw::decode(ordinal, &packed).map(gdi_raw::kernel::dispatch)
}

#[cfg(target_os = "oxide-kernel")]
pub(super) fn raw(ordinal: u64, args: SyscallArgs) -> Option<u64> {
    collect(ordinal, [args.a0, args.a1, args.a2, args.a3, args.a4, args.a5], crate::nt_dispatch::stack_argument)
        .map(|operation| operation.map(gdi_raw::kernel::dispatch).unwrap_or(0))
}

fn collect(ordinal: u64, first: [u64; 6], mut stack: impl FnMut(usize) -> Option<u64>)
    -> Option<Result<gdi_raw::Operation, ()>> {
    let mut packed = [0; 9];
    packed[..6].copy_from_slice(&first);
    // Admission must precede usercopy; unrelated User32 calls have different tails.
    gdi_raw::decode(ordinal, &packed)?;
    let count = match ordinal {
        gdi_raw::EXT_TEXT_OUT_W => 9,
        gdi_raw::GET_TEXT_EXTENT_EX_W => 8,
        _ => 6,
    };
    for (index, value) in packed.iter_mut().enumerate().take(count).skip(6) {
        let Some(argument) = stack(index) else { return Some(Err(())); };
        *value = argument;
    }
    gdi_raw::decode(ordinal, &packed).map(Ok)
}

#[cfg(test)]
#[path = "tests/gdi_route.rs"]
mod tests;
