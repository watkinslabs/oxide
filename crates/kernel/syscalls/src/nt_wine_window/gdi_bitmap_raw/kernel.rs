//! Usercopy and owner calls for the bitmap, blit, pixel and palette ordinals.
//! Module manifest: `objects.rs` owns creation and palette entry transfer;
//! `raster.rs` owns the blits, pixels and device-independent transfers.
use syscall::SyscallArgs;
use super::{Operation, collect, decode};
#[path = "kernel/objects.rs"]
mod objects;
#[path = "kernel/raster.rs"]
mod raster;
#[path = "kernel/dib.rs"]
mod dib;

/// Handle-returning calls answer NULL on failure and boolean ones zero; no
/// status code reaches a Windows caller. # C: owner cost plus bounded usercopy
pub(crate) fn route(ordinal: u64, args: SyscallArgs) -> Option<u64> {
    let collected = collect(ordinal, [args.a0, args.a1, args.a2, args.a3, args.a4, args.a5],
        crate::nt_dispatch::stack_argument)?;
    let Ok(collected) = collected else { return Some(0); };
    let operation = decode(ordinal, &collected)?;
    Some(dispatch(operation))
}

/// Descriptor ingress: the argument array already holds the whole logical
/// list. # C: owner cost plus bounded usercopy
pub(crate) fn descriptor(ordinal: u64, args: &[u64]) -> Option<u64> {
    Some(dispatch(decode(ordinal, args)?))
}

fn dispatch(operation: Operation) -> u64 {
    match operation {
        Operation::CreateCompatibleBitmap { .. } | Operation::CreateHatchBrush { .. }
        | Operation::CreatePalette { .. } | Operation::CreateHalftonePalette
        | Operation::SelectBitmap { .. } | Operation::SelectPalette { .. }
        | Operation::RealizePalette { .. } | Operation::UnrealizeObject { .. }
        | Operation::DoPalette { .. } | Operation::ResizePalette { .. }
        | Operation::GetNearestColor { .. } | Operation::GetNearestPaletteIndex { .. }
        | Operation::GetSystemPaletteUse | Operation::SetSystemPaletteUse { .. }
        | Operation::UpdateColors { .. } | Operation::GetBitmapBits { .. }
        | Operation::SetBitmapBits { .. } | Operation::GetBitmapDimension { .. }
        | Operation::SetBitmapDimension { .. } | Operation::IcmBrushInfo { .. }
        | Operation::DrawStream | Operation::SetMagicColors => objects::dispatch(operation),
        Operation::CreateDibSection { .. } | Operation::CreateDibitmap { .. }
        | Operation::CreateDibBrush { .. } | Operation::GetDiBits { .. }
        | Operation::SetDiBitsToDevice { .. } | Operation::StretchDiBits { .. } => dib::dispatch(operation),
        _ => raster::dispatch(operation),
    }
}
