//! Raw mapping and world-transform ingress.
//!
//! Decoding only. Point runs and matrices are named by address; the kernel
//! binding copies them once the ordinal is admitted.

/// Read one of the four coordinate-space transforms.
pub(crate) const GET_TRANSFORM: u64 = 0x122a;
/// Change the world transform.
pub(crate) const MODIFY_WORLD_TRANSFORM: u64 = 0x1241;
/// Map a point run between logical and device space.
pub(crate) const TRANSFORM_POINTS: u64 = 0x1294;
/// Rebuild the mapping coefficients.
pub(crate) const COMPUTE_XFORM_COEFFICIENTS: u64 = 0x10a4;
/// Scale the viewport extent.
pub(crate) const SCALE_VIEWPORT_EXT: u64 = 0x1269;
/// Scale the window extent.
pub(crate) const SCALE_WINDOW_EXT: u64 = 0x126a;
/// Override the resolution and physical size the mapping modes read.
pub(crate) const SET_VIRTUAL_RESOLUTION: u64 = 0x128c;

const CALLS: &[(u64, usize)] = &[
    (COMPUTE_XFORM_COEFFICIENTS, 1), (GET_TRANSFORM, 3), (MODIFY_WORLD_TRANSFORM, 3),
    (SCALE_VIEWPORT_EXT, 6), (SCALE_WINDOW_EXT, 6), (SET_VIRTUAL_RESOLUTION, 5), (TRANSFORM_POINTS, 5),
];

/// # C: O(N_family_ordinals)
pub(crate) fn argument_count(ordinal: u64) -> Option<usize> {
    CALLS.iter().find(|entry| entry.0 == ordinal).map(|entry| entry.1)
}

/// The longest signature this family carries.
pub(crate) const MAX_ARGUMENTS: usize = 6;
/// A point run longer than this is refused rather than copied.
pub(crate) const MAX_POINTS: i32 = 65536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Call {
    GetTransform { dc: u32, which: u32, xform: u64 },
    ModifyWorldTransform { dc: u32, xform: u64, mode: u32 },
    TransformPoints { dc: u32, input: u64, output: u64, count: i32, mode: u32 },
    ComputeXformCoefficients { dc: u32 },
    ScaleExt { dc: u32, viewport: bool, ratio: [i32; 4], size: u64 },
    SetVirtualResolution { dc: u32, res: (i32, i32), size: (i32, i32) },
}

/// # C: O(N_family_ordinals)
pub(crate) fn route(ordinal: u64, args: &[u64], execute: impl FnOnce(Call) -> u64) -> Option<u64> {
    argument_count(ordinal)?;
    Some(match decode(ordinal, args) { Some(call) => execute(call), None => 0 })
}

/// # C: O(1)
pub(crate) fn decode(ordinal: u64, args: &[u64]) -> Option<Call> {
    let dc = |index: usize| args.get(index).copied().and_then(|value| u32::try_from(value).ok());
    let signed = |index: usize| args.get(index).map(|value| *value as u32 as i32);
    Some(match ordinal {
        GET_TRANSFORM => Call::GetTransform { dc: dc(0)?, which: *args.get(1)? as u32, xform: *args.get(2)? },
        MODIFY_WORLD_TRANSFORM => Call::ModifyWorldTransform { dc: dc(0)?, xform: *args.get(1)?, mode: *args.get(2)? as u32 },
        TRANSFORM_POINTS => {
            let count = signed(3)?;
            if !(0..=MAX_POINTS).contains(&count) { return None; }
            Call::TransformPoints { dc: dc(0)?, input: *args.get(1)?, output: *args.get(2)?, count, mode: *args.get(4)? as u32 }
        }
        COMPUTE_XFORM_COEFFICIENTS => Call::ComputeXformCoefficients { dc: dc(0)? },
        SCALE_VIEWPORT_EXT | SCALE_WINDOW_EXT => Call::ScaleExt { dc: dc(0)?,
            viewport: ordinal == SCALE_VIEWPORT_EXT,
            ratio: [signed(1)?, signed(2)?, signed(3)?, signed(4)?], size: *args.get(5)? },
        SET_VIRTUAL_RESOLUTION => Call::SetVirtualResolution { dc: dc(0)?,
            res: (signed(1)?, signed(2)?), size: (signed(3)?, signed(4)?) },
        _ => return None,
    })
}

#[cfg(target_os = "oxide-kernel")]
#[path = "xform_raw/kernel.rs"]
pub(crate) mod kernel;

#[cfg(test)]
#[path = "tests/xform_raw.rs"]
mod tests;
