//! Typed raw brush ingress; canonical owner performs selection and raster work.
pub(crate) const CREATE_SOLID_BRUSH: u64 = 0x10bf;
pub(crate) const SELECT_BRUSH: u64 = 0x126c;
pub(crate) const PAT_BLT: u64 = 0x124c;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Operation {
    CreateSolid { color: u32 },
    Select { dc: u64, brush: u64 },
    PatBlt { dc: u64, x: i32, y: i32, width: i32, height: i32, rop: u32 },
}

/// Decode 32-bit scalar arguments independently of register high halves. # C: O(1)
pub(crate) fn decode(ordinal: u64, args: &[u64]) -> Option<Operation> {
    Some(match ordinal {
        CREATE_SOLID_BRUSH if args.len() >= 2 => Operation::CreateSolid { color: args[0] as u32 },
        SELECT_BRUSH if args.len() >= 2 => Operation::Select { dc: args[0], brush: args[1] },
        PAT_BLT if args.len() >= 6 => Operation::PatBlt { dc: args[0], x: args[1] as i32, y: args[2] as i32, width: args[3] as i32, height: args[4] as i32, rop: args[5] as u32 },
        _ => return None,
    })
}

#[cfg(target_os = "oxide-kernel")]
#[path = "brush_raw/kernel.rs"]
pub(super) mod kernel;

#[cfg(test)]
#[path = "brush_raw/tests.rs"]
mod tests;
