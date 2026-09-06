//! Typed raw DC clip requests; geometry belongs to the canonical DC owner.
pub(crate) const INTERSECT_CLIP_RECT: u64 = 0x1238;
pub(crate) const GET_APP_CLIP_BOX: u64 = 0x11db;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Operation {
    Intersect { dc: u64, left: i32, top: i32, right: i32, bottom: i32 },
    GetBox { dc: u64, output: u64 },
}

/// Signed rectangle coordinates occupy the low 32 bits of raw arguments. # C: O(1)
pub(crate) fn decode(ordinal: u64, args: &[u64]) -> Option<Operation> {
    Some(match ordinal {
        INTERSECT_CLIP_RECT if args.len() >= 5 => Operation::Intersect { dc: args[0], left: args[1] as i32,
            top: args[2] as i32, right: args[3] as i32, bottom: args[4] as i32 },
        GET_APP_CLIP_BOX if args.len() >= 2 => Operation::GetBox { dc: args[0], output: args[1] },
        _ => return None,
    })
}

#[cfg(target_os = "oxide-kernel")]
#[path = "clip_raw/kernel.rs"]
pub(super) mod kernel;

#[cfg(test)]
#[path = "clip_raw/tests.rs"]
mod tests;
