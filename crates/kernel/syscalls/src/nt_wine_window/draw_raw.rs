//! Raw curved and multi-run drawing ingress.

/// Draw an arc by centre, radius and swept angle.
pub(crate) const ANGLE_ARC: u64 = 0x108d;
/// Draw one of the four arc forms.
pub(crate) const ARC_INTERNAL: u64 = 0x108f;
/// Draw the ellipse inscribed in a rectangle.
pub(crate) const ELLIPSE: u64 = 0x1199;
/// Draw a rounded rectangle.
pub(crate) const ROUND_RECT: u64 = 0x1260;
/// Draw a typed run of lines and curves.
pub(crate) const POLY_DRAW: u64 = 0x124f;
/// Draw several point runs at once.
pub(crate) const POLY_POLY_DRAW: u64 = 0x1251;

const CALLS: &[(u64, usize)] = &[
    (ANGLE_ARC, 6), (ARC_INTERNAL, 10), (ELLIPSE, 5), (POLY_DRAW, 4), (POLY_POLY_DRAW, 5), (ROUND_RECT, 7),
];

/// # C: O(N_family_ordinals)
pub(crate) fn argument_count(ordinal: u64) -> Option<usize> {
    CALLS.iter().find(|entry| entry.0 == ordinal).map(|entry| entry.1)
}

/// The longest signature this family carries.
pub(crate) const MAX_ARGUMENTS: usize = 10;
/// A point run longer than this is refused rather than copied.
pub(crate) const MAX_POINTS: u64 = 65536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Bounds { pub left: i32, pub top: i32, pub right: i32, pub bottom: i32 }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Call {
    AngleArc { dc: u32, x: i32, y: i32, radius: i32, start_bits: u32, sweep_bits: u32 },
    ArcInternal { dc: u32, kind: u32, bounds: Bounds, start: (i32, i32), end: (i32, i32) },
    Ellipse { dc: u32, bounds: Bounds },
    RoundRect { dc: u32, bounds: Bounds, ellipse: (i32, i32) },
    PolyDraw { dc: u32, points: u64, types: u64, count: u32 },
    PolyPolyDraw { dc: u32, points: u64, counts: u64, runs: u32, function: u32 },
}

/// # C: O(N_family_ordinals)
pub(crate) fn route(ordinal: u64, args: &[u64], execute: impl FnOnce(Call) -> u64) -> Option<u64> {
    argument_count(ordinal)?;
    Some(match decode(ordinal, args) { Some(call) => execute(call), None => 0 })
}

/// The arc form is the first argument and the device context the second, which
/// is the one call in this family that does not lead with its handle. # C: O(1)
pub(crate) fn decode(ordinal: u64, args: &[u64]) -> Option<Call> {
    let dc = |index: usize| args.get(index).copied().and_then(|value| u32::try_from(value).ok());
    let signed = |index: usize| args.get(index).map(|value| *value as u32 as i32);
    let bounds = |base: usize| Some(Bounds { left: signed(base)?, top: signed(base + 1)?,
        right: signed(base + 2)?, bottom: signed(base + 3)? });
    Some(match ordinal {
        ANGLE_ARC => Call::AngleArc { dc: dc(0)?, x: signed(1)?, y: signed(2)?, radius: signed(3)?,
            start_bits: *args.get(4)? as u32, sweep_bits: *args.get(5)? as u32 },
        ARC_INTERNAL => Call::ArcInternal { kind: *args.get(0)? as u32, dc: dc(1)?, bounds: bounds(2)?,
            start: (signed(6)?, signed(7)?), end: (signed(8)?, signed(9)?) },
        ELLIPSE => Call::Ellipse { dc: dc(0)?, bounds: bounds(1)? },
        ROUND_RECT => Call::RoundRect { dc: dc(0)?, bounds: bounds(1)?, ellipse: (signed(5)?, signed(6)?) },
        POLY_DRAW => {
            let count = *args.get(3)?;
            if count > MAX_POINTS { return None; }
            Call::PolyDraw { dc: dc(0)?, points: *args.get(1)?, types: *args.get(2)?, count: count as u32 }
        }
        POLY_POLY_DRAW => {
            let runs = *args.get(3)?;
            if runs > MAX_POINTS { return None; }
            Call::PolyPolyDraw { dc: dc(0)?, points: *args.get(1)?, counts: *args.get(2)?,
                runs: runs as u32, function: *args.get(4)? as u32 }
        }
        _ => return None,
    })
}

#[cfg(target_os = "oxide-kernel")]
#[path = "draw_raw/kernel.rs"]
pub(crate) mod kernel;

#[cfg(test)]
#[path = "tests/draw_raw.rs"]
mod tests;
