//! Fixed clock, fixed-factor clock, and fixed-regulator provider decoder.

extern crate alloc;

use alloc::vec::Vec;

use crate::header::read_be_u32;
use crate::opp::ClockReference;
use crate::props::contains_string;
use crate::walk::{walk, Event, Flow};

/// One immutable clock output a DT consumer can name.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct FixedClock { pub phandle: u32, pub rate_hz: u64 }

/// One immutable ratio derived from one parent clock output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixedFactorClock { pub phandle: u32, pub parent: ClockReference, pub mult: u32, pub div: u32 }

/// One immutable regulator a DT consumer can name.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct FixedRegulator { pub phandle: u32, pub voltage_uv: u32 }

/// All complete fixed providers in one device tree.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FixedProviders {
    pub clocks: Vec<FixedClock>,
    pub factors: Vec<FixedFactorClock>,
    pub regulators: Vec<FixedRegulator>,
}

struct RawFactor { phandle: u32, parent: Vec<u8>, mult: u32, div: u32 }

struct Frame {
    depth: u32,
    enabled: bool,
    fixed_clock: bool,
    fixed_factor: bool,
    fixed_regulator: bool,
    phandle: Option<u32>,
    clock_cells: Option<u32>,
    parent: Option<Vec<u8>>,
    mult: Option<u32>,
    div: Option<u32>,
    rate_hz: Option<u64>,
    min_uv: Option<u32>,
    max_uv: Option<u32>,
}

impl Frame {
    fn new(depth: u32, enabled: bool) -> Self {
        Self {
            depth, enabled, fixed_clock: false, fixed_factor: false, fixed_regulator: false,
            phandle: None, clock_cells: None, parent: None, mult: None, div: None,
            rate_hz: None, min_uv: None, max_uv: None,
        }
    }
}

/// Decode complete `fixed-clock`, `fixed-factor-clock`, and `regulator-fixed` nodes. Incomplete,
/// disabled, or duplicate-phandle declarations are not published. # C: O(struct_block_size)
pub fn fixed_providers(bytes: &[u8]) -> FixedProviders {
    let mut frames: Vec<Frame> = Vec::new();
    let mut providers = FixedProviders::default();
    let mut raw_factors = Vec::new();
    let mut clock_cells = Vec::new();
    let mut duplicate = false;
    if walk(bytes, |event| {
        match event {
            Event::BeginNode { depth, .. } => {
                let enabled = frames.last().is_none_or(|parent| parent.enabled);
                frames.push(Frame::new(depth, enabled));
            }
            Event::Prop { name, data, depth } => {
                let Some(frame) = frames.last_mut().filter(|frame| frame.depth == depth) else { return Flow::Stop };
                match name {
                    b"compatible" => {
                        frame.fixed_clock |= contains_string(data, b"fixed-clock");
                        frame.fixed_factor |= contains_string(data, b"fixed-factor-clock");
                        frame.fixed_regulator |= contains_string(data, b"regulator-fixed");
                    }
                    b"status" => frame.enabled &= matches!(string(data), Some(b"ok" | b"okay")),
                    b"phandle" | b"linux,phandle" => frame.phandle = read_be_u32(data, 0).ok(),
                    b"#clock-cells" => frame.clock_cells = read_be_u32(data, 0).ok(),
                    b"clocks" => frame.parent = Some(data.to_vec()),
                    b"clock-mult" => frame.mult = read_be_u32(data, 0).ok(),
                    b"clock-div" => frame.div = read_be_u32(data, 0).ok(),
                    b"clock-frequency" => frame.rate_hz = read_be_u32(data, 0).ok().map(u64::from),
                    b"regulator-min-microvolt" => frame.min_uv = read_be_u32(data, 0).ok(),
                    b"regulator-max-microvolt" => frame.max_uv = read_be_u32(data, 0).ok(),
                    _ => {}
                }
            }
            Event::EndNode { depth } => {
                let Some(frame) = frames.pop() else { return Flow::Stop };
                if frame.depth != depth { return Flow::Stop; }
                if !frame.enabled { return Flow::Continue; }
                if let (Some(phandle), Some(cells)) = (frame.phandle, frame.clock_cells) {
                    if phandle != 0 { clock_cells.push((phandle, cells)); }
                }
                if frame.fixed_clock {
                    if let (Some(phandle), Some(0), Some(rate_hz)) = (frame.phandle, frame.clock_cells, frame.rate_hz) {
                        if phandle != 0 && rate_hz != 0 {
                            if used_phandle(&providers, phandle) { duplicate = true; }
                            else { providers.clocks.push(FixedClock { phandle, rate_hz }); }
                        }
                    }
                }
                if frame.fixed_factor {
                    if let (Some(phandle), Some(0), Some(parent), Some(mult), Some(div)) =
                        (frame.phandle, frame.clock_cells, frame.parent, frame.mult, frame.div)
                    {
                        if phandle != 0 && mult != 0 && div != 0 {
                            raw_factors.push(RawFactor { phandle, parent, mult, div });
                        }
                    }
                }
                if frame.fixed_regulator {
                    if let (Some(phandle), Some(min_uv), Some(max_uv)) = (frame.phandle, frame.min_uv, frame.max_uv) {
                        if phandle != 0 && min_uv != 0 && min_uv == max_uv {
                            if used_phandle(&providers, phandle) { duplicate = true; }
                            else { providers.regulators.push(FixedRegulator { phandle, voltage_uv: min_uv }); }
                        }
                    }
                }
            }
        }
        Flow::Continue
    }).is_err() || duplicate { return FixedProviders::default(); }
    for RawFactor { phandle, parent, mult, div } in raw_factors {
        let Some(parent) = one_clock(&parent, &clock_cells) else { continue; };
        if used_phandle(&providers, phandle) { return FixedProviders::default(); }
        providers.factors.push(FixedFactorClock { phandle, parent, mult, div });
    }
    providers
}

fn string(data: &[u8]) -> Option<&[u8]> { data.split(|byte| *byte == 0).next() }

fn used_phandle(providers: &FixedProviders, phandle: u32) -> bool {
    providers.clocks.iter().any(|clock| clock.phandle == phandle)
        || providers.factors.iter().any(|factor| factor.phandle == phandle)
        || providers.regulators.iter().any(|regulator| regulator.phandle == phandle)
}

fn one_clock(data: &[u8], cells: &[(u32, u32)]) -> Option<ClockReference> {
    let provider = read_be_u32(data, 0).ok()?;
    let mut counts = cells.iter().filter(|(phandle, _)| *phandle == provider).map(|(_, count)| *count);
    let count = usize::try_from(counts.next()?).ok()?;
    if counts.next().is_some() || data.len() != count.checked_add(1)?.checked_mul(4)? { return None; }
    let mut arguments = Vec::with_capacity(count);
    for index in 0..count { arguments.push(read_be_u32(data, (index + 1) * 4).ok()?); }
    Some(ClockReference { provider, arguments })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::Fdt;

    #[test]
    fn complete_enabled_fixed_providers_are_published_by_their_phandles() {
        let mut fdt = Fdt::new();
        fdt.begin("")
            .begin("clock").prop_str("compatible", "fixed-clock").prop_u32("phandle", 1)
            .prop_u32("#clock-cells", 0).prop_u32("clock-frequency", 24_000_000).end()
            .begin("supply").prop_str("compatible", "regulator-fixed").prop_u32("phandle", 2)
            .prop_u32("regulator-min-microvolt", 900_000).prop_u32("regulator-max-microvolt", 900_000).end()
            .begin("disabled").prop_str("compatible", "fixed-clock").prop_u32("phandle", 3)
            .prop_u32("#clock-cells", 0).prop_u32("clock-frequency", 1).prop_str("status", "disabled").end().end();
        assert_eq!(fixed_providers(&fdt.finish()), FixedProviders {
            clocks: alloc::vec![FixedClock { phandle: 1, rate_hz: 24_000_000 }],
            factors: alloc::vec![],
            regulators: alloc::vec![FixedRegulator { phandle: 2, voltage_uv: 900_000 }],
        });
    }

    #[test]
    fn a_fixed_factor_keeps_its_parent_clock_reference_and_ratio() {
        let mut fdt = Fdt::new();
        fdt.begin("")
            .begin("source").prop_str("compatible", "fixed-clock").prop_u32("phandle", 1)
            .prop_u32("#clock-cells", 0).prop_u32("clock-frequency", 24_000_000).end()
            .begin("derived").prop_str("compatible", "fixed-factor-clock").prop_u32("phandle", 2)
            .prop_u32("#clock-cells", 0).prop_u32("clocks", 1).prop_u32("clock-mult", 2).prop_u32("clock-div", 3).end().end();
        assert_eq!(fixed_providers(&fdt.finish()).factors, alloc::vec![FixedFactorClock {
            phandle: 2, parent: ClockReference { provider: 1, arguments: alloc::vec![] }, mult: 2, div: 3,
        }]);
    }

    #[test]
    fn malformed_or_duplicate_fixed_providers_are_not_published() {
        let mut fdt = Fdt::new();
        fdt.begin("")
            .begin("clock-a").prop_str("compatible", "fixed-clock").prop_u32("phandle", 1)
            .prop_u32("#clock-cells", 0).prop_u32("clock-frequency", 1).end()
            .begin("clock-b").prop_str("compatible", "fixed-clock").prop_u32("phandle", 1)
            .prop_u32("#clock-cells", 0).prop_u32("clock-frequency", 2).end()
            .begin("variable").prop_str("compatible", "regulator-fixed").prop_u32("phandle", 2)
            .prop_u32("regulator-min-microvolt", 800_000).prop_u32("regulator-max-microvolt", 900_000).end().end();
        assert_eq!(fixed_providers(&fdt.finish()), FixedProviders::default());
    }
}
