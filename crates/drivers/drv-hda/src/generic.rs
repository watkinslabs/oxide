// The generic parser: given a widget graph and its pin classification, work
// out which converter drives which jack, which widget on each route owns the
// volume and the mute, and which pins can be captured from. A codec with no
// vendor-specific handling still produces sound through this.

use alloc::vec::Vec;

use crate::autocfg::{self, AutoCfg, InputPin, OutType};
use crate::graph::Codec;
use crate::paths::{self, NidPath, Source};

/// Penalties. The primary output missing a converter outweighs every
/// secondary-output problem combined, which is what makes the search prefer
/// a working front output over a complete but shared assignment.
#[derive(Copy, Clone)]
pub struct Badness {
    pub no_primary_dac: u32,
    pub no_dac: u32,
    pub shared_primary: u32,
    pub shared_surround: u32,
    pub shared_clfe: u32,
}

pub const MAIN_OUT_BADNESS: Badness = Badness {
    no_primary_dac: 0x10000, no_dac: 0x4000, shared_primary: 0x10000,
    shared_surround: 0x100, shared_clfe: 0x10,
};
pub const EXTRA_OUT_BADNESS: Badness = Badness {
    no_primary_dac: 0x4000, no_dac: 0x4000, shared_primary: 0x102,
    shared_surround: 0x10, shared_clfe: 0x10,
};
/// A route whose volume or mute widget is already spoken for.
pub const BAD_SHARED_VOL: u32 = 0x10;

/// One jack and the route that reaches it.
#[derive(Clone, Debug)]
pub struct OutputRoute {
    pub pin: u8,
    pub path: NidPath,
    pub dac: u8,
    pub volume: Option<u8>,
    /// `(nid, output_side)` — an interior node mutes on its input side.
    pub mute: Option<(u8, bool)>,
    /// The converter is shared with an earlier output.
    pub shared: bool,
}

/// One capture source and the route from its pin to a converter.
#[derive(Clone, Debug)]
pub struct InputRoute {
    pub pin: u8,
    pub path: NidPath,
    pub adc: u8,
    pub input: InputPin,
}

/// Everything the card driver needs to program and to publish controls.
#[derive(Clone, Debug, Default)]
pub struct Plan {
    pub cfg: AutoCfg,
    pub outputs: Vec<OutputRoute>,
    pub hp: Vec<OutputRoute>,
    pub speaker: Vec<OutputRoute>,
    pub digital: Vec<OutputRoute>,
    pub captures: Vec<InputRoute>,
    pub badness: u32,
}

impl Plan {
    /// Every output route, primary group first. # C: O(routes)
    pub fn all_outputs(&self) -> impl Iterator<Item = &OutputRoute> {
        self.outputs.iter().chain(self.hp.iter()).chain(self.speaker.iter()).chain(self.digital.iter())
    }
    /// The route a PCM playback stream drives. # C: O(1)
    pub fn primary(&self) -> Option<&OutputRoute> { self.outputs.first() }
    /// The route a PCM capture stream drives. # C: O(1)
    pub fn primary_capture(&self) -> Option<&InputRoute> { self.captures.first() }
    /// Route selected by the Linux PCM device number. The primary analog
    /// route is device zero; additional routed converters follow in plan order.
    pub fn output_for(&self, device: u32) -> Option<&OutputRoute> {
        self.all_outputs().nth(device as usize)
    }
    pub fn capture_for(&self, device: u32) -> Option<&InputRoute> {
        self.captures.get(device as usize)
    }
}

struct Assign {
    used_dacs: Vec<u8>,
    /// Volume and mute are separate amplifier controls, so one widget can own
    /// both on the same route; only a second ROUTE reaching for the same one
    /// is a conflict.
    used_volume: Vec<u8>,
    used_mute: Vec<u8>,
    badness: u32,
}

impl Assign {
    fn new() -> Self {
        Self { used_dacs: Vec::new(), used_volume: Vec::new(), used_mute: Vec::new(), badness: 0 }
    }

    /// Claim the volume and mute widgets of a route, charging for any that a
    /// previous route already owns.
    fn claim_controls(&mut self, codec: &Codec, route: &mut OutputRoute) {
        route.volume = paths::volume_nid(codec, &route.path);
        route.mute = paths::mute_nid(codec, &route.path);
        match route.volume {
            Some(nid) if !self.used_volume.contains(&nid) => self.used_volume.push(nid),
            Some(_) => { self.badness += BAD_SHARED_VOL; route.volume = None; }
            None => self.badness += BAD_SHARED_VOL,
        }
        match route.mute {
            Some((nid, _)) if !self.used_mute.contains(&nid) => self.used_mute.push(nid),
            Some(_) => { self.badness += BAD_SHARED_VOL; route.mute = None; }
            None => self.badness += BAD_SHARED_VOL,
        }
    }
}

/// Pins with exactly one reachable unused converter take it first: that
/// assignment is forced, and making it before the greedy pass stops an
/// earlier pin from stealing the only converter a later pin could use.
fn map_singles(codec: &Codec, pins: &[u8], dacs: &[u8], state: &mut Assign) -> Vec<Option<u8>> {
    let mut chosen: Vec<Option<u8>> = alloc::vec![None; pins.len()];
    loop {
        let mut progressed = false;
        for (index, &pin) in pins.iter().enumerate() {
            if chosen[index].is_some() { continue; }
            let mut candidates = dacs.iter().copied()
                .filter(|dac| !state.used_dacs.contains(dac) && paths::reachable(codec, *dac, pin));
            let Some(only) = candidates.next() else { continue; };
            if candidates.next().is_some() { continue; }
            state.used_dacs.push(only);
            chosen[index] = Some(only);
            progressed = true;
        }
        if !progressed { return chosen; }
    }
}

fn assign_group(codec: &Codec, pins: &[u8], table: &Badness, primary_dac: Option<u8>,
                state: &mut Assign) -> Vec<OutputRoute> {
    let dacs = codec.dacs();
    let preassigned = map_singles(codec, pins, &dacs, state);
    let mut routes = Vec::new();
    for (index, &pin) in pins.iter().enumerate() {
        let mut shared = false;
        let dac = match preassigned[index] {
            Some(dac) => Some(dac),
            None => match paths::find(codec, Source::UnusedDac, pin, &state.used_dacs) {
                Some(path) => path.source(),
                None => None,
            },
        };
        let dac = match dac {
            Some(dac) => {
                if !state.used_dacs.contains(&dac) { state.used_dacs.push(dac); }
                dac
            }
            None => {
                // Nothing free: share an already-assigned converter, at the
                // cost the position deserves.
                let fallback = routes.first().map(|r: &OutputRoute| r.dac).or(primary_dac);
                match fallback.filter(|dac| paths::reachable(codec, *dac, pin)) {
                    Some(dac) => {
                        shared = true;
                        state.badness += match index {
                            0 => table.shared_primary,
                            1 => table.shared_surround,
                            _ => table.shared_clfe,
                        };
                        dac
                    }
                    None => {
                        state.badness += if index == 0 { table.no_primary_dac } else { table.no_dac };
                        continue;
                    }
                }
            }
        };
        let Some(path) = paths::find(codec, Source::Nid(dac), pin, &[]) else {
            state.badness += table.no_dac;
            continue;
        };
        let mut route = OutputRoute { pin, path, dac, volume: None, mute: None, shared };
        state.claim_controls(codec, &mut route);
        routes.push(route);
    }
    routes
}

fn assign_outputs(codec: &Codec, cfg: &AutoCfg) -> (Vec<OutputRoute>, Vec<OutputRoute>, Vec<OutputRoute>, Vec<OutputRoute>, u32) {
    let mut state = Assign::new();
    let outputs = assign_group(codec, &cfg.line_out, &MAIN_OUT_BADNESS, None, &mut state);
    let primary = outputs.first().map(|route| route.dac);
    // A group promoted to primary was emptied when it was promoted, so both
    // extra groups are always assigned; skipping one on the strength of the
    // primary's kind would drop a real jack for free.
    let hp = assign_group(codec, &cfg.hp, &EXTRA_OUT_BADNESS, primary, &mut state);
    let speaker = assign_group(codec, &cfg.speaker, &EXTRA_OUT_BADNESS, primary, &mut state);
    let digital = assign_group(codec, &cfg.dig_out, &EXTRA_OUT_BADNESS, primary, &mut state);
    (outputs, hp, speaker, digital, state.badness)
}

/// Swap the primary output group with the headphone or speaker group. When a
/// codec's only line-out set came from one of those groups, driving the other
/// as primary can score better.
fn swapped(cfg: &AutoCfg) -> Option<AutoCfg> {
    let mut alternative = cfg.clone();
    match cfg.line_out_type {
        OutType::Headphone if !cfg.speaker.is_empty() => {
            core::mem::swap(&mut alternative.line_out, &mut alternative.speaker);
            alternative.line_out_type = OutType::Speaker;
        }
        OutType::Speaker if !cfg.hp.is_empty() => {
            core::mem::swap(&mut alternative.line_out, &mut alternative.hp);
            alternative.line_out_type = OutType::Headphone;
        }
        _ => return None,
    }
    Some(alternative)
}

fn assign_captures(codec: &Codec, cfg: &AutoCfg) -> Vec<InputRoute> {
    let adcs = codec.adcs();
    let mut routes = Vec::new();
    for input in cfg.inputs.iter() {
        for &adc in adcs.iter() {
            let Some(path) = paths::find(codec, Source::Nid(input.nid), adc, &[]) else { continue; };
            routes.push(InputRoute { pin: input.nid, path, adc, input: *input });
            break;
        }
    }
    if let Some(pin) = cfg.dig_in {
        let defcfg = codec.widget(pin).map(|w| w.defcfg).unwrap_or(0);
        let input = InputPin { nid: pin, itype: autocfg::InputType::Digital,
                               attr: crate::defcfg::pin_attr(defcfg), boost: false,
                               order: cfg.inputs.len() };
        for &adc in codec.digital_adcs().iter() {
            let Some(path) = paths::find(codec, Source::Nid(pin), adc, &[]) else { continue; };
            routes.push(InputRoute { pin, path, adc, input });
            break;
        }
    }
    routes
}

/// Build the routing plan for `codec`. # C: O(pins × widgets × fan-in)
pub fn build(codec: &Codec) -> Plan {
    let cfg = autocfg::parse_pin_defcfg(codec);
    let (outputs, hp, speaker, digital, badness) = assign_outputs(codec, &cfg);
    let mut plan = Plan { captures: assign_captures(codec, &cfg), cfg, outputs, hp, speaker, digital, badness };
    if plan.badness != 0 {
        if let Some(alternative) = swapped(&plan.cfg) {
            let (outputs, hp, speaker, digital, badness) = assign_outputs(codec, &alternative);
            if badness < plan.badness {
                plan.captures = assign_captures(codec, &alternative);
                plan.cfg = alternative;
                plan.outputs = outputs;
                plan.hp = hp;
                plan.speaker = speaker;
                plan.digital = digital;
                plan.badness = badness;
            }
        }
    }
    plan
}

#[cfg(test)]
#[path = "tests/generic.rs"]
mod tests;
