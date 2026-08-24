// Pin classification: turn every pin's default configuration into the output
// and input groups the parser assigns converters to. This is the only place
// that decides what a jack is for.

use alloc::vec::Vec;

use crate::defcfg::{self, PinAttr};
use crate::graph::{Codec, Widget};
use crate::widget;

/// Widest output group the parser tracks (front/surround/CLFE/side).
pub const MAX_OUTS: usize = 4;
/// Widest input list the parser tracks.
pub const MAX_INS: usize = 18;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum InputType { Mic, LineIn, Cd, Aux, Digital }

/// Which group the card's primary outputs came from, which decides how the
/// mixer controls are named and which group automute may silence.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum OutType { LineOut, Speaker, Headphone }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct InputPin {
    pub nid: u8,
    pub itype: InputType,
    pub attr: PinAttr,
    /// Pin has its own input amplifier, so it can carry a boost control.
    pub boost: bool,
    /// Discovery order, the stable tiebreak in the input sort.
    pub order: usize,
}

#[derive(Clone, Debug, Default)]
pub struct AutoCfg {
    pub line_out: Vec<u8>,
    pub speaker: Vec<u8>,
    pub hp: Vec<u8>,
    pub inputs: Vec<InputPin>,
    pub dig_out: Vec<u8>,
    pub dig_in: Option<u8>,
    pub line_out_type: OutType,
}

impl Default for OutType {
    fn default() -> Self { OutType::LineOut }
}

struct Candidate { nid: u8, key: u16 }

/// A pin can serve a device only if its capabilities agree. A codec that
/// reports no pin capabilities at all is taken at the configuration's word.
fn pincap_allows(pin: &Widget, device: u8) -> bool {
    if pin.pincap == 0 { return true; }
    match device {
        defcfg::DEV_LINE_OUT | defcfg::DEV_SPEAKER | defcfg::DEV_HP_OUT
        | defcfg::DEV_SPDIF_OUT | defcfg::DEV_DIG_OTHER_OUT => pin.pincap & widget::PINCAP_OUT != 0,
        defcfg::DEV_LINE_IN | defcfg::DEV_MIC_IN | defcfg::DEV_CD | defcfg::DEV_AUX
        | defcfg::DEV_SPDIF_IN | defcfg::DEV_DIG_OTHER_IN => pin.pincap & widget::PINCAP_IN != 0,
        _ => true,
    }
}

fn sort_group(group: &mut Vec<Candidate>) {
    group.sort_by_key(|candidate| candidate.key);
}

fn nids(group: &[Candidate]) -> Vec<u8> { group.iter().map(|c| c.nid).collect() }

/// HDA orders multi-channel outputs front/CLFE/surround; ALSA orders them
/// front/surround/CLFE. Three- and four-way groups need the swap.
/// # C: O(1)
fn reorder_outputs(pins: &mut [u8]) {
    if matches!(pins.len(), 3 | 4) { pins.swap(1, 2); }
}

/// Classify every pin of `codec`. # C: O(widgets log widgets)
pub fn parse_pin_defcfg(codec: &Codec) -> AutoCfg {
    let mut line_out: Vec<Candidate> = Vec::new();
    let mut speaker: Vec<Candidate> = Vec::new();
    let mut hp: Vec<Candidate> = Vec::new();
    let mut cfg = AutoCfg::default();
    let mut assoc_line_out = 0u8;

    for pin in codec.widgets.iter().filter(|w| w.is_pin()) {
        let conf = pin.defcfg;
        if defcfg::unconnected(conf) { continue; }
        let device = defcfg::effective_device(conf);
        if !pincap_allows(pin, device) { continue; }
        let seq = defcfg::sequence(conf);
        let assoc = defcfg::association(conf);
        match device {
            defcfg::DEV_LINE_OUT => {
                // Association zero never groups; and only one association
                // group can be the card's line-out set.
                if assoc == 0 { continue; }
                if assoc_line_out == 0 { assoc_line_out = assoc; }
                if assoc_line_out != assoc || line_out.len() >= MAX_OUTS { continue; }
                line_out.push(Candidate { nid: pin.nid, key: u16::from(seq) });
            }
            defcfg::DEV_SPEAKER => speaker.push(Candidate { nid: pin.nid, key: defcfg::group_sort_key(conf) }),
            defcfg::DEV_HP_OUT => hp.push(Candidate { nid: pin.nid, key: defcfg::group_sort_key(conf) }),
            defcfg::DEV_MIC_IN => push_input(&mut cfg, pin, InputType::Mic),
            defcfg::DEV_LINE_IN => push_input(&mut cfg, pin, InputType::LineIn),
            defcfg::DEV_CD => push_input(&mut cfg, pin, InputType::Cd),
            defcfg::DEV_AUX => push_input(&mut cfg, pin, InputType::Aux),
            defcfg::DEV_SPDIF_OUT | defcfg::DEV_DIG_OTHER_OUT => cfg.dig_out.push(pin.nid),
            defcfg::DEV_SPDIF_IN | defcfg::DEV_DIG_OTHER_IN => cfg.dig_in = Some(pin.nid),
            _ => {}
        }
    }

    // A codec with several headphone jacks and no line-out is really a
    // multi-channel line-out set; a sequence of 0xf marks a true headphone.
    if line_out.is_empty() && hp.len() > 1 {
        let mut index = 0;
        while index < hp.len() {
            if hp[index].key & 0x0f == 0x0f { index += 1; continue; }
            line_out.push(hp.remove(index));
        }
        if hp.is_empty() { cfg.line_out_type = OutType::Headphone; }
    }

    sort_group(&mut line_out);
    sort_group(&mut speaker);
    sort_group(&mut hp);
    cfg.line_out = nids(&line_out);
    cfg.speaker = nids(&speaker);
    cfg.hp = nids(&hp);

    // With no line-out at all the speakers are the primary output, and
    // failing that the headphone jack is.
    if cfg.line_out.is_empty() {
        if !cfg.speaker.is_empty() {
            cfg.line_out = core::mem::take(&mut cfg.speaker);
            cfg.line_out_type = OutType::Speaker;
        } else if !cfg.hp.is_empty() {
            cfg.line_out = core::mem::take(&mut cfg.hp);
            cfg.line_out_type = OutType::Headphone;
        }
    }

    reorder_outputs(&mut cfg.line_out);
    reorder_outputs(&mut cfg.speaker);
    reorder_outputs(&mut cfg.hp);
    sort_inputs(&mut cfg.inputs);
    cfg
}

fn push_input(cfg: &mut AutoCfg, pin: &Widget, itype: InputType) {
    if cfg.inputs.len() >= MAX_INS { return; }
    let order = cfg.inputs.len();
    cfg.inputs.push(InputPin {
        nid: pin.nid,
        itype,
        attr: defcfg::pin_attr(pin.defcfg),
        boost: pin.wcaps & widget::WCAP_IN_AMP != 0,
        order,
    });
}

/// Inputs sort by kind, then a boosted pin ahead of an unboosted one of the
/// same kind, then discovery order. # C: O(inputs log inputs)
fn sort_inputs(inputs: &mut [InputPin]) {
    inputs.sort_by_key(|input| (input.itype, core::cmp::Reverse(input.boost), input.order));
}

/// Pins that are outputs of some kind, in the order controls are built.
/// # C: O(outputs)
pub fn all_output_pins(cfg: &AutoCfg) -> Vec<u8> {
    let mut pins = cfg.line_out.clone();
    pins.extend_from_slice(&cfg.hp);
    pins.extend_from_slice(&cfg.speaker);
    pins
}

#[cfg(test)]
#[path = "tests/autocfg.rs"]
mod tests;
