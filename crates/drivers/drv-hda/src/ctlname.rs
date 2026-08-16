// Mixer control naming. `alsamixer` and every desktop volume slider find a
// control by name, so these strings are as much an ABI as the ioctl numbers.

use alloc::vec::Vec;

use crate::autocfg::{AutoCfg, InputPin, InputType, OutType};
use crate::defcfg::PinAttr;
use crate::generic::Plan;

/// Longest control name the sound core's element id carries.
pub const NAME_CAP: usize = sound::elem::ELEM_NAME_WIDTH;

/// Multi-channel output position names, in ALSA's channel order.
const CHANNEL_NAMES: [&[u8]; 5] = [b"Front", b"Surround", b"CLFE", b"Side", b"Back"];

/// Location prefixes for a microphone input, indexed by placement.
fn mic_name(attr: PinAttr) -> &'static [u8] {
    match attr {
        PinAttr::Internal => b"Internal Mic",
        PinAttr::Dock => b"Dock Mic",
        PinAttr::Rear => b"Rear Mic",
        PinAttr::Front => b"Front Mic",
        _ => b"Mic",
    }
}

/// Base label for one capture source. # C: O(1)
pub fn input_label(input: &InputPin, needs_location: bool) -> &'static [u8] {
    match input.itype {
        InputType::Mic => if needs_location { mic_name(input.attr) } else { b"Mic" },
        InputType::LineIn => b"Line",
        InputType::Cd => b"CD",
        InputType::Aux => b"Aux",
    }
}

/// A location prefix is only added when two inputs of the same kind sit in
/// different places, which is the only case where the bare name is
/// ambiguous. # C: O(inputs²)
pub fn inputs_need_location(inputs: &[InputPin]) -> bool {
    inputs.iter().enumerate().any(|(index, input)| {
        inputs[index + 1..].iter().any(|other| other.itype == input.itype && other.attr != input.attr)
    })
}

/// Prefix for output channel `channel` of the primary group.
///
/// A card with one output and nothing else names it `Master`, so a desktop
/// volume slider finds it without knowing anything about the codec.
/// # C: O(1)
pub fn line_out_prefix(plan: &Plan, channel: usize) -> &'static [u8] {
    let cfg: &AutoCfg = &plan.cfg;
    if cfg.line_out.len() == 1 && cfg.hp.is_empty() && cfg.speaker.is_empty() { return b"Master"; }
    if channel >= cfg.line_out.len() { return CHANNEL_NAMES[channel.min(CHANNEL_NAMES.len() - 1)]; }
    match cfg.line_out_type {
        OutType::Speaker => match cfg.line_out.len() {
            1 => b"Speaker",
            2 if channel == 1 => b"Bass Speaker",
            2 => b"Speaker",
            _ => CHANNEL_NAMES[channel.min(CHANNEL_NAMES.len() - 1)],
        },
        OutType::Headphone => b"Headphone",
        OutType::LineOut => {
            if cfg.line_out.len() == 1 { b"Line Out" }
            else { CHANNEL_NAMES[channel.min(CHANNEL_NAMES.len() - 1)] }
        }
    }
}

/// Prefix for an extra (headphone or speaker) output group. # C: O(1)
pub fn extra_out_prefix(group: &'static [u8], count: usize, index: usize) -> &'static [u8] {
    if group == b"Speaker" && count == 2 && index == 1 { return b"Bass Speaker"; }
    group
}

/// `"<prefix> Playback Volume"` and friends, truncated to the element-name
/// width the control ABI carries. # C: O(NAME_CAP)
pub fn compose(prefix: &[u8], middle: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut name = Vec::with_capacity(NAME_CAP);
    for part in [prefix, b" ", middle, b" ", suffix] {
        for &byte in part {
            if name.len() == NAME_CAP { return name; }
            name.push(byte);
        }
    }
    name
}

/// `"<prefix> Playback Volume"`. # C: O(NAME_CAP)
pub fn playback_volume(prefix: &[u8]) -> Vec<u8> { compose(prefix, b"Playback", b"Volume") }
/// `"<prefix> Playback Switch"`. # C: O(NAME_CAP)
pub fn playback_switch(prefix: &[u8]) -> Vec<u8> { compose(prefix, b"Playback", b"Switch") }
/// `"<label> Capture Volume"`. # C: O(NAME_CAP)
pub fn capture_volume() -> Vec<u8> { compose(b"Capture", b"", b"Volume") }
/// `"Capture Switch"`. # C: O(NAME_CAP)
pub fn capture_switch() -> Vec<u8> { compose(b"Capture", b"", b"Switch") }
/// The enumerated control selecting which pin is captured. # C: O(NAME_CAP)
pub fn capture_source() -> Vec<u8> { compose(b"Capture", b"", b"Source") }
/// `"<prefix> Jack"`, the boolean a desktop watches for headphone insertion.
/// # C: O(NAME_CAP)
pub fn jack_name(prefix: &[u8]) -> Vec<u8> { compose(prefix, b"", b"Jack") }

/// Squeeze the double space out of a two-part name. # C: O(name)
pub fn tidy(name: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len());
    let mut previous_space = false;
    for byte in name {
        if byte == b' ' && previous_space { continue; }
        previous_space = byte == b' ';
        out.push(byte);
    }
    while out.last() == Some(&b' ') { out.pop(); }
    out
}

#[cfg(test)]
#[path = "tests/ctlname.rs"]
mod tests;
