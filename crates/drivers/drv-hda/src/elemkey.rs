// Which controls a routing plan should publish, and the driver-private key
// that ties each one back to the amplifier behind it. Both are decisions,
// so both are made here rather than in the MMIO layer.

use alloc::vec::Vec;

use crate::ctlname;
use crate::generic::{OutputRoute, Plan};
use crate::graph::{self, Codec};
use crate::widget::{self, AmpCaps};

/// What an element does.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ElemKind { Volume, Switch, Jack, CaptureSource }

const KIND_SHIFT: u32 = 9;
const OUTPUT_BIT: u32 = 1 << 8;
const NID_MASK: u32 = 0xff;

/// Pack an element's amplifier target into the private word. # C: O(1)
pub fn pack(nid: u8, output: bool, kind: ElemKind) -> u32 {
    let kind_bits = match kind {
        ElemKind::Volume => 0u32, ElemKind::Switch => 1, ElemKind::Jack => 2,
        ElemKind::CaptureSource => 3,
    };
    u32::from(nid) | if output { OUTPUT_BIT } else { 0 } | (kind_bits << KIND_SHIFT)
}

/// # C: O(1)
pub fn unpack(private: u32) -> (u8, bool, ElemKind) {
    let kind = match private >> KIND_SHIFT {
        0 => ElemKind::Volume,
        1 => ElemKind::Switch,
        2 => ElemKind::Jack,
        _ => ElemKind::CaptureSource,
    };
    ((private & NID_MASK) as u8, private & OUTPUT_BIT != 0, kind)
}

/// One amplifier exposed as a volume and, when it can mute, a switch.
#[derive(Clone, Debug)]
pub struct AmpControl {
    pub volume_name: Vec<u8>,
    pub switch_name: Vec<u8>,
    pub nid: u8,
    pub output: bool,
    pub caps: AmpCaps,
}

/// One jack exposed as a read-only presence boolean.
#[derive(Clone, Debug)]
pub struct JackControl {
    pub name: Vec<u8>,
    pub pin: u8,
}

#[derive(Clone, Debug, Default)]
pub struct Controls {
    pub amps: Vec<AmpControl>,
    pub jacks: Vec<JackControl>,
    pub capture_sources: Vec<Vec<u8>>,
}

fn amp_of(codec: &Codec, nid: u8, output: bool) -> Option<AmpCaps> {
    let w = codec.widget(nid)?;
    let caps = if output { w.out_amp(codec.fg_amp_out) } else { w.in_amp(codec.fg_amp_in) }?;
    let decoded = widget::amp_caps(caps);
    if decoded.num_steps == 0 && !decoded.mute { None } else { Some(decoded) }
}

fn push_route(controls: &mut Controls, codec: &Codec, route: &OutputRoute, prefix: &[u8]) {
    // The volume and the mute may sit on different widgets; each is published
    // against the one that actually owns it.
    if let Some((nid, caps)) = route.volume.and_then(|nid| amp_of(codec, nid, true).map(|caps| (nid, caps))) {
        controls.amps.push(AmpControl {
            volume_name: ctlname::tidy(ctlname::playback_volume(prefix)),
            switch_name: ctlname::tidy(ctlname::playback_switch(prefix)),
            nid, output: true, caps,
        });
    }
    let Some((mute_nid, output)) = route.mute else { return; };
    if route.volume == Some(mute_nid) { return; }
    if let Some(caps) = amp_of(codec, mute_nid, output) {
        controls.amps.push(AmpControl {
            volume_name: Vec::new(),
            switch_name: ctlname::tidy(ctlname::playback_switch(prefix)),
            nid: mute_nid, output, caps,
        });
    }
}

/// Controls the card should publish for `plan`. # C: O(routes)
pub fn describe(codec: &Codec, plan: &Plan) -> Controls {
    let mut controls = Controls::default();
    for (index, route) in plan.outputs.iter().enumerate() {
        push_route(&mut controls, codec, route, ctlname::line_out_prefix(plan, index));
    }
    for (index, route) in plan.hp.iter().enumerate() {
        push_route(&mut controls, codec, route, ctlname::extra_out_prefix(b"Headphone", plan.hp.len(), index));
    }
    for (index, route) in plan.speaker.iter().enumerate() {
        push_route(&mut controls, codec, route, ctlname::extra_out_prefix(b"Speaker", plan.speaker.len(), index));
    }
    if let Some(capture) = plan.primary_capture() {
        if let Some(caps) = amp_of(codec, capture.adc, false) {
            controls.amps.push(AmpControl {
                volume_name: ctlname::tidy(ctlname::capture_volume()),
                switch_name: ctlname::tidy(ctlname::capture_switch()),
                nid: capture.adc, output: false, caps,
            });
        }
    }
    if plan.captures.len() > 1 {
        let inputs: Vec<_> = plan.captures.iter().map(|route| route.input).collect();
        let needs_location = ctlname::inputs_need_location(&inputs);
        controls.capture_sources = plan.captures.iter()
            .map(|route| ctlname::tidy(ctlname::input_label(&route.input, needs_location).to_vec()))
            .collect();
    }
    for (index, route) in plan.hp.iter().enumerate() {
        if !codec.widget(route.pin).is_some_and(graph::jack_detectable) { continue; }
        controls.jacks.push(JackControl {
            name: ctlname::tidy(ctlname::jack_name(
                ctlname::extra_out_prefix(b"Headphone", plan.hp.len(), index))),
            pin: route.pin,
        });
    }
    for (index, route) in plan.outputs.iter().enumerate() {
        if !codec.widget(route.pin).is_some_and(graph::jack_detectable) { continue; }
        controls.jacks.push(JackControl {
            name: ctlname::tidy(ctlname::jack_name(ctlname::line_out_prefix(plan, index))),
            pin: route.pin,
        });
    }
    controls
}

#[cfg(test)]
#[path = "tests/elemkey.rs"]
mod tests;
