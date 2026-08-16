// Controller bring-up and the codec-facing operations the ALSA card layer
// calls: enumerate, apply the routing plan, program a stream, read a jack.

#![cfg(target_os = "oxide-kernel")]

use core::cell::RefCell;

use crate::bdl::Geometry;
use crate::generic::{self, OutputRoute, Plan};
use crate::graph::{self, Codec, CodecBus};
use crate::regs::Regs;
use crate::stream::Stream;
use crate::transport::{self, Rings};
use crate::uapi::*;
use crate::verb;
use crate::widget;

/// A codec address bound to a controller, usable as a command bus while the
/// driver lock is held.
pub struct CodecPort<'a> {
    regs: Regs,
    rings: RefCell<&'a mut Rings>,
    addr: u8,
}

impl<'a> CodecPort<'a> {
    /// # C: O(1)
    pub fn new(regs: Regs, rings: &'a mut Rings, addr: u8) -> Self {
        Self { regs, rings: RefCell::new(rings), addr }
    }
}

impl CodecBus for CodecPort<'_> {
    fn command(&self, nid: u8, cmd: u16, payload: u16) -> Option<u32> {
        let command = verb::make_verb(self.addr, nid, cmd, payload)?;
        let mut rings = self.rings.borrow_mut();
        transport::exec(&self.regs, &mut rings, command)
    }
}

/// Everything one controller owns.
pub struct Hda {
    pub regs: Regs,
    pub rings: Rings,
    pub playback: Stream,
    pub capture: Stream,
    pub codec: Option<Codec>,
    pub plan: Option<Plan>,
    /// Unsolicited-response tag assigned to each jack-detectable output pin.
    pub jack_tags: [(u8, u8); MAX_JACKS],
    pub jack_count: usize,
    /// Last reported presence per tracked jack.
    pub jack_present: [bool; MAX_JACKS],
    pub streams: u8,
    /// The controller has an interrupt vector, so the response ring may be
    /// serviced by the handler. Without one the driver polls, which is a
    /// working transport rather than a broken one.
    pub interrupts: bool,
}

/// Jacks the driver tracks presence for.
pub const MAX_JACKS: usize = 4;

impl Hda {
    /// Take the controller out of reset, start the command rings, and return
    /// the codec-presence mask. # C: O(reset timeouts)
    pub fn bring_up(&mut self) -> Option<u16> {
        let present = transport::reset_link(&self.regs)?;
        transport::clear_interrupts(&self.regs, self.streams);
        transport::init_cmd_io(&self.regs, &mut self.rings, self.interrupts);
        if self.interrupts { self.regs.set32(REG_INTCTL, INT_CTRL_EN | INT_GLOBAL_EN); }
        Some(present)
    }

    /// Enumerate the first codec slot that answers with an audio function
    /// group and build its routing plan. # C: O(codecs × widgets)
    pub fn enumerate(&mut self, present: u16) -> bool {
        for addr in 0..MAX_CODECS {
            if present & (1 << addr) == 0 { continue; }
            let port = CodecPort::new(self.regs, &mut self.rings, addr);
            let Some(codec) = graph::parse(&port, addr) else { continue; };
            let plan = generic::build(&codec);
            if plan.primary().is_none() && plan.primary_capture().is_none() { continue; }
            self.codec = Some(codec);
            self.plan = Some(plan);
            return true;
        }
        false
    }

    fn port(&mut self) -> Option<CodecPort<'_>> {
        let addr = self.codec.as_ref()?.addr;
        let regs = self.regs;
        Some(CodecPort::new(regs, &mut self.rings, addr))
    }

    /// Put the function group and every widget into D0. # C: O(widgets)
    fn power_up(&mut self) {
        let Some(codec) = self.codec.clone() else { return; };
        let Some(port) = self.port() else { return; };
        port.command(codec.afg, verb::SET_POWER_STATE, u16::from(verb::PWRST_D0));
        for w in codec.widgets.iter().filter(|w| w.wcaps & widget::WCAP_POWER != 0) {
            port.command(w.nid, verb::SET_POWER_STATE, u16::from(verb::PWRST_D0));
        }
    }

    /// Unmute and open every amplifier on a route, and write the selection
    /// index into each selector it passes through. # C: O(path length)
    fn activate(&mut self, route: &OutputRoute, output_pin_ctl: u8) {
        let Some(codec) = self.codec.clone() else { return; };
        let hops: alloc::vec::Vec<_> = route.path.hops.clone();
        let Some(port) = self.port() else { return; };
        for hop in hops.iter() {
            let Some(w) = codec.widget(hop.nid) else { continue; };
            if hop.multi {
                if let Some(sel) = hop.sel { port.command(hop.nid, verb::SET_CONNECT_SEL, u16::from(sel)); }
            }
            if let Some(caps) = w.out_amp(codec.fg_amp_out) {
                let amp = widget::amp_caps(caps);
                let gain = amp.offset.min(amp.num_steps) as u8;
                port.command(hop.nid, verb::SET_AMP_GAIN_MUTE,
                             widget::amp_set_payload(true, 0, true, true, false, gain));
            }
            if let (Some(caps), Some(sel)) = (w.in_amp(codec.fg_amp_in), hop.sel) {
                let amp = widget::amp_caps(caps);
                let gain = amp.offset.min(amp.num_steps) as u8;
                port.command(hop.nid, verb::SET_AMP_GAIN_MUTE,
                             widget::amp_set_payload(false, sel, true, true, false, gain));
            }
        }
        port.command(route.pin, verb::SET_PIN_WIDGET_CONTROL, u16::from(output_pin_ctl));
        if codec.widget(route.pin).is_some_and(|w| w.pincap & widget::PINCAP_EAPD != 0) {
            port.command(route.pin, verb::SET_EAPD_BTLENABLE, u16::from(widget::EAPDBTL_EAPD));
        }
    }

    /// Program every pin and amplifier the plan describes, and arm jack
    /// detection on the output pins that support it.
    /// # C: O(routes × path length)
    pub fn apply_plan(&mut self) {
        self.power_up();
        let Some(plan) = self.plan.clone() else { return; };
        for route in plan.outputs.iter() { self.activate(route, widget::PIN_OUT); }
        for route in plan.hp.iter() { self.activate(route, widget::PIN_HP); }
        for route in plan.speaker.iter() { self.activate(route, widget::PIN_OUT); }
        self.apply_capture(&plan);
        self.arm_jacks(&plan);
    }

    fn apply_capture(&mut self, plan: &Plan) {
        let Some(codec) = self.codec.clone() else { return; };
        let routes = plan.captures.clone();
        let Some(port) = self.port() else { return; };
        for route in routes.iter() {
            let Some(pin) = codec.widget(route.pin) else { continue; };
            let mut ctl = widget::PIN_IN;
            if route.input.itype == crate::autocfg::InputType::Mic {
                ctl |= widget::default_vref(pin.pincap) & widget::PINCTL_VREF_MASK;
            }
            port.command(route.pin, verb::SET_PIN_WIDGET_CONTROL, u16::from(ctl));
            for hop in route.path.hops.iter() {
                let Some(w) = codec.widget(hop.nid) else { continue; };
                if hop.multi {
                    if let Some(sel) = hop.sel { port.command(hop.nid, verb::SET_CONNECT_SEL, u16::from(sel)); }
                }
                if let (Some(caps), Some(sel)) = (w.in_amp(codec.fg_amp_in), hop.sel) {
                    let amp = widget::amp_caps(caps);
                    let gain = amp.offset.min(amp.num_steps) as u8;
                    port.command(hop.nid, verb::SET_AMP_GAIN_MUTE,
                                 widget::amp_set_payload(false, sel, true, true, false, gain));
                }
            }
        }
    }

    fn arm_jacks(&mut self, plan: &Plan) {
        let Some(codec) = self.codec.clone() else { return; };
        let mut pins: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        for route in plan.hp.iter().chain(plan.outputs.iter()) {
            if pins.len() == MAX_JACKS { break; }
            if codec.widget(route.pin).is_some_and(graph::jack_detectable) { pins.push(route.pin); }
        }
        self.jack_count = pins.len();
        let Some(port) = self.port() else { return; };
        for (tag, pin) in pins.iter().enumerate() {
            port.command(*pin, verb::SET_UNSOLICITED_ENABLE, verb::unsol_enable_payload(tag as u8));
        }
        for (index, pin) in pins.iter().enumerate() { self.jack_tags[index] = (*pin, index as u8); }
    }

    /// Is something plugged into `pin`? A pin that needs a trigger is asked
    /// to sense before it is read. # C: O(one command pair)
    pub fn jack_sense(&mut self, pin: u8) -> bool {
        let Some(codec) = self.codec.clone() else { return false; };
        let trigger = codec.widget(pin).is_some_and(|w| w.pincap & widget::PINCAP_TRIG_REQ != 0);
        let Some(port) = self.port() else { return false; };
        if trigger { port.command(pin, verb::SET_PIN_SENSE, 0); }
        port.command(pin, verb::GET_PIN_SENSE, 0)
            .is_some_and(|value| value & verb::PINSENSE_PRESENCE != 0)
    }

    /// Bind the playback converter to the output stream and program both
    /// sides for `alsa_format`/`rate`/`channels`.
    /// # C: O(periods + one command pair)
    pub fn prepare_playback(&mut self, alsa_format: u32, rate: u32, channels: u8,
                            period_bytes: u32) -> bool {
        let Some(codec) = self.codec.clone() else { return false; };
        let Some(route) = self.plan.as_ref().and_then(|plan| plan.primary().cloned()) else { return false; };
        let par_pcm = codec.pcm_caps_of(route.dac);
        let Some(format) = crate::stream_fmt::format_for(alsa_format, rate, u32::from(channels), par_pcm)
            else { return false; };
        let frame_bytes = sound::format::frame_bytes(alsa_format, u32::from(channels));
        let period = crate::bdl::align_period(period_bytes.min(crate::stream::MAX_PERIOD_BYTES));
        let geometry = Geometry { period_bytes: period, periods: crate::stream::PERIODS };
        let regs = self.regs;
        if !self.playback.setup(&regs, format, geometry, frame_bytes) { return false; }
        self.playback.silence();
        let tag = self.playback.tag;
        let Some(port) = self.port() else { return false; };
        port.command(route.dac, verb::SET_STREAM_FORMAT, format);
        port.command(route.dac, verb::SET_CHANNEL_STREAMID, verb::channel_streamid_payload(tag, 0));
        true
    }

    /// As [`Self::prepare_playback`], for the capture converter.
    /// # C: O(periods + one command pair)
    pub fn prepare_capture(&mut self, alsa_format: u32, rate: u32, channels: u8,
                           period_bytes: u32) -> bool {
        let Some(codec) = self.codec.clone() else { return false; };
        let Some(route) = self.plan.as_ref().and_then(|plan| plan.primary_capture().cloned()) else { return false; };
        let par_pcm = codec.pcm_caps_of(route.adc);
        let Some(format) = crate::stream_fmt::format_for(alsa_format, rate, u32::from(channels), par_pcm)
            else { return false; };
        let frame_bytes = sound::format::frame_bytes(alsa_format, u32::from(channels));
        let period = crate::bdl::align_period(period_bytes.min(crate::stream::MAX_PERIOD_BYTES));
        let geometry = Geometry { period_bytes: period, periods: crate::stream::PERIODS };
        let regs = self.regs;
        if !self.capture.setup(&regs, format, geometry, frame_bytes) { return false; }
        self.capture.silence();
        let tag = self.capture.tag;
        let Some(port) = self.port() else { return false; };
        port.command(route.adc, verb::SET_STREAM_FORMAT, format);
        port.command(route.adc, verb::SET_CHANNEL_STREAMID, verb::channel_streamid_payload(tag, 0));
        true
    }

    /// Detach a converter from its stream tag, which is what frees the
    /// stream for another user. # C: O(one command)
    pub fn release(&mut self, playback: bool) {
        let Some(plan) = self.plan.clone() else { return; };
        let nid = if playback { plan.primary().map(|route| route.dac) }
                  else { plan.primary_capture().map(|route| route.adc) };
        let Some(nid) = nid else { return; };
        let Some(port) = self.port() else { return; };
        port.command(nid, verb::SET_CHANNEL_STREAMID, 0);
    }

    /// Read one amplifier's gain, in steps. # C: O(one command)
    pub fn amp_read(&mut self, nid: u8, output: bool, index: u8, left: bool) -> Option<(bool, u8)> {
        let port = self.port()?;
        port.command(nid, verb::GET_AMP_GAIN_MUTE, widget::amp_get_payload(output, index, left))
            .map(widget::amp_decode)
    }

    /// Write one amplifier's gain and mute. # C: O(one command)
    pub fn amp_write(&mut self, nid: u8, output: bool, index: u8, left: bool, right: bool,
                     mute: bool, gain: u8) -> bool {
        let Some(port) = self.port() else { return false; };
        port.command(nid, verb::SET_AMP_GAIN_MUTE,
                     widget::amp_set_payload(output, index, left, right, mute, gain)).is_some()
    }

    /// Service one controller interrupt: acknowledge every stream that
    /// completed a period and drain the response ring.
    /// # C: O(streams + new responses)
    pub fn handle_interrupt(&mut self) -> bool {
        let status = self.regs.r32(REG_INTSTS);
        if status == 0 || status == u32::MAX { return false; }
        for index in [self.playback.index, self.capture.index] {
            if status & (1u32 << index) == 0 { continue; }
            let sd_status = self.regs.r8(self.regs.sd(index) + SD_STS);
            self.regs.w8(self.regs.sd(index) + SD_STS, SD_INT_MASK as u8);
            let _ = sd_status;
        }
        let rirb = self.regs.r8(REG_RIRBSTS);
        if rirb & RIRBSTS_INT_MASK != 0 {
            // Acknowledge before draining, so a response arriving during the
            // drain still raises the next interrupt.
            self.regs.w8(REG_RIRBSTS, RIRBSTS_INT_MASK);
            if rirb & RIRBSTS_IRQ != 0 { transport::update_rirb(&self.regs, &mut self.rings); }
        }
        true
    }

    /// Drain the queued unsolicited responses, re-sense every jack they
    /// name, and report the ones whose presence changed. Sensing needs a
    /// codec round trip, so this runs in process context rather than in the
    /// interrupt that queued the response.
    /// # C: O(queued events × one command pair)
    pub fn refresh_jacks(&mut self) -> alloc::vec::Vec<(u8, bool)> {
        let mut changed = alloc::vec::Vec::new();
        let mut woken = [false; MAX_JACKS];
        while let Some((value, _)) = self.take_unsolicited() {
            let tag = verb::unsol_tag(value);
            for index in 0..self.jack_count {
                if self.jack_tags[index].1 == tag { woken[index] = true; }
            }
        }
        for index in 0..self.jack_count {
            if !woken[index] { continue; }
            let pin = self.jack_tags[index].0;
            let present = self.jack_sense(pin);
            if present == self.jack_present[index] { continue; }
            self.jack_present[index] = present;
            changed.push((pin, present));
        }
        if !changed.is_empty() { self.apply_automute(); }
        changed
    }

    /// Silence the fixed outputs while a headphone jack is occupied, and
    /// restore them when it is not — a speaker that keeps playing into a
    /// plugged-in headset is the defect this prevents.
    /// # C: O(routes)
    pub fn apply_automute(&mut self) {
        let headphone_present = self.jack_present[..self.jack_count].iter().any(|present| *present);
        let Some(plan) = self.plan.clone() else { return; };
        let Some(port) = self.port() else { return; };
        for route in plan.outputs.iter().chain(plan.speaker.iter()) {
            let ctl = if headphone_present { 0 } else { widget::PIN_OUT };
            port.command(route.pin, verb::SET_PIN_WIDGET_CONTROL, u16::from(ctl));
            if headphone_present {
                port.command(route.pin, verb::SET_EAPD_BTLENABLE, 0);
            } else {
                port.command(route.pin, verb::SET_EAPD_BTLENABLE, u16::from(widget::EAPDBTL_EAPD));
            }
        }
    }

    /// Take one queued unsolicited response. # C: O(UNSOL_QUEUE)
    pub fn take_unsolicited(&mut self) -> Option<(u32, u32)> {
        if self.rings.unsolicited_count == 0 { return None; }
        let head = self.rings.unsolicited[0];
        self.rings.unsolicited.copy_within(1.., 0);
        self.rings.unsolicited_count -= 1;
        Some(head)
    }

    /// Quiesce for removal or shutdown. # C: O(1)
    pub fn quiesce(&mut self) {
        let regs = self.regs;
        self.playback.stop(&regs);
        self.capture.stop(&regs);
        regs.w32(REG_INTCTL, 0);
        transport::stop_cmd_io(&regs);
    }
}
