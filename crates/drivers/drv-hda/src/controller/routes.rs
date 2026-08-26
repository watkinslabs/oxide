use super::*;

impl Hda {
    pub fn pcm_devices(&self) -> u32 {
        self.playback_routes.len().max(self.capture_routes.len()) as u32
    }

    pub fn pcm_caps(&self, device: u32, playback: bool) -> sound::ops::Caps {
        if playback {
            let &(codec_index, route_index) = self.playback_routes.get(device as usize)?;
            let state = self.codecs.get(codec_index)?;
            let route = state.plan.output_for(route_index as u32)?;
            let caps = state.codec.pcm_caps_of(route.dac);
            let formats = crate::stream_fmt::pcm_format_mask(caps);
            let rates = crate::stream_fmt::pcm_rate_mask(caps);
            if formats == 0 || rates == 0 { return None; }
            let base = state.codec.widget(route.dac).map(|w| widget::widget_channels(w.wcaps)).unwrap_or(2);
            let channels = base + u32::from(state.multi_io_active) * 2;
            Some((formats, rates, 1, channels.min(u8::MAX as u32) as u8))
        } else {
            let &(codec_index, route_index) = self.capture_routes.get(device as usize)?;
            let state = self.codecs.get(codec_index)?;
            let route = state.plan.capture_for(if device == 0 { state.capture_source } else { route_index as u32 })?;
            let caps = state.codec.pcm_caps_of(route.adc);
            let formats = crate::stream_fmt::pcm_format_mask(caps);
            let rates = crate::stream_fmt::pcm_rate_mask(caps);
            if formats == 0 || rates == 0 { return None; }
            let channels = state.codec.widget(route.adc).map(|w| widget::widget_channels(w.wcaps)).unwrap_or(2);
            Some((formats, rates, 1, channels.min(u8::MAX as u32) as u8))
        }
    }

    /// Put the function group and every widget into D0. # C: O(widgets)
    fn power_up_for(&mut self, codec_index: usize) {
        let Some(codec) = self.codecs.get(codec_index).map(|state| state.codec.clone()) else { return; };
        let Some(port) = self.port_for(codec_index) else { return; };
        port.command(codec.afg, verb::SET_POWER_STATE, u16::from(verb::PWRST_D0));
        for w in codec.widgets.iter().filter(|w| w.wcaps & widget::WCAP_POWER != 0) {
            port.command(w.nid, verb::SET_POWER_STATE, u16::from(verb::PWRST_D0));
        }
    }


    /// Unmute and open every amplifier on a route, and write the selection
    /// index into each selector it passes through. # C: O(path length)
    fn activate_for(&mut self, codec_index: usize, route: &OutputRoute, output_pin_ctl: u8) {
        let Some(codec) = self.codecs.get(codec_index).map(|state| state.codec.clone()) else { return; };
        let hops: alloc::vec::Vec<_> = route.path.hops.clone();
        let Some(port) = self.port_for(codec_index) else { return; };
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
        for codec_index in 0..self.codecs.len() {
            self.power_up_for(codec_index);
            let Some(plan) = self.codecs.get(codec_index).map(|state| state.plan.clone()) else { continue; };
            for route in plan.outputs.iter() { self.activate_for(codec_index, route, widget::PIN_OUT); }
            for route in plan.hp.iter() { self.activate_for(codec_index, route, widget::PIN_HP); }
            for route in plan.speaker.iter() { self.activate_for(codec_index, route, widget::PIN_OUT); }
            for route in plan.digital.iter() { self.activate_for(codec_index, route, widget::PIN_OUT); }
            self.set_multi_io_for(codec_index, 0);
            self.apply_capture_for(codec_index, &plan);
            self.arm_jacks_for(codec_index, &plan);
        }
    }

    /// Retask the generic parser's line-in/mic candidates. The default is
    /// capture mode; playback setup raises this to the number of extra stereo
    /// pairs required by the requested channel count.
    pub fn set_multi_io_for(&mut self, codec_index: usize, pairs: u8) -> bool {
        let Some(state) = self.codecs.get(codec_index) else { return pairs == 0; };
        let plan = state.plan.clone();
        if usize::from(pairs) > plan.multi_io.len() { return false; }
        let wanted = pairs;
        if wanted == state.multi_io_active { return true; }
        if self.playback.iter().any(|stream| stream.running) { return false; }
        let codec = state.codec.clone();
        for (index, route) in plan.multi_io.iter().enumerate() {
            if index < wanted as usize {
                let output_route = generic::output_route_for_multi_io(&codec, route);
                self.activate_for(codec_index, &output_route, widget::PIN_OUT);
            }
        }
        let Some(port) = self.port_for(codec_index) else { return false; };
        for (index, route) in plan.multi_io.iter().enumerate() {
            if index >= wanted as usize {
                for hop in route.path.hops.iter() {
                    let Some(w) = codec.widget(hop.nid) else { continue; };
                    if let Some(caps) = w.out_amp(codec.fg_amp_out) {
                        let amp = widget::amp_caps(caps);
                        if amp.mute {
                            port.command(hop.nid, verb::SET_AMP_GAIN_MUTE,
                                         widget::amp_set_payload(true, 0, true, true, true, 0));
                        }
                    }
                }
                if codec.widget(route.pin).is_some_and(|w| w.pincap & widget::PINCAP_EAPD != 0) {
                    port.command(route.pin, verb::SET_EAPD_BTLENABLE, 0);
                }
                port.command(route.pin, verb::SET_PIN_WIDGET_CONTROL, u16::from(widget::PIN_IN));
                for hop in route.path.hops.iter() {
                    let Some(w) = codec.widget(hop.nid) else { continue; };
                    if let (Some(caps), Some(sel)) = (w.in_amp(codec.fg_amp_in), hop.sel) {
                        let amp = widget::amp_caps(caps);
                        let gain = amp.offset.min(amp.num_steps) as u8;
                        port.command(hop.nid, verb::SET_AMP_GAIN_MUTE,
                                     widget::amp_set_payload(false, sel, true, true, false, gain));
                    }
                }
            }
        }
        if let Some(state) = self.codecs.get_mut(codec_index) { state.multi_io_active = wanted; }
        true
    }

    pub fn set_multi_io(&mut self, pairs: u8) -> bool { self.set_multi_io_for(0, pairs) }

    fn apply_capture_for(&mut self, codec_index: usize, plan: &Plan) {
        let Some(codec) = self.codecs.get(codec_index).map(|state| state.codec.clone()) else { return; };
        let routes = plan.captures.clone();
        let Some(port) = self.port_for(codec_index) else { return; };
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


    fn arm_jacks_for(&mut self, codec_index: usize, plan: &Plan) {
        let Some(codec) = self.codecs.get(codec_index).map(|state| state.codec.clone()) else { return; };
        let mut pins: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        for route in plan.hp.iter().chain(plan.outputs.iter()) {
            if pins.len() == MAX_JACKS { break; }
            if codec.widget(route.pin).is_some_and(graph::jack_detectable) { pins.push(route.pin); }
        }
        let Some(port) = self.port_for(codec_index) else { return; };
        for (tag, pin) in pins.iter().enumerate() {
            port.command(*pin, verb::SET_UNSOLICITED_ENABLE, verb::unsol_enable_payload(tag as u8));
        }
        if let Some(state) = self.codecs.get_mut(codec_index) {
            state.jack_count = pins.len();
            for (index, pin) in pins.iter().enumerate() { state.jack_tags[index] = (*pin, index as u8); }
        }
    }


    /// Is something plugged into `pin`? A pin that needs a trigger is asked
    /// to sense before it is read. # C: O(one command pair)
    pub fn jack_sense_for(&mut self, codec_index: usize, pin: u8) -> bool {
        let Some(codec) = self.codecs.get(codec_index).map(|state| state.codec.clone()) else { return false; };
        let trigger = codec.widget(pin).is_some_and(|w| w.pincap & widget::PINCAP_TRIG_REQ != 0);
        let Some(port) = self.port_for(codec_index) else { return false; };
        if trigger { port.command(pin, verb::SET_PIN_SENSE, 0); }
        port.command(pin, verb::GET_PIN_SENSE, 0)
            .is_some_and(|value| value & verb::PINSENSE_PRESENCE != 0)
    }

    pub fn jack_sense(&mut self, pin: u8) -> bool { self.jack_sense_for(0, pin) }

    /// Bind the playback converter to the output stream and program both
    /// sides for `alsa_format`/`rate`/`channels`.
    /// # C: O(periods + one command pair)
    pub fn prepare_playback(&mut self, device: u32, alsa_format: u32, rate: u32, channels: u8,
                            period_bytes: u32) -> bool {
        let Some(&(codec_index, route_index)) = self.playback_routes.get(device as usize) else { return false; };
        let Some(state) = self.codecs.get(codec_index) else { return false; };
        let codec = state.codec.clone();
        let Some(route) = state.plan.output_for(route_index as u32).cloned() else { return false; };
        let base_channels = codec.widget(route.dac).map(|w| widget::widget_channels(w.wcaps)).unwrap_or(2);
        let extra_channels = channels.saturating_sub(base_channels as u8);
        if extra_channels != 0 && extra_channels & 1 != 0 { return false; }
        let extra_pairs = u32::from(extra_channels) / 2;
        if !self.set_multi_io_for(codec_index, extra_pairs as u8) { return false; }
        let par_pcm = codec.pcm_caps_of(route.dac);
        let Some(format) = crate::stream_fmt::format_for(alsa_format, rate, u32::from(channels), par_pcm)
            else { return false; };
        let frame_bytes = sound::format::frame_bytes(alsa_format, u32::from(channels));
        let period = crate::bdl::align_period(period_bytes.min(crate::stream::MAX_PERIOD_BYTES));
        let geometry = Geometry { period_bytes: period, periods: crate::stream::PERIODS };
        let regs = self.regs;
        let Some(stream) = self.playback.get_mut(device as usize) else { return false; };
        if !stream.setup(&regs, format, geometry, frame_bytes) { return false; }
        stream.silence();
        let tag = stream.tag;
        let Some(port) = self.port_for(codec_index) else { return false; };
        port.command(route.dac, verb::SET_STREAM_FORMAT, format);
        port.command(route.dac, verb::SET_CHANNEL_STREAMID, verb::channel_streamid_payload(tag, 0));
        if let Some(plan) = self.codecs.get(codec_index).map(|state| state.plan.clone()) {
            let active = self.codecs.get(codec_index).map(|state| state.multi_io_active).unwrap_or(0);
            for (index, multi) in plan.multi_io.iter().enumerate().take(active as usize) {
                port.command(multi.dac, verb::SET_STREAM_FORMAT, format);
                port.command(multi.dac, verb::SET_CHANNEL_STREAMID,
                             verb::channel_streamid_payload(tag, ((index + 1) * 2) as u8));
            }
        }
        true
    }

    /// As [`Self::prepare_playback`], for the capture converter.
    /// # C: O(periods + one command pair)
    pub fn prepare_capture(&mut self, device: u32, alsa_format: u32, rate: u32, channels: u8,
                           period_bytes: u32) -> bool {
        let Some(&(codec_index, route_index)) = self.capture_routes.get(device as usize) else { return false; };
        let Some(state) = self.codecs.get(codec_index) else { return false; };
        let codec = state.codec.clone();
        let route_device = if device == 0 { state.capture_source } else { route_index as u32 };
        let Some(route) = state.plan.capture_for(route_device).cloned() else { return false; };
        if state.plan.multi_io.iter().take(state.multi_io_active as usize).any(|multi| multi.pin == route.pin) { return false; }
        let par_pcm = codec.pcm_caps_of(route.adc);
        let Some(format) = crate::stream_fmt::format_for(alsa_format, rate, u32::from(channels), par_pcm)
            else { return false; };
        let frame_bytes = sound::format::frame_bytes(alsa_format, u32::from(channels));
        let period = crate::bdl::align_period(period_bytes.min(crate::stream::MAX_PERIOD_BYTES));
        let geometry = Geometry { period_bytes: period, periods: crate::stream::PERIODS };
        let regs = self.regs;
        let Some(stream) = self.capture.get_mut(device as usize) else { return false; };
        if !stream.setup(&regs, format, geometry, frame_bytes) { return false; }
        stream.silence();
        let tag = stream.tag;
        let Some(port) = self.port_for(codec_index) else { return false; };
        port.command(route.adc, verb::SET_STREAM_FORMAT, format);
        port.command(route.adc, verb::SET_CHANNEL_STREAMID, verb::channel_streamid_payload(tag, 0));
        true
    }

    /// Detach a converter from its stream tag, which is what frees the
    /// stream for another user. # C: O(one command)
    pub fn release(&mut self, device: u32, playback: bool) {
        let (codec_index, route_index) = if playback {
            let Some(&mapping) = self.playback_routes.get(device as usize) else { return; };
            mapping
        } else {
            let Some(&mapping) = self.capture_routes.get(device as usize) else { return; };
            mapping
        };
        let Some(state) = self.codecs.get(codec_index) else { return; };
        let route_device = if !playback && device == 0 { state.capture_source } else { route_index as u32 };
        let nid = if playback { state.plan.output_for(route_index as u32).map(|route| route.dac) }
                  else { state.plan.capture_for(route_device).map(|route| route.adc) };
        let Some(nid) = nid else { return; };
        let Some(port) = self.port_for(codec_index) else { return; };
        port.command(nid, verb::SET_CHANNEL_STREAMID, 0);
        if playback {
            if let Some(plan) = self.codecs.get(codec_index).map(|state| state.plan.clone()) {
                let active = self.codecs.get(codec_index).map(|state| state.multi_io_active).unwrap_or(0);
                for route in plan.multi_io.iter().take(active as usize) {
                    port.command(route.dac, verb::SET_CHANNEL_STREAMID, 0);
                }
            }
            drop(port);
            let _ = self.set_multi_io_for(codec_index, 0);
        }
    }

    /// Select the capture route used by PCM capture device zero.
    /// # C: O(one command)
    pub fn set_capture_source(&mut self, source: u32) -> bool {
        let Some(state) = self.codecs.first() else { return false; };
        let plan = &state.plan;
        if plan.capture_for(source).is_none() { return false; }
        if state.capture_source == source { return true; }
        if self.capture.first().is_some_and(|stream| stream.running) { return false; }
        self.release(0, false);
        if let Some(state) = self.codecs.first_mut() { state.capture_source = source; }
        true
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

    /// Program the codec's standard digital beep generator.
    /// # C: O(one command)
    pub fn beep(&mut self, hz: u32) -> bool {
        let Some(codec) = self.codecs.first().map(|state| state.codec.clone()) else { return false; };
        let Some(beep) = codec.widgets.iter()
            .find(|widget| widget::widget_type(widget.wcaps) == widget::WidgetType::Beep) else { return false; };
        let tone = if hz == 0 { 0 } else { (12_000 / hz).clamp(1, 0xff) as u16 };
        let Some(port) = self.port() else { return false; };
        port.command(beep.nid, verb::SET_BEEP_CONTROL, tone).is_some()
    }

    /// Drain the queued unsolicited responses, re-sense every jack they
    /// name, and report the ones whose presence changed. Sensing needs a
    /// codec round trip, so this runs in process context rather than in the
    /// interrupt that queued the response.
    /// # C: O(queued events × one command pair)
    pub fn refresh_jacks(&mut self) -> alloc::vec::Vec<(usize, u8, bool)> {
        let mut changed = alloc::vec::Vec::new();
        let mut woken = [[false; MAX_JACKS]; 16];
        while let Some((value, extended)) = self.take_unsolicited() {
            let tag = verb::unsol_tag(value);
            let addr = (extended & crate::uapi::RIRB_EX_ADDR_MASK) as u8;
            for (codec_index, state) in self.codecs.iter().enumerate() {
                if state.codec.addr != addr { continue; }
                for index in 0..state.jack_count {
                    if state.jack_tags[index].1 == tag { woken[codec_index][index] = true; }
                }
            }
        }
        for codec_index in 0..self.codecs.len() {
            let jack_count = self.codecs[codec_index].jack_count;
            for index in 0..jack_count {
                if !woken[codec_index][index] { continue; }
                let pin = self.codecs[codec_index].jack_tags[index].0;
                let present = self.jack_sense_for(codec_index, pin);
                let prior = self.codecs[codec_index].jack_present[index];
                if present == prior { continue; }
                self.codecs[codec_index].jack_present[index] = present;
                changed.push((codec_index, pin, present));
            }
        }
        if !changed.is_empty() { self.apply_automute(); }
        changed
    }

    /// Silence the fixed outputs while a headphone jack is occupied, and
    /// restore them when it is not — a speaker that keeps playing into a
    /// plugged-in headset is the defect this prevents.
    /// # C: O(routes)
    pub fn apply_automute(&mut self) {
        for codec_index in 0..self.codecs.len() {
            let state = &self.codecs[codec_index];
            let headphone_present = state.jack_present[..state.jack_count].iter().any(|present| *present);
            let plan = state.plan.clone();
            let Some(port) = self.port_for(codec_index) else { continue; };
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
    }

    /// Take one queued unsolicited response. # C: O(UNSOL_QUEUE)
    pub fn take_unsolicited(&mut self) -> Option<(u32, u32)> {
        let mut rings = transport::lock_regs(&self.rings);
        if rings.unsolicited_count == 0 { return None; }
        let head = rings.unsolicited[0];
        rings.unsolicited.copy_within(1.., 0);
        rings.unsolicited_count -= 1;
        Some(head)
    }

    /// Quiesce for removal or shutdown. # C: O(1)
    pub fn quiesce(&mut self) {
        let regs = self.regs;
        for stream in &mut self.playback { stream.stop(&regs); }
        for stream in &mut self.capture { stream.stop(&regs); }
        regs.w32(REG_INTCTL, 0);
        regs.w32(REG_DPLBASE, 0);
        regs.w32(REG_DPUBASE, 0);
        transport::stop_cmd_io(&regs);
    }
}

