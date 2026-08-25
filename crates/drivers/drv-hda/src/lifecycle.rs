use super::*;

impl Hda {
    /// Take the controller out of reset, start the command rings, and return
    /// the codec-presence mask. # C: O(reset timeouts)
    pub fn bring_up(&mut self) -> Option<u16> {
        let present = transport::reset_link(&self.regs)?;
        transport::clear_interrupts(&self.regs, self.streams);
        transport::init_cmd_io(&self.regs, &mut transport::lock_regs(&self.rings), self.interrupts);
        let (lo, hi) = crate::position::base_words(self.posbuf_pa);
        self.regs.w32(REG_DPLBASE, lo);
        self.regs.w32(REG_DPUBASE, hi);
        if self.interrupts { self.regs.set32(REG_INTCTL, INT_CTRL_EN | INT_GLOBAL_EN); }
        Some(present)
    }

    /// Enable controller and response interrupts after the IRQ endpoint is
    /// reachable from the registry. # C: O(1)
    pub fn enable_interrupts(&mut self) {
        self.regs.set8(REG_RIRBCTL, RIRBCTL_IRQ_EN);
        self.regs.set32(REG_INTCTL, INT_CTRL_EN | INT_GLOBAL_EN);
        self.interrupts = true;
    }

    /// Enumerate every codec slot that answers with an audio function group
    /// and build one routing plan per codec. Linux keeps every successful
    /// codec on the controller bus; the PCM maps below preserve that ownership
    /// when the shared stream pool is exposed through the sound card. # C: O(codecs × widgets)
    pub fn enumerate(&mut self, present: u16) -> bool {
        self.codecs.clear();
        self.playback_routes.clear();
        self.capture_routes.clear();
        for addr in 0..MAX_CODECS {
            if present & (1 << addr) == 0 { continue; }
            let port = CodecPort::new(self.regs, &self.rings, addr);
            let Some(codec) = graph::parse(&port, addr) else { continue; };
            let plan = generic::build(&codec);
            if plan.all_outputs().next().is_none() && plan.primary_capture().is_none() { continue; }
            self.codecs.push(CodecState::new(codec, plan));
        }
        for (codec_index, state) in self.codecs.iter().enumerate() {
            for route_index in 0..state.plan.all_outputs().count() {
                if self.playback_routes.len() == self.playback.len() { break; }
                self.playback_routes.push((codec_index, route_index));
            }
            for route_index in 0..state.plan.captures.len() {
                if self.capture_routes.len() == self.capture.len() { break; }
                self.capture_routes.push((codec_index, route_index));
            }
        }
        !self.codecs.is_empty()
    }

    pub(crate) fn port_for(&self, codec_index: usize) -> Option<CodecPort<'_>> {
        let addr = self.codecs.get(codec_index)?.codec.addr;
        let regs = self.regs;
        Some(CodecPort::new(regs, &self.rings, addr))
    }

    pub(crate) fn port(&self) -> Option<CodecPort<'_>> { self.port_for(0) }

    pub fn primary_codec(&self) -> Option<&Codec> { self.codecs.first().map(|state| &state.codec) }
    pub fn primary_plan(&self) -> Option<&Plan> { self.codecs.first().map(|state| &state.plan) }
    pub fn primary_capture_source(&self) -> u32 {
        self.codecs.first().map(|state| state.capture_source).unwrap_or(0)
    }
    pub fn primary_multi_io_active(&self) -> u8 {
        self.codecs.first().map(|state| state.multi_io_active).unwrap_or(0)
    }

    pub fn amp_read_for(&mut self, codec_index: usize, nid: u8, output: bool, index: u8, left: bool) -> Option<(bool, u8)> {
        let port = self.port_for(codec_index)?;
        port.command(nid, verb::GET_AMP_GAIN_MUTE, widget::amp_get_payload(output, index, left))
            .map(widget::amp_decode)
    }

    pub fn amp_write_for(&mut self, codec_index: usize, nid: u8, output: bool, index: u8,
                         left: bool, right: bool, mute: bool, gain: u8) -> bool {
        let Some(port) = self.port_for(codec_index) else { return false; };
        port.command(nid, verb::SET_AMP_GAIN_MUTE,
                     widget::amp_set_payload(output, index, left, right, mute, gain)).is_some()
    }
}

