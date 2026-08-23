// Synthetic codecs for the hosted tests. A `FakeCodec` answers exactly the
// commands a real codec answers, so the enumeration and parser run unchanged
// against a recorded node table with no controller present.

use alloc::vec::Vec;

use crate::defcfg;
use crate::graph::CodecBus;
use crate::stream_fmt;
use crate::verb;
use crate::widget;

pub struct FakeCodec {
    entries: Vec<(u8, u16, u16, u32)>,
}

impl CodecBus for FakeCodec {
    fn command(&self, nid: u8, cmd: u16, payload: u16) -> Option<u32> {
        self.entries.iter()
            .find(|(n, c, p, _)| *n == nid && *c == cmd && *p == payload)
            .map(|(_, _, _, value)| *value)
    }
}

/// Builder for a codec node table.
pub struct Builder {
    entries: Vec<(u8, u16, u16, u32)>,
    afg: u8,
    lowest: u8,
    highest: u8,
}

/// PCM capability every fixture codec reports: 44.1/48 kHz, 16- and 32-bit.
pub const FIXTURE_PCM: u32 = (1 << 5) | (1 << 6) | stream_fmt::SUPPCM_BITS_16 | stream_fmt::SUPPCM_BITS_32;

/// An amplifier with 0x4a steps of 0.75 dB, 0 dB at step 0x27, mutable.
pub const FIXTURE_AMP: u32 = 0x27 | (0x4a << 8) | (0x02 << 16) | (1 << 31);

impl Builder {
    /// # C: O(1)
    pub fn new(vendor_id: u32, afg: u8, first_widget: u8) -> Self {
        let mut builder = Self { entries: Vec::new(), afg, lowest: first_widget, highest: first_widget };
        builder.put(verb::NODE_ROOT, verb::PARAMETERS, verb::PAR_VENDOR_ID, vendor_id);
        builder.put(verb::NODE_ROOT, verb::PARAMETERS, verb::PAR_SUBSYSTEM_ID, 0x1af4_0000);
        builder.put(verb::NODE_ROOT, verb::PARAMETERS, verb::PAR_REV_ID, 0x0010_0000);
        builder.put(verb::NODE_ROOT, verb::PARAMETERS, verb::PAR_NODE_COUNT, (u32::from(afg) << 16) | 1);
        builder.put(afg, verb::PARAMETERS, verb::PAR_FUNCTION_TYPE, verb::GRP_AUDIO_FUNCTION);
        builder.put(afg, verb::PARAMETERS, verb::PAR_PCM, FIXTURE_PCM);
        builder.put(afg, verb::PARAMETERS, verb::PAR_STREAM, stream_fmt::SUPFMT_PCM);
        builder.put(afg, verb::PARAMETERS, verb::PAR_AMP_OUT_CAP, FIXTURE_AMP);
        builder.put(afg, verb::PARAMETERS, verb::PAR_AMP_IN_CAP, FIXTURE_AMP);
        builder.put(afg, verb::PARAMETERS, verb::PAR_POWER_STATE, 0x0f);
        builder
    }

    fn put(&mut self, nid: u8, cmd: u16, payload: u16, value: u32) {
        self.entries.push((nid, cmd, payload, value));
    }

    fn widget(&mut self, nid: u8, wcaps: u32, conns: &[u8]) -> &mut Self {
        if nid < self.lowest { self.lowest = nid; }
        if nid > self.highest { self.highest = nid; }
        self.put(nid, verb::PARAMETERS, verb::PAR_AUDIO_WIDGET_CAP, wcaps);
        if !conns.is_empty() {
            self.put(nid, verb::PARAMETERS, verb::PAR_CONNLIST_LEN, conns.len() as u32);
            for (index, chunk) in conns.chunks(4).enumerate() {
                let mut word = 0u32;
                for (slot, &nid) in chunk.iter().enumerate() { word |= u32::from(nid) << (8 * slot); }
                self.put(nid, verb::GET_CONNECT_LIST, (index * 4) as u16, word);
            }
        }
        self
    }

    /// A DAC with an output amplifier. # C: O(1)
    pub fn dac(&mut self, nid: u8) -> &mut Self {
        self.widget(nid, widget::WCAP_STEREO | widget::WCAP_OUT_AMP, &[])
    }

    /// An ADC with an input amplifier fed by `conns`. # C: O(conns)
    pub fn adc(&mut self, nid: u8, conns: &[u8]) -> &mut Self {
        let caps = widget::WCAP_STEREO | widget::WCAP_IN_AMP | widget::WCAP_CONN_LIST
                   | (0x1 << widget::WCAP_TYPE_SHIFT);
        self.widget(nid, caps, conns)
    }

    pub fn digital_adc(&mut self, nid: u8, conns: &[u8]) -> &mut Self {
        let caps = widget::WCAP_STEREO | widget::WCAP_IN_AMP | widget::WCAP_CONN_LIST
                   | widget::WCAP_DIGITAL | (0x1 << widget::WCAP_TYPE_SHIFT);
        self.widget(nid, caps, conns)
    }

    /// A mixer summing `conns`. # C: O(conns)
    pub fn mixer(&mut self, nid: u8, conns: &[u8]) -> &mut Self {
        let caps = widget::WCAP_STEREO | widget::WCAP_IN_AMP | widget::WCAP_CONN_LIST
                   | (0x2 << widget::WCAP_TYPE_SHIFT);
        self.widget(nid, caps, conns)
    }

    /// A selector choosing between `conns`. # C: O(conns)
    pub fn selector(&mut self, nid: u8, conns: &[u8]) -> &mut Self {
        let caps = widget::WCAP_STEREO | widget::WCAP_CONN_LIST | (0x3 << widget::WCAP_TYPE_SHIFT);
        self.widget(nid, caps, conns)
    }

    /// A pin with the given default configuration and capabilities.
    /// # C: O(conns)
    pub fn pin(&mut self, nid: u8, defcfg: u32, pincap: u32, conns: &[u8]) -> &mut Self {
        let mut caps = widget::WCAP_STEREO | (0x4 << widget::WCAP_TYPE_SHIFT);
        if !conns.is_empty() { caps |= widget::WCAP_CONN_LIST; }
        if pincap & widget::PINCAP_PRES_DETECT != 0 { caps |= widget::WCAP_UNSOL_CAP; }
        self.widget(nid, caps, conns);
        self.put(nid, verb::PARAMETERS, verb::PAR_PIN_CAP, pincap);
        self.put(nid, verb::GET_CONFIG_DEFAULT, 0, defcfg);
        self
    }

    /// Finish the table. The function group's node range spans every widget
    /// added, the way a real codec numbers its nodes contiguously; gaps are
    /// simply nodes that answer nothing.
    /// # C: O(entries)
    pub fn build(&mut self) -> FakeCodec {
        let mut entries = self.entries.clone();
        let count = u32::from(self.highest) - u32::from(self.lowest) + 1;
        entries.push((self.afg, verb::PARAMETERS, verb::PAR_NODE_COUNT,
                      (u32::from(self.lowest) << 16) | count));
        FakeCodec { entries }
    }
}

/// Compose a pin default-configuration word. # C: O(1)
pub fn cfg(device: u8, port: u8, location: u8, assoc: u8, sequence: u8) -> u32 {
    (u32::from(port) << defcfg::PORT_CONN_SHIFT)
        | (u32::from(location) << defcfg::LOCATION_SHIFT)
        | (u32::from(device) << defcfg::DEVICE_SHIFT)
        | (u32::from(assoc) << defcfg::ASSOC_SHIFT)
        | u32::from(sequence)
}

/// The codec QEMU's `hda-duplex` presents: one DAC behind one line-out pin,
/// one ADC behind one line-in pin.
/// # C: O(nodes)
pub fn qemu_duplex() -> FakeCodec {
    let mut builder = Builder::new(0x1af4_0011, 1, 2);
    builder.dac(2);
    builder.pin(3, cfg(defcfg::DEV_LINE_OUT, defcfg::PORT_COMPLEX, defcfg::LOC_REAR, 1, 0),
                widget::PINCAP_OUT | widget::PINCAP_PRES_DETECT, &[2]);
    builder.adc(4, &[5]);
    builder.pin(5, cfg(defcfg::DEV_LINE_IN, defcfg::PORT_COMPLEX, defcfg::LOC_REAR, 2, 0),
                widget::PINCAP_IN | widget::PINCAP_PRES_DETECT, &[]);
    builder.build()
}

/// A laptop-shaped analog codec: two DACs, an internal speaker, a headphone
/// jack, an internal microphone and an external microphone through a mixer.
/// # C: O(nodes)
pub fn laptop_codec() -> FakeCodec {
    let mut builder = Builder::new(0x10ec_0888, 1, 2);
    builder.dac(2);
    builder.dac(3);
    builder.pin(0x14, cfg(defcfg::DEV_SPEAKER, defcfg::PORT_FIXED, defcfg::LOC_INTERNAL, 1, 0),
                widget::PINCAP_OUT, &[2]);
    builder.pin(0x15, cfg(defcfg::DEV_HP_OUT, defcfg::PORT_COMPLEX, defcfg::LOC_FRONT, 2, 0),
                widget::PINCAP_OUT | widget::PINCAP_HP_DRV | widget::PINCAP_PRES_DETECT, &[3]);
    builder.pin(0x12, cfg(defcfg::DEV_MIC_IN, defcfg::PORT_FIXED, defcfg::LOC_INTERNAL, 3, 0),
                widget::PINCAP_IN, &[]);
    builder.pin(0x18, cfg(defcfg::DEV_MIC_IN, defcfg::PORT_COMPLEX, defcfg::LOC_FRONT, 4, 0),
                widget::PINCAP_IN | widget::PINCAP_PRES_DETECT, &[]);
    builder.selector(0x22, &[0x12, 0x18]);
    builder.adc(0x08, &[0x22]);
    builder.build()
}
