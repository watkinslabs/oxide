// Codec widget graph: the model plus the enumeration that fills it from a
// codec. Enumeration is expressed over a `CodecBus`, so the whole walk runs
// against a recorded node table with no controller present.

use alloc::vec::Vec;

use crate::connlist;
use crate::defcfg;
use crate::verb;
use crate::widget::{self, WidgetType};

/// Anything that can put one command to a codec and return its response.
pub trait CodecBus {
    /// `None` when the codec did not answer. # C: O(command round trip)
    fn command(&self, nid: u8, verb: u16, payload: u16) -> Option<u32>;
}

/// A parameter read, the codec's most common command shape. # C: O(1)
pub fn read_param<C: CodecBus>(bus: &C, nid: u8, param: u16) -> Option<u32> {
    bus.command(nid, verb::PARAMETERS, verb::param_payload(param))
}

/// One widget node and every capability the parser consults.
#[derive(Clone, Debug)]
pub struct Widget {
    pub nid: u8,
    pub wcaps: u32,
    pub conns: Vec<u8>,
    /// Pin widgets only.
    pub pincap: u32,
    pub defcfg: u32,
    pub amp_in: u32,
    pub amp_out: u32,
    /// Converter widgets that override the function group's PCM capability.
    pub par_pcm: u32,
}

impl Widget {
    /// # C: O(1)
    pub fn kind(&self) -> WidgetType { widget::widget_type(self.wcaps) }
    /// # C: O(1)
    pub fn is_pin(&self) -> bool { self.kind() == WidgetType::Pin }
    /// # C: O(1)
    pub fn is_dac(&self) -> bool { self.kind() == WidgetType::AudioOut }
    /// # C: O(1)
    pub fn is_adc(&self) -> bool { self.kind() == WidgetType::AudioIn }
    /// # C: O(1)
    pub fn digital(&self) -> bool { self.wcaps & widget::WCAP_DIGITAL != 0 }
    /// # C: O(1)
    pub fn stereo(&self) -> bool { self.wcaps & widget::WCAP_STEREO != 0 }
    /// Amplifier capabilities of a widget, falling back to the function
    /// group's when the widget does not override them. # C: O(1)
    pub fn out_amp(&self, fg_out_amp: u32) -> Option<u32> {
        if self.wcaps & widget::WCAP_OUT_AMP == 0 { return None; }
        Some(if self.wcaps & widget::WCAP_AMP_OVRD != 0 { self.amp_out } else { fg_out_amp })
    }
    /// # C: O(1)
    pub fn in_amp(&self, fg_in_amp: u32) -> Option<u32> {
        if self.wcaps & widget::WCAP_IN_AMP == 0 { return None; }
        Some(if self.wcaps & widget::WCAP_AMP_OVRD != 0 { self.amp_in } else { fg_in_amp })
    }
}

/// One codec behind one `STATESTS` slot.
#[derive(Clone, Debug)]
pub struct Codec {
    pub addr: u8,
    pub vendor_id: u32,
    pub subsystem_id: u32,
    pub revision_id: u32,
    /// Audio function group node.
    pub afg: u8,
    pub afg_pcm: u32,
    pub afg_stream: u32,
    pub fg_amp_in: u32,
    pub fg_amp_out: u32,
    pub power_caps: u32,
    pub widgets: Vec<Widget>,
}

impl Codec {
    /// # C: O(widgets)
    pub fn widget(&self, nid: u8) -> Option<&Widget> { self.widgets.iter().find(|w| w.nid == nid) }
    /// # C: O(widgets)
    pub fn kind_of(&self, nid: u8) -> Option<WidgetType> { self.widget(nid).map(|w| w.kind()) }
    /// PCM capability governing `nid`: the widget's own when it overrides the
    /// function group's. # C: O(widgets)
    pub fn pcm_caps_of(&self, nid: u8) -> u32 {
        match self.widget(nid) {
            Some(w) if w.wcaps & widget::WCAP_FORMAT_OVRD != 0 && w.par_pcm != 0 => w.par_pcm,
            _ => self.afg_pcm,
        }
    }
    /// Analog audio-output widgets, in node order. # C: O(widgets)
    pub fn dacs(&self) -> Vec<u8> {
        self.widgets.iter().filter(|w| w.is_dac() && !w.digital()).map(|w| w.nid).collect()
    }
    /// Analog audio-input widgets, in node order. # C: O(widgets)
    pub fn adcs(&self) -> Vec<u8> {
        self.widgets.iter().filter(|w| w.is_adc() && !w.digital()).map(|w| w.nid).collect()
    }

    /// Digital input converters are kept separate from analog ADCs because
    /// Linux publishes them as a distinct PCM capture route.
    pub fn digital_adcs(&self) -> Vec<u8> {
        self.widgets.iter().filter(|w| w.is_adc() && w.digital()).map(|w| w.nid).collect()
    }
}

/// Read one widget's connection list. # C: O(list length)
pub fn connections<C: CodecBus>(bus: &C, nid: u8, wcaps: u32) -> Vec<u8> {
    if wcaps & widget::WCAP_CONN_LIST == 0 { return Vec::new(); }
    let Some(param) = read_param(bus, nid, verb::PAR_CONNLIST_LEN) else { return Vec::new(); };
    let layout = connlist::layout(param);
    if layout.len == 0 { return Vec::new(); }
    if layout.len == 1 {
        return match bus.command(nid, verb::GET_CONNECT_LIST, 0) {
            Some(value) => alloc::vec![(value & layout.mask) as u8],
            None => Vec::new(),
        };
    }
    let mut words = Vec::new();
    for index in 0..connlist::word_count(&layout) {
        let payload = (index * layout.per_word) as u16;
        match bus.command(nid, verb::GET_CONNECT_LIST, payload) {
            Some(value) => words.push(value),
            None => break,
        }
    }
    connlist::expand(&layout, &words)
}

fn read_widget<C: CodecBus>(bus: &C, nid: u8) -> Option<Widget> {
    let wcaps = read_param(bus, nid, verb::PAR_AUDIO_WIDGET_CAP)?;
    let is_pin = widget::widget_type(wcaps) == WidgetType::Pin;
    Some(Widget {
        nid,
        wcaps,
        conns: connections(bus, nid, wcaps),
        pincap: if is_pin { read_param(bus, nid, verb::PAR_PIN_CAP).unwrap_or(0) } else { 0 },
        defcfg: if is_pin { bus.command(nid, verb::GET_CONFIG_DEFAULT, 0).unwrap_or(0) } else { 0 },
        amp_in: read_param(bus, nid, verb::PAR_AMP_IN_CAP).unwrap_or(0),
        amp_out: read_param(bus, nid, verb::PAR_AMP_OUT_CAP).unwrap_or(0),
        par_pcm: read_param(bus, nid, verb::PAR_PCM).unwrap_or(0),
    })
}

/// Locate the audio function group under the root node. # C: O(function groups)
fn find_afg<C: CodecBus>(bus: &C) -> Option<u8> {
    let (start, count) = verb::sub_nodes(read_param(bus, verb::NODE_ROOT, verb::PAR_NODE_COUNT)?);
    for offset in 0..count {
        let nid = start.checked_add(offset as u8)?;
        let function = read_param(bus, nid, verb::PAR_FUNCTION_TYPE)?;
        if function & verb::FGT_TYPE_MASK == verb::GRP_AUDIO_FUNCTION { return Some(nid); }
    }
    None
}

/// Walk a codec: root identity, then its audio function group, then every
/// widget under it. `None` when the codec has no audio function group, which
/// is a modem-only or absent codec.
/// # C: O(widgets × commands per widget)
pub fn parse<C: CodecBus>(bus: &C, addr: u8) -> Option<Codec> {
    let vendor_id = read_param(bus, verb::NODE_ROOT, verb::PAR_VENDOR_ID)?;
    if vendor_id == 0 || vendor_id == u32::MAX { return None; }
    let afg = find_afg(bus)?;
    let (start, count) = verb::sub_nodes(read_param(bus, afg, verb::PAR_NODE_COUNT)?);
    if start == 0 || count == 0 || count >= 0xff { return None; }

    let subsystem_id = read_param(bus, verb::NODE_ROOT, verb::PAR_SUBSYSTEM_ID)
        .filter(|id| *id != 0 && *id != u32::MAX)
        .or_else(|| bus.command(afg, verb::GET_SUBSYSTEM_ID, 0))
        .unwrap_or(0);

    let mut widgets = Vec::new();
    for offset in 0..count {
        let Some(nid) = start.checked_add(offset as u8) else { break; };
        if let Some(w) = read_widget(bus, nid) { widgets.push(w); }
    }

    Some(Codec {
        addr,
        vendor_id,
        subsystem_id,
        revision_id: read_param(bus, verb::NODE_ROOT, verb::PAR_REV_ID).unwrap_or(0),
        afg,
        afg_pcm: read_param(bus, afg, verb::PAR_PCM).unwrap_or(0),
        afg_stream: read_param(bus, afg, verb::PAR_STREAM).unwrap_or(0),
        fg_amp_in: read_param(bus, afg, verb::PAR_AMP_IN_CAP).unwrap_or(0),
        fg_amp_out: read_param(bus, afg, verb::PAR_AMP_OUT_CAP).unwrap_or(0),
        power_caps: read_param(bus, afg, verb::PAR_POWER_STATE).unwrap_or(0),
        widgets,
    })
}

/// Can a jack on this pin be detected? Both the widget capability and the
/// configuration's presence flag have to agree. # C: O(1)
pub fn jack_detectable(pin: &Widget) -> bool {
    pin.pincap & widget::PINCAP_PRES_DETECT != 0
        && !defcfg::no_presence(pin.defcfg)
        && pin.wcaps & widget::WCAP_UNSOL_CAP != 0
}

#[cfg(test)]
#[path = "tests/graph.rs"]
mod tests;
