// Widget, pin and amplifier capability decoding. Every accessor here is a
// pure decode of a codec parameter response.

#![allow(dead_code)]

// ---- Widget capabilities (`PAR_AUDIO_WIDGET_CAP`) ----
pub const WCAP_STEREO: u32 = 1 << 0;
pub const WCAP_IN_AMP: u32 = 1 << 1;
pub const WCAP_OUT_AMP: u32 = 1 << 2;
pub const WCAP_AMP_OVRD: u32 = 1 << 3;
pub const WCAP_FORMAT_OVRD: u32 = 1 << 4;
pub const WCAP_STRIPE: u32 = 1 << 5;
pub const WCAP_PROC_WID: u32 = 1 << 6;
pub const WCAP_UNSOL_CAP: u32 = 1 << 7;
pub const WCAP_CONN_LIST: u32 = 1 << 8;
pub const WCAP_DIGITAL: u32 = 1 << 9;
pub const WCAP_POWER: u32 = 1 << 10;
pub const WCAP_LR_SWAP: u32 = 1 << 11;
pub const WCAP_CHAN_CNT_EXT_SHIFT: u32 = 13;
pub const WCAP_CHAN_CNT_EXT_MASK: u32 = 0x7 << WCAP_CHAN_CNT_EXT_SHIFT;
pub const WCAP_TYPE_SHIFT: u32 = 20;
pub const WCAP_TYPE_MASK: u32 = 0xf << WCAP_TYPE_SHIFT;

/// Widget node types.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WidgetType {
    AudioOut,
    AudioIn,
    AudioMixer,
    AudioSelector,
    Pin,
    Power,
    VolumeKnob,
    Beep,
    Vendor,
    Reserved(u8),
}

/// Widget type encoded in `wcaps`. # C: O(1)
pub fn widget_type(wcaps: u32) -> WidgetType {
    match ((wcaps & WCAP_TYPE_MASK) >> WCAP_TYPE_SHIFT) as u8 {
        0x0 => WidgetType::AudioOut,
        0x1 => WidgetType::AudioIn,
        0x2 => WidgetType::AudioMixer,
        0x3 => WidgetType::AudioSelector,
        0x4 => WidgetType::Pin,
        0x5 => WidgetType::Power,
        0x6 => WidgetType::VolumeKnob,
        0x7 => WidgetType::Beep,
        0xf => WidgetType::Vendor,
        other => WidgetType::Reserved(other),
    }
}

/// Channels a widget carries: the extension field counts extra pairs on top
/// of the stereo bit. # C: O(1)
pub fn widget_channels(wcaps: u32) -> u32 {
    let extension = (wcaps & WCAP_CHAN_CNT_EXT_MASK) >> WCAP_CHAN_CNT_EXT_SHIFT;
    let stereo = u32::from(wcaps & WCAP_STEREO != 0);
    (extension << 1) + stereo + 1
}

// ---- Pin capabilities (`PAR_PIN_CAP`) ----
pub const PINCAP_IMP_SENSE: u32 = 1 << 0;
pub const PINCAP_TRIG_REQ: u32 = 1 << 1;
pub const PINCAP_PRES_DETECT: u32 = 1 << 2;
pub const PINCAP_HP_DRV: u32 = 1 << 3;
pub const PINCAP_OUT: u32 = 1 << 4;
pub const PINCAP_IN: u32 = 1 << 5;
pub const PINCAP_BALANCE: u32 = 1 << 6;
pub const PINCAP_VREF_SHIFT: u32 = 8;
pub const PINCAP_VREF_MASK: u32 = 0x37 << PINCAP_VREF_SHIFT;
pub const PINCAP_EAPD: u32 = 1 << 16;

pub const VREF_HIZ: u8 = 0;
pub const VREF_50: u8 = 1;
pub const VREF_GRD: u8 = 2;
pub const VREF_80: u8 = 4;
pub const VREF_100: u8 = 5;

// ---- Pin widget control (`SET_PIN_WIDGET_CONTROL`) ----
pub const PINCTL_VREF_MASK: u8 = 0x07;
pub const PINCTL_IN_EN: u8 = 1 << 5;
pub const PINCTL_OUT_EN: u8 = 1 << 6;
pub const PINCTL_HP_EN: u8 = 1 << 7;
/// Composite targets the parser installs.
pub const PIN_IN: u8 = PINCTL_IN_EN;
pub const PIN_OUT: u8 = PINCTL_OUT_EN;
pub const PIN_HP: u8 = PINCTL_OUT_EN | PINCTL_HP_EN;

// ---- EAPD/BTL ----
pub const EAPDBTL_BALANCED: u8 = 1 << 0;
pub const EAPDBTL_EAPD: u8 = 1 << 1;
pub const EAPDBTL_LR_SWAP: u8 = 1 << 2;

/// Is `vref` advertised in the pin's capability field? # C: O(1)
pub fn pincap_has_vref(pincap: u32, vref: u8) -> bool {
    ((pincap & PINCAP_VREF_MASK) >> PINCAP_VREF_SHIFT) & (1u32 << vref) != 0
}

/// Bias a microphone input pin should carry, in the reference's preference
/// order, falling back to high impedance. # C: O(1)
pub fn default_vref(pincap: u32) -> u8 {
    for candidate in [VREF_80, VREF_50, VREF_100, VREF_GRD] {
        if pincap_has_vref(pincap, candidate) { return candidate; }
    }
    VREF_HIZ
}

// ---- Amplifier capabilities (`PAR_AMP_IN_CAP` / `PAR_AMP_OUT_CAP`) ----
pub const AMPCAP_OFFSET_MASK: u32 = 0x7f;
pub const AMPCAP_NUM_STEPS_SHIFT: u32 = 8;
pub const AMPCAP_NUM_STEPS_MASK: u32 = 0x7f << AMPCAP_NUM_STEPS_SHIFT;
pub const AMPCAP_STEP_SIZE_SHIFT: u32 = 16;
pub const AMPCAP_STEP_SIZE_MASK: u32 = 0x7f << AMPCAP_STEP_SIZE_SHIFT;
pub const AMPCAP_MUTE: u32 = 1 << 31;

// ---- Amp gain/mute payload (`SET_AMP_GAIN_MUTE` / `GET_AMP_GAIN_MUTE`) ----
pub const AMP_MUTE: u16 = 1 << 7;
pub const AMP_GAIN_MASK: u16 = 0x7f;
pub const AMP_GET_INDEX_MASK: u16 = 0x0f;
pub const AMP_GET_LEFT: u16 = 1 << 13;
pub const AMP_GET_OUTPUT: u16 = 1 << 15;
pub const AMP_SET_INDEX_SHIFT: u32 = 8;
pub const AMP_SET_RIGHT: u16 = 1 << 12;
pub const AMP_SET_LEFT: u16 = 1 << 13;
pub const AMP_SET_INPUT: u16 = 1 << 14;
pub const AMP_SET_OUTPUT: u16 = 1 << 15;

/// One amplifier's usable range.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AmpCaps {
    /// Highest gain step; step 0 is the quietest.
    pub num_steps: u32,
    /// Step index that is 0 dB.
    pub offset: u32,
    /// Gain per step in 1/100 dB.
    pub step_centibel: u32,
    pub mute: bool,
}

/// Decode an amplifier capability response. # C: O(1)
pub fn amp_caps(caps: u32) -> AmpCaps {
    AmpCaps {
        num_steps: (caps & AMPCAP_NUM_STEPS_MASK) >> AMPCAP_NUM_STEPS_SHIFT,
        offset: caps & AMPCAP_OFFSET_MASK,
        step_centibel: (((caps & AMPCAP_STEP_SIZE_MASK) >> AMPCAP_STEP_SIZE_SHIFT) + 1) * 25,
        mute: caps & AMPCAP_MUTE != 0,
    }
}

/// Gain at step 0, in 1/100 dB — the TLV minimum. # C: O(1)
pub fn amp_min_centibel(caps: &AmpCaps) -> i32 { -((caps.offset * caps.step_centibel) as i32) }

/// Payload writing `gain`/`mute` to one amplifier. `input` selects the
/// per-connection input amp at `index`; otherwise the output amp.
/// # C: O(1)
pub fn amp_set_payload(output: bool, index: u8, left: bool, right: bool, mute: bool, gain: u8) -> u16 {
    let mut payload = if output { AMP_SET_OUTPUT } else { AMP_SET_INPUT };
    if left { payload |= AMP_SET_LEFT; }
    if right { payload |= AMP_SET_RIGHT; }
    payload |= (u16::from(index) & AMP_GET_INDEX_MASK) << AMP_SET_INDEX_SHIFT;
    if mute { payload |= AMP_MUTE; }
    payload | (u16::from(gain) & AMP_GAIN_MASK)
}

/// Payload reading one amplifier's current gain/mute. # C: O(1)
pub fn amp_get_payload(output: bool, index: u8, left: bool) -> u16 {
    let mut payload = if output { AMP_GET_OUTPUT } else { 0 };
    if left { payload |= AMP_GET_LEFT; }
    payload | (u16::from(index) & AMP_GET_INDEX_MASK)
}

/// `(mute, gain)` from an amp read response. # C: O(1)
pub fn amp_decode(value: u32) -> (bool, u8) {
    ((value as u16 & AMP_MUTE) != 0, (value as u16 & AMP_GAIN_MASK) as u8)
}

#[cfg(test)]
#[path = "tests/widget.rs"]
mod tests;
