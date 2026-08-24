// Codec command encoding and response decoding. A command is one 32-bit
// word on the CORB; a response is the 64-bit RIRB entry the codec returns.

#![allow(dead_code)]

pub const NODE_ROOT: u8 = 0x00;
pub const MAX_CODEC_ADDRESS: u8 = 0x0f;
pub const MAX_NID: u8 = 0x7f;

// ---- Verbs. The four 0x_00-terminated ones carry a 16-bit payload; the
// rest carry 8 bits.
pub const GET_STREAM_FORMAT: u16 = 0x0a00;
pub const GET_AMP_GAIN_MUTE: u16 = 0x0b00;
pub const GET_PROC_COEF: u16 = 0x0c00;
pub const GET_COEF_INDEX: u16 = 0x0d00;
pub const SET_STREAM_FORMAT: u16 = 0x0200;
pub const SET_AMP_GAIN_MUTE: u16 = 0x0300;
pub const SET_PROC_COEF: u16 = 0x0400;
pub const SET_COEF_INDEX: u16 = 0x0500;

pub const PARAMETERS: u16 = 0x0f00;
pub const GET_CONNECT_SEL: u16 = 0x0f01;
pub const GET_CONNECT_LIST: u16 = 0x0f02;
pub const GET_POWER_STATE: u16 = 0x0f05;
pub const GET_CONV: u16 = 0x0f06;
pub const GET_PIN_WIDGET_CONTROL: u16 = 0x0f07;
pub const GET_UNSOLICITED_RESPONSE: u16 = 0x0f08;
pub const GET_PIN_SENSE: u16 = 0x0f09;
pub const GET_EAPD_BTLENABLE: u16 = 0x0f0c;
pub const GET_DIGI_CONVERT_1: u16 = 0x0f0d;
pub const GET_CONFIG_DEFAULT: u16 = 0x0f1c;
pub const GET_SUBSYSTEM_ID: u16 = 0x0f20;

pub const SET_CONNECT_SEL: u16 = 0x0701;
pub const SET_POWER_STATE: u16 = 0x0705;
pub const SET_CHANNEL_STREAMID: u16 = 0x0706;
pub const SET_PIN_WIDGET_CONTROL: u16 = 0x0707;
pub const SET_UNSOLICITED_ENABLE: u16 = 0x0708;
pub const SET_PIN_SENSE: u16 = 0x0709;
pub const SET_BEEP_CONTROL: u16 = 0x070a;
pub const SET_EAPD_BTLENABLE: u16 = 0x070c;
pub const SET_DIGI_CONVERT_1: u16 = 0x070d;
pub const SET_CODEC_RESET: u16 = 0x07ff;

// ---- Parameter IDs read through `PARAMETERS`.
pub const PAR_VENDOR_ID: u16 = 0x00;
pub const PAR_SUBSYSTEM_ID: u16 = 0x01;
pub const PAR_REV_ID: u16 = 0x02;
pub const PAR_NODE_COUNT: u16 = 0x04;
pub const PAR_FUNCTION_TYPE: u16 = 0x05;
pub const PAR_AUDIO_FG_CAP: u16 = 0x08;
pub const PAR_AUDIO_WIDGET_CAP: u16 = 0x09;
pub const PAR_PCM: u16 = 0x0a;
pub const PAR_STREAM: u16 = 0x0b;
pub const PAR_PIN_CAP: u16 = 0x0c;
pub const PAR_AMP_IN_CAP: u16 = 0x0d;
pub const PAR_CONNLIST_LEN: u16 = 0x0e;
pub const PAR_POWER_STATE: u16 = 0x0f;
pub const PAR_PROC_CAP: u16 = 0x10;
pub const PAR_GPIO_CAP: u16 = 0x11;
pub const PAR_AMP_OUT_CAP: u16 = 0x12;
pub const PAR_VOL_KNB_CAP: u16 = 0x13;

// ---- Function-group types.
pub const GRP_AUDIO_FUNCTION: u32 = 0x01;
pub const GRP_MODEM_FUNCTION: u32 = 0x02;
pub const FGT_TYPE_MASK: u32 = 0xff;
pub const FGT_UNSOL_CAP: u32 = 1 << 8;

// ---- Sub-node count response: start nid in the high half, count in the low.
pub const NODE_COUNT_MASK: u32 = 0x7fff;
pub const NODE_START_SHIFT: u32 = 16;

// ---- Unsolicited response enable and payload.
pub const UNSOL_TAG_MASK: u8 = 0x3f;
pub const UNSOL_ENABLED: u8 = 1 << 7;
pub const UNSOL_RES_TAG_SHIFT: u32 = 26;
pub const UNSOL_RES_TAG_MASK: u32 = 0x3f;
pub const UNSOL_RES_SUBTAG_SHIFT: u32 = 21;
pub const UNSOL_RES_SUBTAG_MASK: u32 = 0x1f;
pub const UNSOL_RES_PRESENCE: u32 = 1 << 0;
pub const UNSOL_RES_ELDV: u32 = 1 << 1;

// ---- Pin sense.
pub const PINSENSE_PRESENCE: u32 = 1 << 31;
pub const PINSENSE_ELDV: u32 = 1 << 30;

// ---- Power states.
pub const PWRST_D0: u8 = 0x00;
pub const PWRST_D1: u8 = 0x01;
pub const PWRST_D2: u8 = 0x02;
pub const PWRST_D3: u8 = 0x03;
pub const PWRST_SETTING_MASK: u32 = 0xf;
pub const PWRST_ACTUAL_SHIFT: u32 = 4;
pub const PWRST_ERROR: u32 = 1 << 8;
pub const PWRST_EPSS: u32 = 1 << 31;

// ---- Converter stream/channel assignment.
pub const CONV_CHANNEL_MASK: u8 = 0x0f;
pub const CONV_STREAM_SHIFT: u32 = 4;

/// Encode one codec command. `None` when a field is out of range, which is
/// how the reference reports an unencodable verb rather than truncating it.
/// # C: O(1)
pub fn make_verb(addr: u8, nid: u8, verb: u16, payload: u16) -> Option<u32> {
    if addr > MAX_CODEC_ADDRESS || nid > MAX_NID || verb > 0x0fff { return None; }
    Some((addr as u32) << 28 | (nid as u32) << 20 | (verb as u32) << 8 | payload as u32)
}

/// Codec address a command word is addressed to. # C: O(1)
pub fn verb_addr(cmd: u32) -> u8 { (cmd >> 28) as u8 }

/// Payload of `PARAMETERS` for parameter `id`. # C: O(1)
pub fn param_payload(id: u16) -> u16 { id }

/// Decoded RIRB entry.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Response {
    pub value: u32,
    pub addr: u8,
    pub unsolicited: bool,
}

/// Split a RIRB entry into its response word and its extension. # C: O(1)
pub fn decode_response(value: u32, extended: u32) -> Response {
    Response {
        value,
        addr: (extended & crate::uapi::RIRB_EX_ADDR_MASK) as u8,
        unsolicited: extended & crate::uapi::RIRB_EX_UNSOL_EV != 0,
    }
}

/// Tag an unsolicited response echoes back from `SET_UNSOLICITED_ENABLE`.
/// # C: O(1)
pub fn unsol_tag(value: u32) -> u8 { ((value >> UNSOL_RES_TAG_SHIFT) & UNSOL_RES_TAG_MASK) as u8 }

/// Sub-node range `(start_nid, count)` from a `PAR_NODE_COUNT` response.
/// # C: O(1)
pub fn sub_nodes(param: u32) -> (u8, u16) {
    (((param >> NODE_START_SHIFT) & NODE_COUNT_MASK) as u8, (param & NODE_COUNT_MASK) as u16)
}

/// Payload enabling unsolicited responses with `tag`. # C: O(1)
pub fn unsol_enable_payload(tag: u8) -> u16 { u16::from(UNSOL_ENABLED | (tag & UNSOL_TAG_MASK)) }

/// Payload assigning a converter to `stream` tag and starting `channel`.
/// # C: O(1)
pub fn channel_streamid_payload(stream: u8, channel: u8) -> u16 {
    u16::from((stream << CONV_STREAM_SHIFT) | (channel & CONV_CHANNEL_MASK))
}

#[cfg(test)]
#[path = "tests/verb.rs"]
mod tests;
