// Pin default-configuration decode. The BIOS writes this word per pin; it is
// the only description of what a jack physically is, so the parser's entire
// output routing follows from it.

#![allow(dead_code)]

pub const SEQUENCE_MASK: u32 = 0x0000_000f;
pub const ASSOC_SHIFT: u32 = 4;
pub const ASSOC_MASK: u32 = 0xf << ASSOC_SHIFT;
pub const MISC_SHIFT: u32 = 8;
pub const MISC_MASK: u32 = 0xf << MISC_SHIFT;
pub const MISC_NO_PRESENCE: u32 = 1 << 0;
pub const COLOR_SHIFT: u32 = 12;
pub const COLOR_MASK: u32 = 0xf << COLOR_SHIFT;
pub const CONN_TYPE_SHIFT: u32 = 16;
pub const CONN_TYPE_MASK: u32 = 0xf << CONN_TYPE_SHIFT;
pub const DEVICE_SHIFT: u32 = 20;
pub const DEVICE_MASK: u32 = 0xf << DEVICE_SHIFT;
pub const LOCATION_SHIFT: u32 = 24;
pub const LOCATION_MASK: u32 = 0x3f << LOCATION_SHIFT;
pub const PORT_CONN_SHIFT: u32 = 30;
pub const PORT_CONN_MASK: u32 = 0x3 << PORT_CONN_SHIFT;

// Default-device values.
pub const DEV_LINE_OUT: u8 = 0x0;
pub const DEV_SPEAKER: u8 = 0x1;
pub const DEV_HP_OUT: u8 = 0x2;
pub const DEV_CD: u8 = 0x3;
pub const DEV_SPDIF_OUT: u8 = 0x4;
pub const DEV_DIG_OTHER_OUT: u8 = 0x5;
pub const DEV_MODEM_LINE: u8 = 0x6;
pub const DEV_MODEM_HAND: u8 = 0x7;
pub const DEV_LINE_IN: u8 = 0x8;
pub const DEV_AUX: u8 = 0x9;
pub const DEV_MIC_IN: u8 = 0xa;
pub const DEV_TELEPHONY: u8 = 0xb;
pub const DEV_SPDIF_IN: u8 = 0xc;
pub const DEV_DIG_OTHER_IN: u8 = 0xd;
pub const DEV_OTHER: u8 = 0xf;

// Port connectivity.
pub const PORT_COMPLEX: u8 = 0;
pub const PORT_NONE: u8 = 1;
pub const PORT_FIXED: u8 = 2;
pub const PORT_BOTH: u8 = 3;

// Location: low bits name the face, bits 5:4 name the area.
pub const LOC_AREA_MASK: u8 = 0x30;
pub const LOC_EXTERNAL: u8 = 0x00;
pub const LOC_INTERNAL: u8 = 0x10;
pub const LOC_SEPARATE: u8 = 0x20;
pub const LOC_OTHER: u8 = 0x30;
pub const LOC_NONE: u8 = 0;
pub const LOC_REAR: u8 = 1;
pub const LOC_FRONT: u8 = 2;
pub const LOC_HDMI: u8 = 0x18;

/// Where an input pin physically sits, which is what decides whether its
/// label needs a location prefix and whether it can be auto-switched.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum PinAttr {
    Unused,
    Internal,
    Dock,
    Normal,
    Rear,
    Front,
}

/// # C: O(1)
pub fn sequence(cfg: u32) -> u8 { (cfg & SEQUENCE_MASK) as u8 }
/// # C: O(1)
pub fn association(cfg: u32) -> u8 { ((cfg & ASSOC_MASK) >> ASSOC_SHIFT) as u8 }
/// # C: O(1)
pub fn misc(cfg: u32) -> u8 { ((cfg & MISC_MASK) >> MISC_SHIFT) as u8 }
/// # C: O(1)
pub fn color(cfg: u32) -> u8 { ((cfg & COLOR_MASK) >> COLOR_SHIFT) as u8 }
/// # C: O(1)
pub fn conn_type(cfg: u32) -> u8 { ((cfg & CONN_TYPE_MASK) >> CONN_TYPE_SHIFT) as u8 }
/// # C: O(1)
pub fn device(cfg: u32) -> u8 { ((cfg & DEVICE_MASK) >> DEVICE_SHIFT) as u8 }
/// # C: O(1)
pub fn location(cfg: u32) -> u8 { ((cfg & LOCATION_MASK) >> LOCATION_SHIFT) as u8 }
/// # C: O(1)
pub fn port_conn(cfg: u32) -> u8 { ((cfg & PORT_CONN_MASK) >> PORT_CONN_SHIFT) as u8 }

/// A pin whose default configuration says nothing is wired to it. # C: O(1)
pub fn unconnected(cfg: u32) -> bool { port_conn(cfg) == PORT_NONE }

/// Pin has no presence-detect circuitry behind it even if the widget claims
/// the capability. # C: O(1)
pub fn no_presence(cfg: u32) -> bool { u32::from(misc(cfg)) & MISC_NO_PRESENCE != 0 }

/// A `LINE_OUT` on a fixed (or fixed-and-jack) port is a built-in speaker,
/// whatever the BIOS labelled it. # C: O(1)
pub fn effective_device(cfg: u32) -> u8 {
    let dev = device(cfg);
    if dev == DEV_LINE_OUT && matches!(port_conn(cfg), PORT_FIXED | PORT_BOTH) { DEV_SPEAKER } else { dev }
}

/// Physical placement class of a pin. # C: O(1)
pub fn pin_attr(cfg: u32) -> PinAttr {
    let conn = port_conn(cfg);
    if conn == PORT_NONE { return PinAttr::Unused; }
    if conn == PORT_FIXED || conn == PORT_BOTH { return PinAttr::Internal; }
    let loc = location(cfg);
    match loc & LOC_AREA_MASK {
        LOC_INTERNAL => PinAttr::Internal,
        LOC_SEPARATE => PinAttr::Dock,
        _ => match loc {
            LOC_REAR => PinAttr::Rear,
            LOC_FRONT => PinAttr::Front,
            _ => PinAttr::Normal,
        },
    }
}

/// Sort key ordering a group of output pins: association first, sequence
/// within it. Line-outs are constrained to one association before sorting,
/// so their key is the sequence alone.
/// # C: O(1)
pub fn group_sort_key(cfg: u32) -> u16 {
    (u16::from(association(cfg)) << 4) | u16::from(sequence(cfg))
}

#[cfg(test)]
#[path = "tests/defcfg.rs"]
mod tests;
