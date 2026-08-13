//! Bounded HID report-descriptor parsing for USB interrupt input.
//!
//! This is intentionally descriptor-driven: unlike the boot-protocol helper,
//! it records the bit geometry and usages that the device actually publishes.

const MAX_FIELDS: usize = 64;
const MAX_VALUES: usize = 32;
/// HID 1.11's fixed global-environment nesting limit, shared with Linux.
const HID_GLOBAL_STACK_SIZE: usize = 4;

/// One input field from a HID report descriptor.  Usage ranges model both
/// variable controls and array controls without expanding untrusted input.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct InputField {
    pub report_id: u8,
    pub bit_offset: u32,
    pub bit_size: u8,
    pub count: u16,
    pub usage_page: u16,
    pub usage_min: u32,
    pub usage_max: u32,
    pub logical_min: i32,
    pub logical_max: i32,
    pub flags: u16,
}

/// Validated, fixed-capacity input-report layout.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ReportLayout { fields: [Option<InputField>; MAX_FIELDS], count: usize }
impl ReportLayout {
    pub const fn empty() -> Self { Self { fields: [None; MAX_FIELDS], count: 0 } }
    pub const fn len(&self) -> usize { self.count }
    pub fn field(&self, index: usize) -> Option<InputField> { self.fields.get(index).copied().flatten() }
}

/// Stateful HID input decoder. Values are retained per descriptor field so
/// variable controls and array-key reports emit only transitions.
pub struct ReportDecoder { layout: ReportLayout, values: [[i32; MAX_VALUES]; MAX_FIELDS] }
impl ReportDecoder {
    pub const fn new(layout: ReportLayout) -> Self { Self { layout, values: [[0; MAX_VALUES]; MAX_FIELDS] } }
    /// Decode one interrupt report into changed Linux input events. # C: O(fields * values)
    pub fn decode(&mut self, report: &[u8]) -> [Option<crate::hid::Event>; MAX_FIELDS] {
        let mut events = [None; MAX_FIELDS]; let mut out = 0usize;
        for index in 0..self.layout.count {
            let Some(field) = self.layout.field(index) else { continue; };
            let data = if field.report_id == 0 { report } else if report.first().copied() == Some(field.report_id) { &report[1..] } else { continue };
            let count = usize::from(field.count);
            for entry in 0..count {
                let Some(raw) = extract(data, field.bit_offset + entry as u32 * u32::from(field.bit_size), field.bit_size) else { continue; };
                let value = if field.logical_min < 0 { sign_extend(raw, field.bit_size) } else { raw as i32 };
                let previous = self.values[index][entry];
                if previous == value { continue; }
                self.values[index][entry] = value;
                if out == events.len() { return events; }
                if field.flags & 2 != 0 {
                    let usage = field.usage_min.saturating_add(entry as u32);
                    if let Some(event) = event_for(field, usage, value) { events[out] = Some(event); out += 1; }
                } else {
                    if previous != 0 { if let Some(event) = event_for(field, previous as u32, 0) { events[out] = Some(event); out += 1; } }
                    if value != 0 && out < events.len() { if let Some(event) = event_for(field, value as u32, 1) { events[out] = Some(event); out += 1; } }
                }
                if out == events.len() { return events; }
            }
        }
        events
    }
}

#[derive(Copy, Clone)]
struct Global { usage_page: u16, logical_min: i32, logical_max: i32, report_size: u8, report_count: u16, report_id: u8 }
impl Global { const fn new() -> Self { Self { usage_page: 0, logical_min: 0, logical_max: 0, report_size: 0, report_count: 0, report_id: 0 } } }

#[derive(Copy, Clone)]
struct Local { usage: Option<u32>, usage_min: Option<u32>, usage_max: Option<u32> }
impl Local { const fn new() -> Self { Self { usage: None, usage_min: None, usage_max: None } } }

/// Parse standard short HID items and retain every non-constant Input item.
/// Long items and malformed/truncated descriptors are rejected. # C: O(bytes + fields)
pub fn parse_report_descriptor(bytes: &[u8]) -> Option<ReportLayout> {
    let mut globals = Global::new();
    let mut global_stack = [Global::new(); HID_GLOBAL_STACK_SIZE];
    let mut global_depth = 0usize;
    let mut locals = Local::new();
    let mut bits = [0u32; 256];
    let mut layout = ReportLayout::empty();
    let mut at = 0usize;
    while at < bytes.len() {
        let prefix = *bytes.get(at)?; at += 1;
        if prefix == 0xfe { return None; }
        let size = match prefix & 3 { 3 => 4usize, n => n as usize };
        let raw = bytes.get(at..at.checked_add(size)?)?;
        at += size;
        let value = unsigned(raw)?;
        let signed = signed(raw)?;
        match ((prefix >> 2) & 3, (prefix >> 4) & 15) {
            (1, 0) => globals.usage_page = value as u16,
            (1, 1) => globals.logical_min = signed,
            (1, 2) => globals.logical_max = signed,
            (1, 7) if value <= 255 => globals.report_size = value as u8,
            (1, 8) if value != 0 && value <= 255 => globals.report_id = value as u8,
            (1, 9) if value <= u16::MAX as u32 => globals.report_count = value as u16,
            // HID_GLOBAL_ITEM_TAG_PUSH/POP retain and restore every global
            // item (including report ID and bit geometry). Linux rejects
            // stack overflow and underflow; do the same before accepting a
            // descriptor from an untrusted USB device.
            (1, 10) => {
                if global_depth == HID_GLOBAL_STACK_SIZE { return None; }
                global_stack[global_depth] = globals;
                global_depth += 1;
            }
            (1, 11) => {
                if global_depth == 0 { return None; }
                global_depth -= 1;
                globals = global_stack[global_depth];
            }
            (2, 0) => locals.usage = Some(value),
            (2, 1) => locals.usage_min = Some(value),
            (2, 2) => locals.usage_max = Some(value),
            // Main Input: constant fields still consume report bits but create no input event field.
            (0, 8) => {
                let width = u32::from(globals.report_size).checked_mul(u32::from(globals.report_count))?;
                let id = globals.report_id as usize;
                let start = bits[id]; bits[id] = start.checked_add(width)?;
                if value & 1 == 0 {
                    if layout.count == MAX_FIELDS || globals.report_size == 0 || globals.report_count == 0 || globals.report_count as usize > MAX_VALUES { return None; }
                    let minimum = locals.usage_min.or(locals.usage).unwrap_or(0);
                    let maximum = locals.usage_max.or(locals.usage).unwrap_or(minimum);
                    if maximum < minimum { return None; }
                    layout.fields[layout.count] = Some(InputField { report_id: globals.report_id, bit_offset: start,
                        bit_size: globals.report_size, count: globals.report_count, usage_page: globals.usage_page,
                        usage_min: minimum, usage_max: maximum, logical_min: globals.logical_min,
                        logical_max: globals.logical_max, flags: value as u16 });
                    layout.count += 1;
                }
                locals = Local::new();
            }
            // Collection/end-collection/output/feature are not input geometry;
            // they still delimit local state as required by HID's item rules.
            (0, 9 | 11 | 10 | 12) => locals = Local::new(),
            _ => {}
        }
    }
    (layout.count != 0).then_some(layout)
}

fn unsigned(bytes: &[u8]) -> Option<u32> { match bytes.len() { 0 => Some(0), 1 => Some(u32::from(bytes[0])), 2 => Some(u32::from(u16::from_le_bytes(bytes.try_into().ok()?))), 4 => Some(u32::from_le_bytes(bytes.try_into().ok()?)), _ => None } }
fn signed(bytes: &[u8]) -> Option<i32> { match bytes.len() { 0 => Some(0), 1 => Some(i32::from(bytes[0] as i8)), 2 => Some(i32::from(i16::from_le_bytes(bytes.try_into().ok()?))), 4 => Some(i32::from_le_bytes(bytes.try_into().ok()?)), _ => None } }
fn extract(bytes: &[u8], bit: u32, width: u8) -> Option<u32> { if width == 0 || width > 32 { return None; } let end = bit.checked_add(u32::from(width))?; if end > (bytes.len() as u32).checked_mul(8)? { return None; } let mut value = 0u32; for n in 0..width { value |= u32::from(bytes[((bit + u32::from(n)) / 8) as usize] >> ((bit + u32::from(n)) & 7) & 1) << n; } Some(value) }
fn sign_extend(value: u32, width: u8) -> i32 { if width == 32 { value as i32 } else if value & (1 << (width - 1)) != 0 { (value | (!0u32 << width)) as i32 } else { value as i32 } }
fn event_for(field: InputField, usage: u32, value: i32) -> Option<crate::hid::Event> { match field.usage_page { 7 => crate::hid::keycode(usage as u8).map(|code| crate::hid::Event::Key { code, value }), 9 if usage > 0 => Some(crate::hid::Event::Key { code: 271 + usage as u16, value }), 1 if field.flags & 4 != 0 => match usage { 0x30 => Some(crate::hid::Event::Relative { code: 0, value }), 0x31 => Some(crate::hid::Event::Relative { code: 1, value }), 0x38 => Some(crate::hid::Event::Relative { code: 8, value }), _ => None }, _ => None } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_keyboard_modifier_and_key_array_input_fields() {
        let report = [0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0x15, 0, 0x25, 1, 0x75, 1, 0x95, 8, 0x81, 2, 0x95, 1, 0x75, 8, 0x81, 1, 0x95, 6, 0x75, 8, 0x15, 0, 0x25, 0x65, 0x05, 0x07, 0x19, 0, 0x29, 0x65, 0x81, 0, 0xc0];
        let layout = parse_report_descriptor(&report).unwrap();
        assert_eq!(layout.len(), 2);
        assert_eq!(layout.field(0).unwrap().bit_offset, 0);
        assert_eq!(layout.field(0).unwrap().usage_min, 0xe0);
        assert_eq!(layout.field(1).unwrap().bit_offset, 16);
        assert_eq!(layout.field(1).unwrap().count, 6);
    }
    #[test]
    fn rejects_long_or_truncated_items() { assert!(parse_report_descriptor(&[0xfe, 1]).is_none()); assert!(parse_report_descriptor(&[0x75]).is_none()); }
    #[test]
    fn decoder_emits_only_keyboard_usage_transitions() {
        let report = [0x05, 0x07, 0x19, 4, 0x29, 4, 0x15, 0, 0x25, 1, 0x75, 1, 0x95, 1, 0x81, 2];
        let mut decoder = ReportDecoder::new(parse_report_descriptor(&report).unwrap());
        assert_eq!(decoder.decode(&[1])[0], Some(crate::hid::Event::Key { code: 30, value: 1 }));
        assert_eq!(decoder.decode(&[1])[0], None);
        assert_eq!(decoder.decode(&[0])[0], Some(crate::hid::Event::Key { code: 30, value: 0 }));
    }
    #[test]
    fn decoder_maps_relative_wheel_usage() {
        let report = [0x05, 0x01, 0x09, 0x38, 0x15, 0x81, 0x25, 0x7f, 0x75, 8, 0x95, 1, 0x81, 6];
        let mut decoder = ReportDecoder::new(parse_report_descriptor(&report).unwrap());
        assert_eq!(decoder.decode(&[0xfe])[0], Some(crate::hid::Event::Relative { code: 8, value: -2 }));
    }
    #[test]
    fn global_push_pop_restores_usage_page_and_bit_geometry() {
        let report = [0x05, 0x01, 0x15, 0, 0x25, 1, 0x75, 1, 0x95, 1,
            0xa4, 0x05, 0x07, 0x09, 4, 0x81, 2, 0xb4, 0x09, 0x30, 0x81, 6];
        let layout = parse_report_descriptor(&report).unwrap();
        assert_eq!(layout.len(), 2);
        assert_eq!(layout.field(0).unwrap().usage_page, 7);
        assert_eq!(layout.field(1).unwrap().usage_page, 1);
        assert_eq!(layout.field(1).unwrap().bit_offset, 1);
    }
    #[test]
    fn global_stack_overflow_and_underflow_are_rejected() {
        assert!(parse_report_descriptor(&[0xa4, 0xa4, 0xa4, 0xa4, 0xa4]).is_none());
        assert!(parse_report_descriptor(&[0xb4]).is_none());
    }
}
