//! Bounded HID report-descriptor parsing for USB interrupt input.
//!
//! This is intentionally descriptor-driven: unlike the boot-protocol helper,
//! it records the bit geometry and usages that the device actually publishes.

const MAX_FIELDS: usize = 64;

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
            (2, 0) => locals.usage = Some(value),
            (2, 1) => locals.usage_min = Some(value),
            (2, 2) => locals.usage_max = Some(value),
            // Main Input: constant fields still consume report bits but create no input event field.
            (0, 8) => {
                let width = u32::from(globals.report_size).checked_mul(u32::from(globals.report_count))?;
                let id = globals.report_id as usize;
                let start = bits[id]; bits[id] = start.checked_add(width)?;
                if value & 1 == 0 {
                    if layout.count == MAX_FIELDS || globals.report_size == 0 || globals.report_count == 0 { return None; }
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
}
