//! Selected native font query wire records and bounded copy policy.
use super::{VERSION, MAX_HEIGHT, MAX_WIDTH, MAX_UNITS};
pub const QUERY_COPY: u64 = 4;
pub const QUERY_CHARSET: u32 = 1;
pub const QUERY_DATA: u32 = 2;
pub const QUERY_GLYPHS: u32 = 3;
pub const QUERY_ABC: u32 = 4;
pub const QUERY_OUTLINE: u32 = 5;
pub const QUERY_NONCLIENT: u32 = 6;
pub const QUERY_SYSTEM_METRIC: u32 = 7;
/// Indices requiring measured nonclient fonts, not a scalar default. # C: O(1)
pub fn system_metric_needs_font(index: u32) -> bool { matches!(index, 4 | 15 | 31 | 51 | 53 | 55 | 57) }
pub const NONCLIENT_BYTES: u32 = 504;
pub const NONCLIENT_LEGACY_BYTES: u32 = 500;
pub const GDI_ERROR: u32 = u32::MAX;
pub const MAX_QUERY_BYTES: u32 = 16 * 1024 * 1024;
pub const ABC_INTEGER: u32 = 1;
pub const ABC_INDICES: u32 = 2;
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct QueryRequest {
    pub version: u32, pub size: u32, pub dc: u64, pub kind: u32, pub flags: u32,
    pub height: i32, pub width: i32, pub weight: i32, pub italic: u32,
    pub first: u32, pub count: u32, pub input: u64, pub output: u64,
    pub table: u32, pub offset: u32, pub capacity: u32, pub reserved: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct QueryOutput { pub result: u32, pub length: u32, pub data: u64, pub reserved: u64 }
impl QueryRequest {
    /// API failure domain, distinct from callback dispatch return registers. # C: O(1)
    pub fn failure(&self) -> u64 {
        match self.kind { QUERY_CHARSET => 1, QUERY_DATA | QUERY_GLYPHS => GDI_ERROR as u64, _ => 0 }
    }
    /// Validate sizes and pointer arithmetic before allocation or usercopy. # C: O(1)
    pub fn valid(&self) -> bool {
        if self.version != VERSION || self.size as usize != core::mem::size_of::<Self>() || (self.dc == 0 && !matches!(self.kind, QUERY_NONCLIENT | QUERY_SYSTEM_METRIC)) || self.reserved != 0
            || !self.height.checked_abs().is_some_and(|v| v <= MAX_HEIGHT) || !self.width.checked_abs().is_some_and(|v| v <= MAX_WIDTH)
            || !(0..=1000).contains(&self.weight) || self.italic > 1 || self.count > MAX_UNITS
            || self.input.checked_add(self.count as u64 * 2).is_none() { return false; }
        let bytes = match self.kind {
            QUERY_SYSTEM_METRIC if self.count == NONCLIENT_BYTES / 2 && self.output == 0 && self.capacity == 0
                && system_metric_needs_font(self.first) => 0,
            QUERY_NONCLIENT if self.count == NONCLIENT_BYTES / 2 && self.output != 0
                && matches!(self.capacity, NONCLIENT_BYTES | NONCLIENT_LEGACY_BYTES) => self.capacity,
            QUERY_CHARSET if self.count == 0 => 24,
            QUERY_DATA | QUERY_OUTLINE if self.count == 0 && self.capacity <= MAX_QUERY_BYTES => self.capacity,
            QUERY_GLYPHS if self.count == 0 || self.input != 0 => self.count * 2,
            QUERY_ABC if self.input != 0 || self.first.checked_add(self.count).is_some_and(|n| n <= 65536) => self.count * 12,
            _ => return false,
        };
        if matches!(self.kind, QUERY_GLYPHS | QUERY_ABC) && self.count != 0 && self.output == 0 { return false; }
        self.output.checked_add(bytes as u64).is_some()
    }
    /// Validate complete callback output before any destination writes. # C: O(1)
    pub fn accepts(&self, out: &QueryOutput) -> bool {
        if !self.valid() || out.reserved != 0 || out.length > MAX_QUERY_BYTES
            || out.data.checked_add(out.length as u64).is_none() || (out.length != 0 && (out.data == 0 || self.output == 0)) { return false; }
        match self.kind {
            QUERY_SYSTEM_METRIC => out.result > 0 && out.result <= i32::MAX as u32 && out.length == 0,
            QUERY_NONCLIENT => out.result == 1 && out.length == self.capacity,
            QUERY_CHARSET => out.result == 0 && out.length == if self.output == 0 { 0 } else { 24 },
            QUERY_DATA => out.result <= MAX_QUERY_BYTES && out.length == if self.output == 0 || self.capacity == 0 { 0 } else { out.result }
                && out.length <= self.capacity,
            QUERY_GLYPHS => out.result == self.count && out.length == self.count * 2,
            QUERY_ABC => out.result == 1 && out.length == self.count * 12,
            QUERY_OUTLINE => out.result <= MAX_QUERY_BYTES && out.length <= self.capacity
                && out.length == if self.output == 0 { 0 } else { out.result },
            _ => false,
        }
    }
}
