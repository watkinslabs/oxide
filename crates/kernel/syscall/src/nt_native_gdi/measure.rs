use super::*;

pub const MEASURE_COPY: u64 = 3;
pub const MEASURE_METRICS: u32 = 1;
pub const MEASURE_EXTENT: u32 = 2;
pub const TEXTMETRIC_BYTES: usize = 60;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MeasureRequest {
    pub version: u32, pub size: u32, pub dc: u64, pub kind: u32, pub count: u32,
    pub height: i32, pub width: i32, pub weight: i32, pub italic: u32,
    pub max_extent: i32, pub flags: u32, pub text: u64, pub metrics: u64,
    pub extent: u64, pub fit: u64, pub cumulative: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MeasureOutput {
    pub metrics: [u8; TEXTMETRIC_BYTES], pub width: i32, pub height: i32,
    pub fit: u32, pub count: u32, pub reserved: u32, pub cumulative: u64,
}

impl MeasureOutput {
    /// Validate the complete native extent result before choosing the copyout prefix. # C: O(count)
    pub fn extent_copy_count(&self, request: &MeasureRequest, advances: &[u8]) -> Option<usize> {
        if !request.valid() || request.kind != MEASURE_EXTENT || self.reserved != 0
            || self.count != request.count || self.fit > request.count || self.width < 0 || self.height < 0
            || advances.len() != request.count as usize * 4 { return None; }
        let mut previous = 0;
        let mut fit = 0;
        for bytes in advances.chunks_exact(4) {
            let position = i32::from_le_bytes(bytes.try_into().ok()?);
            if position < previous { return None; }
            if position as u32 <= request.max_extent as u32 { fit += 1; }
            previous = position;
        }
        if previous != self.width || fit != self.fit { return None; }
        Some(if request.fit == 0 { request.count as usize } else { fit as usize })
    }
}

impl MeasureRequest {
    /// Fixed measurement ABI admission before any user-buffer access. # C: O(1)
    pub fn valid(&self) -> bool {
        self.version == VERSION && self.size as usize == core::mem::size_of::<Self>() && self.dc != 0
            && self.count <= MAX_UNITS && self.width.checked_abs().is_some_and(|w| w <= MAX_WIDTH)
            && self.height.checked_abs().is_some_and(|h| h <= MAX_HEIGHT)
            && (0..=1000).contains(&self.weight) && self.italic <= 1
            && match self.kind {
                MEASURE_METRICS => self.count == 0 && self.metrics != 0 && self.metrics.checked_add(TEXTMETRIC_BYTES as u64).is_some(),
                MEASURE_EXTENT => self.extent != 0 && (self.count == 0 || self.text != 0)
                    && self.text.checked_add(self.count as u64 * 2).is_some()
                    && self.extent.checked_add(8).is_some() && self.fit.checked_add(4).is_some()
                    && self.cumulative.checked_add(self.count as u64 * 4).is_some(),
                _ => false,
            }
    }
    /// Native callback copied header plus UTF-16 storage. # C: O(1)
    pub fn payload_bytes(&self) -> Option<usize> {
        self.valid().then_some(core::mem::size_of::<Self>() + self.count as usize * 2)
    }
}
