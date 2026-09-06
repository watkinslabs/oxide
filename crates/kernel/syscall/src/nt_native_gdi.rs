//! Versioned native text callback ABI (`31ge§2`).
#[path = "nt_native_gdi/measure.rs"]
mod measure;
pub use measure::*;
#[path = "nt_native_gdi/query.rs"]
mod query;
pub use query::*;
pub const INFO_CLASS: u64 = 1007;
pub const VERSION: u32 = 1;
pub const REGISTER: u64 = 0;
pub const COMPLETE: u64 = 1;
pub const ALPHA_UPLOAD: u64 = 2;
pub const TRANSPARENT: u32 = 1;
pub const BACKGROUND_OPAQUE: u32 = 2;
pub const TOKEN: u64 = 0x4e54_4744_4954;
pub const MAX_UNITS: u32 = 4096;
pub const MAX_HEIGHT: i32 = 256;
pub const MAX_WIDTH: i32 = 256;
pub const OPAQUE: u32 = 2;
pub const CLIPPED: u32 = 4;
pub const GLYPH_INDEX: u32 = 0x10;
pub const IGNORE_LANGUAGE: u32 = 0x1000;
pub const PDY: u32 = 0x2000;
pub const INVALID: u64 = 0xc000_000d;
pub const NOT_READY: u64 = 0xc000_00a3;
const STACK_ALIGNMENT: u64 = 16;
const CALLBACK_LINK_AND_SHADOW: u64 = 40;

/// Stack storage shared by both registered native callback request layouts. # C: O(1)
pub fn callback_storage_layout(original_sp: u64, bytes: usize, arch: CallbackArch) -> Option<(u64, u64)> {
    if bytes > core::mem::size_of::<TextRequest>() + MAX_UNITS as usize * 10 { return None; }
    let payload = original_sp.checked_sub(bytes as u64 + STACK_ALIGNMENT)? & !(STACK_ALIGNMENT - 1);
    let stack = payload.checked_sub(CALLBACK_LINK_AND_SHADOW)?;
    let stack = match arch { CallbackArch::X86_64 => stack, CallbackArch::Aarch64 => stack & !(STACK_ALIGNMENT - 1) };
    Some((payload, stack))
}

#[derive(Clone, Copy)]
pub enum CallbackArch { X86_64, Aarch64 }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallbackLayout {
    pub payload: u64, pub stack: u64, pub text: u64, pub advances: u64, pub bytes: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TextRequest {
    pub version: u32, pub size: u32, pub dc: u64,
    pub x: i32, pub y: i32, pub flags: u32, pub count: u32,
    pub text: u64, pub advances: u64, pub rect: [i32; 4],
    pub height: i32, pub width: i32, pub weight: i32, pub italic: u32,
    pub foreground: u32, pub background: u32, pub has_rect: u32, pub reserved: u32,
    pub background_mode: u32, pub alignment: u32, pub current_x: i32, pub current_y: i32,
}

impl TextRequest {
    /// Validate before either side dereferences caller text. # C: O(1)
    pub fn valid(&self) -> bool {
        self.version == VERSION && self.size as usize == core::mem::size_of::<Self>()
            && self.width.checked_abs().is_some_and(|w| w <= MAX_WIDTH) && (0..=1000).contains(&self.weight) && self.italic <= 1 && self.reserved == 0
            && matches!(self.background_mode, TRANSPARENT | BACKGROUND_OPAQUE) && self.alignment == 0
            && self.dc != 0 && self.count <= MAX_UNITS && (self.count == 0 || self.text != 0)
            && self.flags & !(OPAQUE | CLIPPED | GLYPH_INDEX | IGNORE_LANGUAGE | PDY) == 0 && self.has_rect <= 1
            && (self.flags & (OPAQUE | CLIPPED) == 0 || self.has_rect == 1)
            && (self.has_rect == 0 || (self.rect[0] <= self.rect[2] && self.rect[1] <= self.rect[3]))
            && self.height.checked_abs().is_some_and(|h| h <= MAX_HEIGHT)
            && self.text.checked_add(self.count as u64 * 2).is_some()
            && self.advances.checked_add(self.advance_count() as u64 * 4).is_some()
    }
    /// PDY contains signed X/Y pairs for every input WORD. # C: O(1)
    pub fn advance_count(&self) -> usize { self.count as usize * if self.flags & PDY != 0 { 2 } else { 1 } }
    /// Total callback storage including aligned advance array. # C: O(1)
    pub fn payload_bytes(&self) -> Option<usize> {
        if !self.valid() { return None; }
        let text_end = core::mem::size_of::<Self>() + self.count as usize * 2;
        Some((text_end + 3) & !3usize).and_then(|end| end.checked_add(if self.advances == 0 { 0 } else { self.advance_count() * 4 }))
    }
    /// Fixed callback ABI layout; no pointer accesses or Task state changes. # C: O(1)
    pub fn callback_layout(&self, original_sp: u64, arch: CallbackArch) -> Option<CallbackLayout> {
        let bytes = self.payload_bytes()?;
        let (payload, stack) = callback_storage_layout(original_sp, bytes, arch)?;
        let text = payload.checked_add(core::mem::size_of::<Self>() as u64)?;
        let advances = if self.advances == 0 { 0 } else { text.checked_add(self.count as u64 * 2 + 3)? & !3 };
        Some(CallbackLayout { payload, stack, text, advances, bytes })
    }
}
