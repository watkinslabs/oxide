//! Client GDI byte projection and shared text snapshot (`31gf`). No object ownership.
#[path = "nt_gdi_client/size.rs"]
mod size;
pub const ENTRY_SIZE: usize = 24;
pub const DC_ATTR_SIZE: usize = 192;
pub const HANDLE_COUNT: u32 = 65536;
pub const TABLE_BYTES: usize = HANDLE_COUNT as usize * ENTRY_SIZE;
pub const DC_ATTR_BYTES: usize = HANDLE_COUNT as usize * DC_ATTR_SIZE;
pub const PEB_TABLE_OFFSET: u64 = 0xf8;
pub const HANDLE_TYPE_MASK: u32 = 0x007f0000;
pub const HANDLE_STOCK: u32 = 0x00800000;
pub const TYPE_DC: u32 = 0x010000;
pub const TYPE_MEMDC: u32 = 0x410000;
pub const TYPE_FONT: u32 = 0x0a0000;
const BASE_TYPE_MASK: u8 = 0x1f;
const SLOT_MASK: u32 = 0xffff;
const RGB_MASK: u32 = 0x00ffffff;
const ALIGN_MASK: u32 = 0x011f;
const TRANSPARENT: u32 = 1;
const OPAQUE: u32 = 2;

/// Complete fixed-width client record offsets; fields never use host layout.
pub mod dc {
    pub const HDC: usize = 0; pub const DISABLED: usize = 4; pub const SAVE_LEVEL: usize = 8;
    pub const BACKGROUND_COLOR: usize = 12; pub const BRUSH_COLOR: usize = 16;
    pub const PEN_COLOR: usize = 20; pub const TEXT_COLOR: usize = 24; pub const CUR_POS: usize = 28;
    pub const GRAPHICS_MODE: usize = 36; pub const ARC_DIRECTION: usize = 40; pub const LAYOUT: usize = 44;
    pub const TEXT_ALIGN: usize = 48; pub const BACKGROUND_MODE: usize = 50;
    pub const POLY_FILL_MODE: usize = 52; pub const ROP_MODE: usize = 54;
    pub const REL_ABS_MODE: usize = 56; pub const STRETCH_BLT_MODE: usize = 58;
    pub const MAP_MODE: usize = 60; pub const CHAR_EXTRA: usize = 64; pub const MAPPER_FLAGS: usize = 68;
    pub const VIS_RECT: usize = 72; pub const MITER_LIMIT: usize = 88;
    pub const BRUSH_ORG: usize = 92; pub const WND_ORG: usize = 100; pub const WND_EXT: usize = 108;
    pub const VPORT_ORG: usize = 116; pub const VPORT_EXT: usize = 124;
    pub const VIRTUAL_RES: usize = 132; pub const VIRTUAL_SIZE: usize = 140;
    pub const FONT_CODE_PAGE: usize = 148; pub const EMF_BOUNDS: usize = 152;
    pub const EMF: usize = 168; pub const ABORT_PROC: usize = 176; pub const PRINT: usize = 184;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error { Length, Handle, Pointer, ObjectPointer, Disabled, Color, Alignment, BackgroundMode, Dimensions, UnsupportedTransform }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandleEntry { pub owner: u32, pub unique: u16, pub kind: u8, pub flags: u8, pub user_pointer: u64 }

impl HandleEntry {
    /// Project a caller-validated canonical identity; never allocate one. # C: O(1)
    pub fn for_handle(handle: u32, process_id: u16, user_pointer: u64) -> Result<Self, Error> {
        let kind = ((handle >> 16) as u8) & BASE_TYPE_MASK;
        if handle & SLOT_MASK == 0 || kind == 0 { return Err(Error::Handle); }
        if user_pointer != 0 { user_range(user_pointer, 1)?; }
        Ok(Self { owner: process_id as u32, unique: (handle >> 16) as u16, kind, flags: 0, user_pointer })
    }
    /// Object is always zero; no native/kernel object address is representable. # C: O(1)
    pub fn encode(self) -> Result<[u8; ENTRY_SIZE], Error> {
        if self.kind != 0 && self.kind != (self.unique as u8 & BASE_TYPE_MASK) { return Err(Error::Handle); }
        if self.user_pointer != 0 { user_range(self.user_pointer, 1)?; }
        let mut out = [0; ENTRY_SIZE];
        put32(&mut out, 8, self.owner); put16(&mut out, 12, self.unique);
        out[14] = self.kind; out[15] = self.flags;
        out[16..24].copy_from_slice(&self.user_pointer.to_le_bytes());
        Ok(out)
    }
    /// Decode untrusted projection bytes, never an ownership lookup. # C: O(1)
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != ENTRY_SIZE { return Err(Error::Length); }
        if bytes[..8] != [0; 8] { return Err(Error::ObjectPointer); }
        let out = Self { owner: get32(bytes, 8), unique: get16(bytes, 12), kind: bytes[14], flags: bytes[15],
            user_pointer: u64::from_le_bytes(bytes[16..24].try_into().map_err(|_| Error::Length)?) };
        out.encode()?;
        Ok(out)
    }
    /// Caller selects this entry by low-16 slot. Legacy client matching only,
    /// NOT canonical kernel admission. # C: O(1)
    pub fn client_matches(self, handle: u32) -> bool {
        self.kind != 0 && (handle >> 16 == 0 || handle >> 16 == self.unique as u32)
    }
    /// # C: O(1)
    pub fn extended_type(self) -> u8 { self.unique as u8 & 0x7f }
    /// # C: O(1)
    pub fn stock(self) -> bool { self.unique & 0x80 != 0 }
    /// # C: O(1)
    pub fn generation(self) -> u8 { (self.unique >> 8) as u8 }
}

fn user_range(base: u64, bytes: u64) -> Result<u64, Error> {
    if base == 0 || base >= hal::USER_VA_END || base.checked_add(bytes).filter(|end| *end <= hal::USER_VA_END).is_none() {
        return Err(Error::Pointer);
    }
    Ok(base)
}

fn slot_address(base: u64, slot: u32, stride: usize) -> Result<u64, Error> {
    if slot >= HANDLE_COUNT { return Err(Error::Handle); }
    if base & 7 != 0 { return Err(Error::Pointer); }
    user_range(base, HANDLE_COUNT as u64 * stride as u64)?;
    base.checked_add(slot as u64 * stride as u64).ok_or(Error::Pointer)
}

/// Address from retained mapping + canonical slot, not client UserPointer. # C: O(1)
pub fn entry_address(base: u64, slot: u32) -> Result<u64, Error> { slot_address(base, slot, ENTRY_SIZE) }
/// Address from retained mapping + canonical slot, not client UserPointer. # C: O(1)
pub fn dc_attr_address(base: u64, slot: u32) -> Result<u64, Error> { slot_address(base, slot, DC_ATTR_SIZE) }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DcText {
    pub foreground: u32, pub background: u32, pub alignment: u32,
    pub background_mode: u32, pub current_position: (i32, i32),
}

impl Default for DcText {
    fn default() -> Self { Self { foreground: 0, background: RGB_MASK, alignment: 0,
        background_mode: OPAQUE, current_position: (0, 0) } }
}

/// Plain RGB only; palette-index/PALETTERGB semantics require a palette owner. # C: O(1)
pub fn colorref_to_xrgb(value: u32) -> Result<u32, Error> {
    if value & !RGB_MASK != 0 { return Err(Error::Color); }
    Ok(((value & 0xff) << 16) | (value & 0xff00) | ((value >> 16) & 0xff))
}
/// # C: O(1)
pub fn xrgb_to_colorref(value: u32) -> Result<u32, Error> { colorref_to_xrgb(value) }

fn validate_text(text: DcText) -> Result<(), Error> {
    colorref_to_xrgb(text.foreground)?; colorref_to_xrgb(text.background)?;
    if !matches!(text.background_mode, TRANSPARENT | OPAQUE) { return Err(Error::BackgroundMode); }
    if text.alignment & !ALIGN_MASK != 0 || !matches!(text.alignment & 6, 0 | 2 | 6)
        || !matches!(text.alignment & 0x18, 0 | 8 | 0x18) { return Err(Error::Alignment); }
    Ok(())
}

/// Initialize all 192 bytes before publishing a live handle entry. # C: O(1)
pub fn encode_dc_attr(handle: u32, width: i32, height: i32, text: DcText) -> Result<[u8; DC_ATTR_SIZE], Error> {
    if ((handle & HANDLE_TYPE_MASK) >> 16) as u8 & BASE_TYPE_MASK != 1 || handle & SLOT_MASK == 0 { return Err(Error::Handle); }
    size::dimensions(width, height)?;
    validate_text(text)?;
    let mut out = [0; DC_ATTR_SIZE];
    put32(&mut out, dc::HDC, handle);
    put32(&mut out, dc::BACKGROUND_COLOR, xrgb_to_colorref(text.background)?);
    put32(&mut out, dc::BRUSH_COLOR, RGB_MASK);
    put32(&mut out, dc::TEXT_COLOR, xrgb_to_colorref(text.foreground)?);
    put32(&mut out, dc::CUR_POS, text.current_position.0 as u32);
    put32(&mut out, dc::CUR_POS + 4, text.current_position.1 as u32);
    for offset in [dc::GRAPHICS_MODE, dc::ARC_DIRECTION, dc::MAP_MODE, dc::WND_EXT, dc::WND_EXT + 4,
        dc::VPORT_EXT, dc::VPORT_EXT + 4] { put32(&mut out, offset, 1); }
    for (offset, value) in [(dc::TEXT_ALIGN, text.alignment as u16), (dc::BACKGROUND_MODE, text.background_mode as u16),
        (dc::POLY_FILL_MODE, 1), (dc::ROP_MODE, 13), (dc::REL_ABS_MODE, 1), (dc::STRETCH_BLT_MODE, 1)] { put16(&mut out, offset, value); }
    put32(&mut out, dc::VIS_RECT + 8, width as u32); put32(&mut out, dc::VIS_RECT + 12, height as u32);
    put32(&mut out, dc::MITER_LIMIT, 10.0f32.to_bits());
    Ok(out)
}

/// One copied record supplies authoritative text state. No pointer fields followed.
/// Unsupported transforms must fail before a render/measure callback. # C: O(1)
pub fn decode_text(bytes: &[u8], expected_handle: u32) -> Result<DcText, Error> {
    if bytes.len() != DC_ATTR_SIZE { return Err(Error::Length); }
    if get32(bytes, dc::HDC) != expected_handle || expected_handle & SLOT_MASK == 0
        || ((expected_handle >> 16) as u8 & BASE_TYPE_MASK) != 1 { return Err(Error::Handle); }
    if get32(bytes, dc::DISABLED) != 0 { return Err(Error::Disabled); }
    for (offset, expected) in [(dc::GRAPHICS_MODE, 1), (dc::MAP_MODE, 1), (dc::LAYOUT, 0), (dc::CHAR_EXTRA, 0),
        (dc::MAPPER_FLAGS, 0), (dc::WND_ORG, 0), (dc::WND_ORG + 4, 0), (dc::VPORT_ORG, 0), (dc::VPORT_ORG + 4, 0),
        (dc::WND_EXT, 1), (dc::WND_EXT + 4, 1), (dc::VPORT_EXT, 1), (dc::VPORT_EXT + 4, 1)] {
        if get32(bytes, offset) != expected { return Err(Error::UnsupportedTransform); }
    }
    let left = get32(bytes, dc::VIS_RECT) as i32; let top = get32(bytes, dc::VIS_RECT + 4) as i32;
    let right = get32(bytes, dc::VIS_RECT + 8) as i32; let bottom = get32(bytes, dc::VIS_RECT + 12) as i32;
    size::visible_rect(left, top, right, bottom)?;
    let text = DcText { foreground: colorref_to_xrgb(get32(bytes, dc::TEXT_COLOR))?,
        background: colorref_to_xrgb(get32(bytes, dc::BACKGROUND_COLOR))?,
        alignment: get16(bytes, dc::TEXT_ALIGN) as u32, background_mode: get16(bytes, dc::BACKGROUND_MODE) as u32,
        current_position: (get32(bytes, dc::CUR_POS) as i32, get32(bytes, dc::CUR_POS + 4) as i32) };
    validate_text(text)?;
    Ok(text)
}

fn get16(bytes: &[u8], at: usize) -> u16 { u16::from_le_bytes([bytes[at], bytes[at + 1]]) }
fn get32(bytes: &[u8], at: usize) -> u32 { u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]) }
fn put16(bytes: &mut [u8], at: usize, value: u16) { bytes[at..at + 2].copy_from_slice(&value.to_le_bytes()); }
fn put32(bytes: &mut [u8], at: usize, value: u32) { bytes[at..at + 4].copy_from_slice(&value.to_le_bytes()); }

#[cfg(test)]
#[path = "nt_gdi_client/tests.rs"]
mod tests;
