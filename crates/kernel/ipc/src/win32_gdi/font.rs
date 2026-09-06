//! Canonical LOGFONTW storage, derived metrics and selected-object lifetime; 31fk§1.
use super::{Font, GdiError, GdiManager, TYPE_FONT, DEFAULT_DC_FONT_HANDLE};
use super::stock::StockDescription;

pub const LOGFONTW_BYTES: usize = 92;
const HEIGHT: usize = 0;
const WIDTH: usize = 4;
const WEIGHT: usize = 16;
const ITALIC: usize = 20;
const CHARSET: usize = 23;
const PITCH: usize = 27;
const FACE: usize = 28;
const FACE_UNITS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FontRecord { bytes: [u8; LOGFONTW_BYTES], deleted: bool }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FontQuery { pub bytes: [u8; LOGFONTW_BYTES], pub count: usize }

impl FontRecord {
    /// Retain the complete logical record, rejecting metric overflow inputs. # C: O(1)
    pub fn from_bytes(bytes: [u8; LOGFONTW_BYTES]) -> Result<Self, GdiError> {
        let record = Self { bytes, deleted: false };
        let font = record.metrics();
        if font.height == i32::MIN || font.width == i32::MIN { return Err(GdiError::InvalidDimensions); }
        Ok(record)
    }

    /// Native DTO creation initializes unspecified logical fields to zero. # C: O(1)
    pub fn from_font(font: Font) -> Result<Self, GdiError> {
        let mut bytes = [0; LOGFONTW_BYTES];
        bytes[HEIGHT..HEIGHT + 4].copy_from_slice(&font.height.to_le_bytes());
        bytes[WIDTH..WIDTH + 4].copy_from_slice(&font.width.to_le_bytes());
        bytes[WEIGHT..WEIGHT + 4].copy_from_slice(&font.weight.to_le_bytes());
        bytes[ITALIC] = u8::from(font.italic);
        Self::from_bytes(bytes)
    }

    /// Measurement values are derived, never a second retained font description. # C: O(1)
    pub fn metrics(&self) -> Font {
        let integer = |offset: usize| i32::from_le_bytes([self.bytes[offset], self.bytes[offset + 1], self.bytes[offset + 2], self.bytes[offset + 3]]);
        Font { height: integer(HEIGHT), width: integer(WIDTH), weight: integer(WEIGHT), italic: self.bytes[ITALIC] != 0 }
    }

    /// Copy the unmodified logical bytes for object queries. # C: O(1)
    pub fn bytes(&self) -> [u8; LOGFONTW_BYTES] { self.bytes }
}

impl GdiManager {
    /// Query size or copy a bounded prefix from the same canonical font record. # C: O(fonts)
    pub fn query_font(&self, handle: u32, count: i32, has_buffer: bool) -> Result<FontQuery, GdiError> {
        let bytes = self.font_record(handle)?.bytes();
        let count = if !has_buffer || count < 0 { LOGFONTW_BYTES } else { (count as usize).min(LOGFONTW_BYTES) };
        Ok(FontQuery { bytes, count })
    }

    /// Native DTO creation enters the same complete logical record owner. # C: O(1)
    pub fn create_font(&mut self, font: Font) -> Result<u32, GdiError> {
        self.create_font_record(FontRecord::from_font(font)?)
    }

    /// Allocate one canonical font identity with no side metadata table. # C: O(1)
    pub fn create_font_record(&mut self, mut record: FontRecord) -> Result<u32, GdiError> {
        let handle = self.allocate(TYPE_FONT)?;
        record.deleted = false;
        self.fonts.push((handle, record));
        Ok(handle)
    }

    /// Return dynamic bytes or serialize immutable stock logical metadata. # C: O(fonts)
    pub fn font_record(&self, handle: u32) -> Result<FontRecord, GdiError> {
        if let Some(description) = self.stock_description(handle) {
            let StockDescription::Font(stock) = description else { return Err(GdiError::NoSuchObject); };
            let mut record = FontRecord::from_font(stock.logical)?;
            record.bytes[CHARSET] = stock.charset;
            record.bytes[PITCH] = stock.pitch_and_family;
            for (index, unit) in stock.face.encode_utf16().take(FACE_UNITS - 1).enumerate() {
                let offset = FACE + index * 2;
                record.bytes[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
            }
            return Ok(record);
        }
        self.fonts.iter().find(|(id, _)| *id == handle).map(|(_, font)| *font).ok_or(GdiError::NoSuchObject)
    }

    /// Retained selections survive deletion; the final release collects the record. # C: O(fonts * DCs)
    pub fn delete_font(&mut self, handle: u32) -> Result<(), GdiError> {
        if let Some(description) = self.stock_description(handle) {
            return if matches!(description, StockDescription::Font(_)) { Ok(()) } else { Err(GdiError::NoSuchObject) };
        }
        let record = &mut self.fonts.iter_mut().find(|(id, _)| *id == handle).ok_or(GdiError::NoSuchObject)?.1;
        record.deleted = true;
        self.collect_deleted_fonts();
        Ok(())
    }

    /// Parent DC destruction calls this after dropping its selected font. # C: O(fonts * DCs)
    pub fn collect_deleted_fonts(&mut self) {
        let dcs = &self.dcs;
        self.fonts.retain(|(id, record)| !record.deleted || dcs.iter().any(|(_, dc)| dc.font == Some(*id)));
    }

    /// Select a live font and return the previous canonical identity. # C: O(fonts * DCs)
    pub fn select_font(&mut self, dc: u32, font: u32) -> Result<u32, GdiError> {
        self.font_record(font)?;
        let state = &mut self.dcs.iter_mut().find(|(id, _)| *id == dc).ok_or(GdiError::NoSuchObject)?.1;
        let previous = state.font.unwrap_or(DEFAULT_DC_FONT_HANDLE);
        state.font = Some(font);
        self.collect_deleted_fonts();
        Ok(previous)
    }

    pub(super) fn font_for(&self, dc: u32) -> Result<Option<Font>, GdiError> {
        let state = &self.dcs.iter().find(|(id, _)| *id == dc).ok_or(GdiError::NoSuchObject)?.1;
        self.font_record(state.font.unwrap_or(DEFAULT_DC_FONT_HANDLE)).map(|record| Some(record.metrics()))
    }
}
