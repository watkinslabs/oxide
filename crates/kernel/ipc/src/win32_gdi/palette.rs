//! Canonical logical palette objects and the process palette state; 31fk§4.
//! Module manifest: `colors.rs` owns the default colour tables this file and
//! the indexed bitmap depths both resolve through.
use alloc::vec::Vec;
use super::{GdiError, GdiManager};
#[path = "palette/colors.rs"]
mod colors;
pub use colors::{default_color_entry, default_color_table_len};

pub const TYPE_PALETTE: u32 = 0x08_0000;
/// A colour a query could not resolve.
pub const CLR_INVALID: u32 = 0xffff_ffff;
/// System palette use selectors; `SYSPAL_ERROR` is also the failure answer.
pub const SYSPAL_ERROR: u32 = 0;
pub const SYSPAL_STATIC: u32 = 1;
pub const SYSPAL_NOSTATIC: u32 = 2;
pub const SYSPAL_NOSTATIC256: u32 = 3;
/// Only entries carrying this flag are replaced by an animation request.
pub const PC_RESERVED: u8 = 0x01;
/// Version word every palette this owner creates reports.
pub const PALETTE_VERSION: u16 = 0x300;
/// The default palette holds the twenty static system colours.
pub const DEFAULT_PALETTE_ENTRIES: u32 = 20;
/// Colour-table depth the default and halftone palettes draw their entries from.
const SYSTEM_TABLE_BPP: u32 = 8;
/// A halftone palette spans the whole eight-bit default colour table.
pub const HALFTONE_PALETTE_ENTRIES: u32 = 256;
/// The default palette's second ten entries are the colour table's last ten.
const SYSTEM_TAIL_BASE: u32 = 236;
const SYSTEM_HEAD_ENTRIES: u32 = 10;
const RGB_MASK: u32 = 0x00ff_ffff;
/// A COLORREF's high byte selects PALETTEINDEX (1) or PALETTERGB (2) resolution.
const SPEC_PALETTEINDEX: u32 = 1;
const SPEC_PALETTERGB: u32 = 2;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PaletteEntry { pub red: u8, pub green: u8, pub blue: u8, pub flags: u8 }

impl PaletteEntry {
    /// COLORREF orders the channels red, green, blue from the low byte. # C: O(1)
    pub fn colorref(&self) -> u32 { u32::from(self.red) | (u32::from(self.green) << 8) | (u32::from(self.blue) << 16) }
    /// Canonical surface words are XRGB. # C: O(1)
    pub fn xrgb(&self) -> u32 { (u32::from(self.red) << 16) | (u32::from(self.green) << 8) | u32::from(self.blue) }
}

/// `realized` records that a realization is outstanding: the reference stores
/// the driver's unrealize function there and clears it on unrealize.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Palette { pub version: u16, entries: Vec<PaletteEntry>, realized: bool }

impl Palette {
    /// # C: O(1)
    pub fn entries(&self) -> &[PaletteEntry] { &self.entries }
}

/// The twenty static system colours, in the order the default palette holds
/// them: the colour table's first ten then its last ten. # C: O(1)
pub fn default_palette_entry(index: u32) -> Option<PaletteEntry> {
    if index >= DEFAULT_PALETTE_ENTRIES { return None; }
    let source = if index < SYSTEM_HEAD_ENTRIES { index } else { SYSTEM_TAIL_BASE + index };
    let (red, green, blue) = default_color_entry(SYSTEM_TABLE_BPP, source)?;
    Some(PaletteEntry { red, green, blue, flags: 0 })
}

impl GdiManager {
    /// Store one logical palette; the caller's entry array is copied whole. # C: O(count)
    pub fn create_palette(&mut self, version: u16, entries: &[PaletteEntry]) -> Result<u32, GdiError> {
        let mut stored = Vec::new();
        stored.try_reserve_exact(entries.len()).map_err(|_| GdiError::HandleLimit)?;
        stored.extend_from_slice(entries);
        self.palettes.try_reserve(1).map_err(|_| GdiError::HandleLimit)?;
        let handle = self.allocate(TYPE_PALETTE)?;
        self.palettes.push((handle, Palette { version, entries: stored, realized: false }));
        Ok(handle)
    }

    /// A halftone palette is the whole eight-bit default colour table. # C: O(256)
    pub fn create_halftone_palette(&mut self) -> Result<u32, GdiError> {
        let mut entries = Vec::new();
        entries.try_reserve_exact(HALFTONE_PALETTE_ENTRIES as usize).map_err(|_| GdiError::HandleLimit)?;
        for index in 0..HALFTONE_PALETTE_ENTRIES {
            let (red, green, blue) = default_color_entry(SYSTEM_TABLE_BPP, index).ok_or(GdiError::InvalidDimensions)?;
            entries.push(PaletteEntry { red, green, blue, flags: 0 });
        }
        self.create_palette(PALETTE_VERSION, &entries)
    }

    /// # C: O(palettes)
    pub fn palette(&self, handle: u32) -> Option<&Palette> {
        self.palettes.iter().find(|(id, _)| *id == handle).map(|(_, palette)| palette)
    }

    /// Resolve a palette handle including the stock default palette, whose
    /// entries this owner materializes on demand. # C: O(palettes)
    fn palette_entry(&self, handle: u32, index: u32) -> Option<PaletteEntry> {
        if handle == super::stock::DEFAULT_PALETTE_HANDLE { return default_palette_entry(index); }
        self.palette(handle)?.entries.get(index as usize).copied()
    }

    /// Entry count of a palette, stock default included. # C: O(palettes)
    pub fn palette_count(&self, handle: u32) -> Option<u32> {
        if handle == super::stock::DEFAULT_PALETTE_HANDLE { return Some(DEFAULT_PALETTE_ENTRIES); }
        u32::try_from(self.palette(handle)?.entries.len()).ok()
    }

    /// A zero count asks for the entry count alone and copies nothing; a range
    /// past the end shortens, and a start past the end copies nothing.
    /// # C: O(count)
    pub fn get_palette_entries(&self, handle: u32, start: u32, count: u32, out: &mut [PaletteEntry]) -> u32 {
        let Some(total) = self.palette_count(handle) else { return 0; };
        if count == 0 { return total; }
        let count = if start.saturating_add(count) > total { total.saturating_sub(start) } else { count };
        if start >= total { return 0; }
        for index in 0..count.min(out.len() as u32) {
            let Some(entry) = self.palette_entry(handle, start + index) else { break; };
            out[index as usize] = entry;
        }
        count
    }

    /// The stock default palette refuses replacement; a successful write
    /// unrealizes the palette. # C: O(count)
    pub fn set_palette_entries(&mut self, handle: u32, start: u32, count: u32, entries: &[PaletteEntry]) -> u32 {
        if handle == super::stock::DEFAULT_PALETTE_HANDLE { return 0; }
        let Some(total) = self.palette_count(handle) else { return 0; };
        if start >= total { return 0; }
        let count = if start.saturating_add(count) > total { total - start } else { count };
        let Some(palette) = self.palettes.iter_mut().find(|(id, _)| *id == handle).map(|(_, palette)| palette) else { return 0; };
        for index in 0..count {
            let Some(entry) = entries.get(index as usize) else { break; };
            palette.entries[(start + index) as usize] = *entry;
        }
        self.unrealize_object(handle);
        count
    }

    /// Animation replaces only entries flagged reserved and never touches the
    /// stock default palette, which it still reports success for. # C: O(count)
    pub fn animate_palette(&mut self, handle: u32, start: u32, count: u32, entries: &[PaletteEntry]) -> bool {
        if handle == super::stock::DEFAULT_PALETTE_HANDLE { return true; }
        let Some(total) = self.palette_count(handle) else { return false; };
        if start >= total { return false; }
        let count = if start.saturating_add(count) > total { total - start } else { count };
        let Some(palette) = self.palettes.iter_mut().find(|(id, _)| *id == handle).map(|(_, palette)| palette) else { return false; };
        for index in 0..count {
            let Some(entry) = entries.get(index as usize) else { break; };
            let slot = &mut palette.entries[(start + index) as usize];
            if slot.flags & PC_RESERVED != 0 { *slot = *entry; }
        }
        true
    }

    /// Growth zero-fills the new entries; either direction unrealizes. # C: O(count)
    pub fn resize_palette(&mut self, handle: u32, count: u32) -> bool {
        let Some(palette) = self.palettes.iter_mut().find(|(id, _)| *id == handle).map(|(_, palette)| palette) else { return false; };
        let count = count as usize;
        if count > palette.entries.len() && palette.entries.try_reserve(count - palette.entries.len()).is_err() { return false; }
        palette.entries.resize(count, PaletteEntry::default());
        self.unrealize_object(handle);
        true
    }

    /// Nearest entry by squared channel distance; the first exact match wins
    /// and an unresolvable handle answers index zero. # C: O(entries)
    pub fn nearest_palette_index(&self, handle: u32, color: u32) -> u32 {
        let Some(total) = self.palette_count(handle) else { return 0; };
        let (red, green, blue) = (color & 0xff, (color >> 8) & 0xff, (color >> 16) & 0xff);
        let (mut index, mut best) = (0u32, i32::MAX);
        for candidate in 0..total {
            if best == 0 { break; }
            let Some(entry) = self.palette_entry(handle, candidate) else { break; };
            let channel = |entry: u8, want: u32| i32::from(entry) - want as i32;
            let (r, g, b) = (channel(entry.red, red), channel(entry.green, green), channel(entry.blue, blue));
            let distance = r * r + g * g + b * b;
            if distance < best { index = candidate; best = distance; }
        }
        index
    }

    /// A device without a palette answers the request colour unchanged; a
    /// palettised one resolves PALETTEINDEX and PALETTERGB through the DC's
    /// selected palette and masks the result to RGB. # C: O(DCs + entries)
    pub fn nearest_color(&self, dc: u32, color: u32, device_has_palette: bool) -> Result<u32, GdiError> {
        let state = &self.dcs.iter().find(|(id, _)| *id == dc).ok_or(GdiError::NoSuchObject)?.1;
        if !device_has_palette { return Ok(color); }
        let spec = color >> 24;
        if spec != SPEC_PALETTEINDEX && spec != SPEC_PALETTERGB { return Ok(color & RGB_MASK); }
        let palette = state.palette.unwrap_or(super::stock::DEFAULT_PALETTE_HANDLE);
        let index = if spec == SPEC_PALETTERGB { self.nearest_palette_index(palette, color) } else { color & 0xffff };
        let entry = match self.palette_entry(palette, index) {
            Some(entry) => entry,
            None => match self.palette_entry(palette, 0) { Some(entry) => entry, None => return Ok(CLR_INVALID) },
        };
        Ok(entry.colorref() & RGB_MASK)
    }

    /// # C: O(1)
    pub fn system_palette_use(&self) -> u32 { self.system_palette_use }

    /// A device without a palette refuses every request; an unnamed selector
    /// is refused too, and the previous selector is the success answer.
    /// # C: O(1)
    pub fn set_system_palette_use(&mut self, use_value: u32, device_has_palette: bool) -> u32 {
        if !device_has_palette { return SYSPAL_ERROR; }
        let old = self.system_palette_use;
        match use_value {
            SYSPAL_STATIC | SYSPAL_NOSTATIC | SYSPAL_NOSTATIC256 => { self.system_palette_use = use_value; old }
            _ => SYSPAL_ERROR,
        }
    }

    /// Clearing an outstanding realization also clears the last-realized
    /// record when it names this palette. Objects with no realization state
    /// report success unchanged. # C: O(palettes)
    pub fn unrealize_object(&mut self, handle: u32) -> bool {
        if let Some(palette) = self.palettes.iter_mut().find(|(id, _)| *id == handle).map(|(_, palette)| palette) {
            palette.realized = false;
        }
        if self.last_realized_palette == Some(handle) { self.last_realized_palette = None; }
        true
    }

    /// Selecting a non-palette handle refuses before the DC is resolved. A
    /// foreground selection records the process primary palette.
    /// # C: O(DCs + palettes)
    pub fn select_palette(&mut self, dc: u32, palette: u32, is_primary: bool) -> Result<u32, GdiError> {
        if self.palette(palette).is_none() && palette != super::stock::DEFAULT_PALETTE_HANDLE { return Err(GdiError::NoSuchObject); }
        let state = &mut self.dcs.iter_mut().find(|(id, _)| *id == dc).ok_or(GdiError::NoSuchObject)?.1;
        let previous = state.palette.unwrap_or(super::stock::DEFAULT_PALETTE_HANDLE);
        state.palette = Some(palette);
        if is_primary { self.primary_palette = Some(palette); }
        Ok(previous)
    }

    /// Returns the number of entries the device mapped. This owner's surfaces
    /// are direct-colour, so a realization maps nothing and the count is zero;
    /// realizing the same palette twice in a row is skipped entirely.
    /// # C: O(DCs + palettes)
    pub fn realize_palette(&mut self, dc: u32) -> Result<u32, GdiError> {
        let state = &self.dcs.iter().find(|(id, _)| *id == dc).ok_or(GdiError::NoSuchObject)?.1;
        let selected = state.palette.unwrap_or(super::stock::DEFAULT_PALETTE_HANDLE);
        if selected == super::stock::DEFAULT_PALETTE_HANDLE { return Ok(0); }
        if self.last_realized_palette == Some(selected) { return Ok(0); }
        self.last_realized_palette = Some(selected);
        if let Some(palette) = self.palettes.iter_mut().find(|(id, _)| *id == selected).map(|(_, palette)| palette) {
            palette.realized = true;
        }
        Ok(0)
    }

    /// The palette a foreground window realized, for palette-change notification. # C: O(1)
    pub fn primary_palette(&self) -> Option<u32> { self.primary_palette }

    /// The palette selected in one device context, defaulting to the stock
    /// default palette. # C: O(DCs)
    pub fn dc_palette(&self, dc: u32) -> Result<u32, GdiError> {
        let state = &self.dcs.iter().find(|(id, _)| *id == dc).ok_or(GdiError::NoSuchObject)?.1;
        Ok(state.palette.unwrap_or(super::stock::DEFAULT_PALETTE_HANDLE))
    }

    /// Deleting a palette unrealizes it first, exactly as the reference does. # C: O(palettes + DCs)
    pub fn delete_palette(&mut self, handle: u32) -> Result<(), GdiError> {
        if self.palettes.iter().all(|(id, _)| *id != handle) { return Err(GdiError::NoSuchObject); }
        self.unrealize_object(handle);
        self.palettes.retain(|(id, _)| *id != handle);
        for (_, state) in self.dcs.iter_mut() { if state.palette == Some(handle) { state.palette = None; } }
        if self.primary_palette == Some(handle) { self.primary_palette = None; }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/palette.rs"]
mod tests;
