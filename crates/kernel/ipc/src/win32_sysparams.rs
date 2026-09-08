//! Session-wide Win32 system parameters: one store for every scalar setting a
//! client reads or writes through the system-parameters entry point, and the
//! classification of one action into what that call must transfer.
//!
//! Module manifest:
//! - `table`: the entries, their action pairs, their kinds and their defaults.
//! - `route`: one action plus its `uiParam` into a `Request` the caller performs.
//!
//! The store holds only values. Every user-memory transfer, and the font and
//! nonclient answers that need the graphics owner, belong to the caller: this
//! module decides, it does not copy.

extern crate alloc;

#[path = "win32_sysparams/table.rs"]
pub mod table;

pub use table::{a as action, Entry, Kind, ENTRIES, NO_ACTION};

use table::{slot, DEFAULT_DPI, TWIPS_PER_INCH};

/// Bytes one `LOGFONTW` occupies, as the graphics owner writes one.
pub use crate::win32_gdi::LOGFONTW_BYTES;

/// What one system-parameter call must transfer once the action is decoded.
/// `Refused` is the answer to an action this kernel names no entry for, which
/// is the same `FALSE` the reference answers an unknown action with.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Request {
    /// Write these four bytes at `pvParam`; absent `pvParam` refuses.
    Word(u32),
    /// Write these words at `pvParam` in order, four bytes each.
    Words(alloc::vec::Vec<u32>),
    /// Write the named profile face's `LOGFONTW` at `pvParam`.
    Font,
    /// Write the icon-metrics record at `pvParam`: three words then the face.
    IconMetrics(alloc::vec::Vec<u32>),
    /// Write up to `uiParam` units of the stored wallpaper path at `pvParam`.
    Path,
    /// The nonclient profile answers through the graphics owner, not here.
    Nonclient,
    /// The action was applied to the store; nothing is written back.
    Applied,
    /// No entry names this action.
    Refused,
}

/// Values one `SETICONMETRICS`/`SETMINIMIZEDMETRICS`/`SETMOUSE` call carries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructWrite<'a> { pub words: &'a [i32], pub font: Option<&'a [u8; LOGFONTW_BYTES]> }

/// Every scalar system parameter, plus the wallpaper path and the icon-title
/// face a client may replace. One process's write is every process's read, as
/// a session-wide setting is.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemParameters {
    values: [i32; ENTRIES.len()],
    /// Icon-title face a client wrote, absent while the profile's own face answers.
    icon_font: Option<[u8; LOGFONTW_BYTES]>,
    /// Profile faces a client replaced, in profile order; absent entries keep
    /// the face the stock description names.
    nonclient_fonts: [Option<[u8; LOGFONTW_BYTES]>; NONCLIENT_FACES],
    wallpaper: alloc::vec::Vec<u16>,
}

impl Default for SystemParameters { fn default() -> Self { Self::new() } }

impl SystemParameters {
    /// Start every entry at the value it is quoted with before anything writes
    /// one. # C: O(N_entries)
    pub const fn new() -> Self {
        let mut values = [0; ENTRIES.len()];
        let mut index = 0;
        while index < ENTRIES.len() { values[index] = ENTRIES[index].default; index += 1; }
        Self { values, icon_font: None, nonclient_fonts: [None; NONCLIENT_FACES], wallpaper: alloc::vec::Vec::new() }
    }

    /// The stored value of one slot, still in its own quoting. # C: O(1)
    pub fn raw(&self, slot: usize) -> i32 { self.values[slot] }

    /// One slot's value in pixels at `dpi`: a twips entry is negative while it
    /// is quoted in twips, and 1440 twips is one inch. # C: O(1)
    pub fn pixels(&self, slot: usize, dpi: u32) -> i32 { resolve(ENTRIES[slot].kind, self.values[slot], dpi) }

    /// The icon-title face a client wrote, absent while the profile answers.
    /// # C: O(1)
    pub fn icon_font(&self) -> Option<&[u8; LOGFONTW_BYTES]> { self.icon_font.as_ref() }

    /// The stored wallpaper path, empty until one is written. # C: O(1)
    pub fn wallpaper(&self) -> &[u16] { &self.wallpaper }

    /// Decode one reading action into what the caller must write back.
    /// `pointer` says whether the call carries a `pvParam`, which the
    /// dual-purpose spacing actions read as "get" rather than "set".
    /// # C: O(N_entries)
    pub fn read(&self, action: u32, dpi: u32, pointer: bool) -> Request {
        match action {
            action::GET_NONCLIENT_METRICS => return Request::Nonclient,
            action::GET_ICON_TITLE_LOGFONT => return Request::Font,
            action::GET_DESK_WALLPAPER => return Request::Path,
            // The reference answers this one TRUE without consulting a stored value.
            action::GET_FAST_TASK_SWITCH => return Request::Word(1),
            action::GET_MOUSE => return Request::Words(alloc::vec![
                self.values[slot::MOUSE_THRESHOLD1] as u32, self.values[slot::MOUSE_THRESHOLD2] as u32,
                self.values[slot::MOUSE_ACCELERATION] as u32]),
            action::GET_MINIMIZED_METRICS => return Request::Words(alloc::vec![
                self.pixels(slot::MIN_WIDTH, dpi) as u32, self.pixels(slot::MIN_HORZ_GAP, dpi) as u32,
                self.pixels(slot::MIN_VERT_GAP, dpi) as u32, self.pixels(slot::MIN_ARRANGE, dpi) as u32]),
            action::GET_ICON_METRICS => return Request::IconMetrics(alloc::vec![
                self.pixels(slot::ICON_HORIZONTAL_SPACING, dpi) as u32,
                self.pixels(slot::ICON_VERTICAL_SPACING, dpi) as u32,
                self.values[slot::ICON_TITLE_WRAP] as u32]),
            // Both spacing actions read when the call carries an output pointer
            // and write when it does not.
            action::ICON_HORIZONTAL_SPACING if pointer => return Request::Word(self.pixels(slot::ICON_HORIZONTAL_SPACING, dpi) as u32),
            action::ICON_VERTICAL_SPACING if pointer => return Request::Word(self.pixels(slot::ICON_VERTICAL_SPACING, dpi) as u32),
            _ => {}
        }
        match slot_of_get(action) {
            Some(slot) => Request::Word(self.pixels(slot, dpi) as u32),
            None => Request::Refused,
        }
    }

    /// Apply one writing action. `value` is the call's `uiParam`; `carried`
    /// holds the words and face a struct-shaped write brings with it.
    /// # C: O(N_entries)
    pub fn write(&mut self, action: u32, value: i32, carried: Option<StructWrite<'_>>) -> Request {
        match action {
            action::SET_NONCLIENT_METRICS => {
                let Some(carried) = carried else { return Request::Refused; };
                if carried.words.len() < NONCLIENT_DIMENSIONS.len() { return Request::Refused; }
                // The border a caller reads back carries the padded border with
                // it, so the border it writes back has to have it taken off.
                let padded = self.values[slot::PADDED_BORDER_WIDTH];
                for (index, slot) in NONCLIENT_DIMENSIONS.into_iter().enumerate() {
                    let word = carried.words[index];
                    self.values[slot] = if slot == slot::BORDER { word.saturating_sub(padded) } else { word };
                }
                if let Some(face) = carried.font { self.nonclient_fonts[NONCLIENT_MENU_FACE] = Some(*face); }
                return Request::Applied;
            }
            action::SET_FAST_TASK_SWITCH => return Request::Refused,
            action::SET_ICON_TITLE_LOGFONT => {
                let Some(font) = carried.and_then(|carried| carried.font.copied()) else { return Request::Refused; };
                self.icon_font = Some(font); return Request::Applied;
            }
            action::SET_MOUSE => {
                let Some(words) = carried.map(|carried| carried.words) else { return Request::Refused; };
                if words.len() < 3 { return Request::Refused; }
                self.values[slot::MOUSE_THRESHOLD1] = words[0];
                self.values[slot::MOUSE_THRESHOLD2] = words[1];
                self.values[slot::MOUSE_ACCELERATION] = words[2];
                return Request::Applied;
            }
            action::SET_MINIMIZED_METRICS => {
                let Some(words) = carried.map(|carried| carried.words) else { return Request::Refused; };
                if words.len() < 4 { return Request::Refused; }
                self.values[slot::MIN_WIDTH] = words[0].max(0);
                self.values[slot::MIN_HORZ_GAP] = words[1].max(0);
                self.values[slot::MIN_VERT_GAP] = words[2].max(0);
                self.values[slot::MIN_ARRANGE] = words[3] & 0x0f;
                return Request::Applied;
            }
            action::SET_ICON_METRICS => {
                let Some(carried) = carried else { return Request::Refused; };
                if carried.words.len() < 3 { return Request::Refused; }
                self.values[slot::ICON_HORIZONTAL_SPACING] = carried.words[0].max(MIN_ICON_SPACING);
                self.values[slot::ICON_VERTICAL_SPACING] = carried.words[1].max(MIN_ICON_SPACING);
                self.values[slot::ICON_TITLE_WRAP] = carried.words[2];
                if let Some(font) = carried.font { self.icon_font = Some(*font); }
                return Request::Applied;
            }
            // The caller reads the path out of user memory and stores it.
            action::SET_DESK_WALLPAPER => return Request::Path,
            action::ICON_HORIZONTAL_SPACING => {
                self.values[slot::ICON_HORIZONTAL_SPACING] = value.max(MIN_ICON_SPACING); return Request::Applied;
            }
            action::ICON_VERTICAL_SPACING => {
                self.values[slot::ICON_VERTICAL_SPACING] = value.max(MIN_ICON_SPACING); return Request::Applied;
            }
            _ => {}
        }
        match slot_of_set(action) {
            Some(slot) => { self.values[slot] = value; Request::Applied }
            None => Request::Refused,
        }
    }

    /// Replace the profile faces one nonclient write carries, in profile
    /// order. A face the write does not carry keeps the one it had.
    /// # C: O(N_faces)
    pub fn set_nonclient_fonts(&mut self, faces: &[[u8; LOGFONTW_BYTES]]) {
        for (slot, face) in self.nonclient_fonts.iter_mut().zip(faces) { *slot = Some(*face); }
    }

    /// The profile face a client replaced, absent while the stock description
    /// answers. # C: O(1)
    pub fn nonclient_font(&self, index: usize) -> Option<&[u8; LOGFONTW_BYTES]> {
        self.nonclient_fonts.get(index).and_then(|face| face.as_ref())
    }

    /// The live nonclient profile: the default record the graphics owner builds
    /// from the stock description, with every dimension and face this store
    /// currently holds written over it. One record, one owner, so a client's
    /// own write of a setting is the value the next reader sees.
    /// # C: O(1), fixed record
    pub fn nonclient_profile(&self, size: u32, dpi: u32)
        -> Result<[u8; crate::win32_gdi::NONCLIENT_BYTES], crate::win32_gdi::GdiError> {
        let mut bytes = crate::win32_gdi::nonclient_defaults(size)?;
        for (index, slot) in NONCLIENT_DIMENSIONS.into_iter().enumerate() {
            let offset = NONCLIENT_DIMENSION_OFFSETS[index];
            let mut value = self.pixels(slot, dpi);
            if slot == slot::BORDER { value = value.saturating_add(self.pixels(slot::PADDED_BORDER_WIDTH, dpi)); }
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (index, offset) in NONCLIENT_FACE_OFFSETS.into_iter().enumerate() {
            let Some(face) = self.nonclient_font(index) else { continue; };
            bytes[offset..offset + LOGFONTW_BYTES].copy_from_slice(face);
        }
        Ok(bytes)
    }

    /// Replace the stored wallpaper path. # C: O(N_units)
    pub fn set_wallpaper(&mut self, path: &[u16]) -> bool {
        self.wallpaper.clear();
        if self.wallpaper.try_reserve_exact(path.len()).is_err() { return false; }
        self.wallpaper.extend_from_slice(path); true
    }
}

/// Spacing below which the reference refuses to place desktop icons.
const MIN_ICON_SPACING: i32 = 32;

/// Faces the nonclient profile carries.
pub const NONCLIENT_FACES: usize = 5;

/// Index of the menu face inside the profile's face list.
pub const NONCLIENT_MENU_FACE: usize = 2;

/// The nonclient profile's dimension words, in the order the record stores
/// them after its size field.
pub const NONCLIENT_DIMENSIONS: [usize; 9] = [slot::BORDER, slot::SCROLL_WIDTH, slot::SCROLL_HEIGHT,
    slot::CAPTION_WIDTH, slot::CAPTION_HEIGHT, slot::SM_CAPTION_WIDTH, slot::SM_CAPTION_HEIGHT,
    slot::MENU_WIDTH, slot::MENU_HEIGHT];

/// Byte offsets those dimension words sit at inside the profile record.
pub const NONCLIENT_DIMENSION_OFFSETS: [usize; 9] = [4, 8, 12, 16, 20, 116, 120, 216, 220];

/// Byte offsets the profile's faces sit at inside the record.
pub const NONCLIENT_FACE_OFFSETS: [usize; NONCLIENT_FACES] = [24, 124, 224, 316, 408];

/// The slot one reading action names. # C: O(N_entries)
pub fn slot_of_get(action: u32) -> Option<usize> {
    if action == NO_ACTION { return None; }
    ENTRIES.iter().position(|entry| entry.get == action)
}

/// The slot one writing action names. # C: O(N_entries)
pub fn slot_of_set(action: u32) -> Option<usize> {
    if action == NO_ACTION { return None; }
    ENTRIES.iter().position(|entry| entry.set == action)
}

/// One stored value in pixels. A twips value is negative and is scaled against
/// the display's dots per inch, rounded to nearest; a positive value is
/// already pixels and is scaled from the quoted profile resolution.
/// # C: O(1)
pub fn resolve(kind: Kind, value: i32, dpi: u32) -> i32 {
    let dpi = i64::from(dpi.max(1));
    match kind {
        Kind::Word => value,
        Kind::Twips if value < 0 => {
            let scaled = (-i64::from(value) * dpi + TWIPS_PER_INCH / 2) / TWIPS_PER_INCH;
            i32::try_from(scaled).unwrap_or(i32::MAX)
        }
        Kind::Twips => {
            let scaled = (i64::from(value) * dpi + i64::from(DEFAULT_DPI) / 2) / i64::from(DEFAULT_DPI);
            i32::try_from(scaled).unwrap_or(i32::MAX)
        }
    }
}

/// The pixel value one entry carries before anything writes it, at the
/// resolution the profile is quoted at. Every owner that needs a nonclient
/// dimension reads it from here, so a caller's own read of the same setting
/// and the profile it is drawn with cannot disagree. # C: O(1)
pub const fn default_pixels(slot: usize) -> i32 {
    let entry = ENTRIES[slot];
    match entry.kind {
        Kind::Word => entry.default,
        Kind::Twips if entry.default < 0 => {
            ((-(entry.default as i64) * DEFAULT_DPI as i64 + TWIPS_PER_INCH / 2) / TWIPS_PER_INCH) as i32
        }
        Kind::Twips => entry.default,
    }
}

#[cfg(test)]
#[path = "win32_sysparams/tests.rs"]
mod tests;
