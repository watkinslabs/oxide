//! Owned per-window extra bytes and pointer-width scalar properties.
use alloc::vec::Vec;
use super::{WindowId, WindowManager, WindowRecord};

pub const MAX_WINDOW_EXTRA: usize = 4096;
pub const GWLP_WNDPROC: i32 = -4;
pub const GWLP_HINSTANCE: i32 = -6;
pub const GWLP_HWNDPARENT: i32 = -8;
pub const GWLP_ID: i32 = -12;
pub const GWL_STYLE: i32 = -16;
pub const GWL_EXSTYLE: i32 = -20;
pub const GWLP_USERDATA: i32 = -21;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LongPtrError { InvalidWindow, InvalidIndex, InvalidSize, NoMemory, OwnerTransaction }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowExtra { bytes: Vec<u8>, pub userdata: u64, pub instance: u64 }

impl WindowExtra {
    /// Admit signed class size and allocate zeroed private bytes before HWND publication.
    /// # C: O(size)
    pub fn new(size: i32, instance: u64) -> Result<Self, LongPtrError> {
        let size = usize::try_from(size).ok().filter(|size| *size <= MAX_WINDOW_EXTRA).ok_or(LongPtrError::InvalidSize)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size).map_err(|_| LongPtrError::NoMemory)?;
        bytes.resize(size, 0);
        Ok(Self { bytes, userdata: 0, instance })
    }
    /// Return declared per-window storage extent, not vector capacity. # C: O(1)
    pub fn len(&self) -> usize { self.bytes.len() }
    /// Read a byte-indexed, possibly unaligned WORD/DWORD/pointer slot. # C: O(1)
    pub fn read(&self, offset: i32, width: usize) -> Result<u64, LongPtrError> {
        let range = self.range(offset, width)?;
        let mut value = [0u8; 8];
        value[..width].copy_from_slice(&self.bytes[range]);
        Ok(u64::from_le_bytes(value))
    }
    /// Return old bytes and replace exactly the admitted range. # C: O(1)
    pub fn write(&mut self, offset: i32, width: usize, value: u64) -> Result<u64, LongPtrError> {
        let range = self.range(offset, width)?;
        let previous = self.read(offset, width)?;
        self.bytes[range].copy_from_slice(&value.to_le_bytes()[..width]);
        Ok(previous)
    }
    fn range(&self, offset: i32, width: usize) -> Result<core::ops::Range<usize>, LongPtrError> {
        if !matches!(width, 2 | 4 | 8) { return Err(LongPtrError::InvalidSize); }
        let start = usize::try_from(offset).map_err(|_| LongPtrError::InvalidIndex)?;
        let end = start.checked_add(width).filter(|end| *end <= self.bytes.len()).ok_or(LongPtrError::InvalidIndex)?;
        Ok(start..end)
    }
}

/// Metadata and extra storage share the canonical window vector's lifetime.
#[derive(Debug)]
pub struct OwnedWindow { pub record: WindowRecord, pub extra: WindowExtra, pub(super) properties: super::WindowProperties, pub(super) scroll: [super::ScrollState; 2] }
impl OwnedWindow {
    /// Prepare the entire entry before the canonical vector publishes it. # C: O(extra_size)
    pub fn new(record: WindowRecord, extra_size: i32, instance: u64) -> Result<Self, LongPtrError> {
        Ok(Self { record, extra: WindowExtra::new(extra_size, instance)?, properties: super::WindowProperties::new(), scroll: [super::ScrollState::new(); 2] })
    }
}
impl core::ops::Deref for OwnedWindow {
    type Target = WindowRecord;
    fn deref(&self) -> &WindowRecord { &self.record }
}
impl core::ops::DerefMut for OwnedWindow {
    fn deref_mut(&mut self) -> &mut WindowRecord { &mut self.record }
}

impl WindowManager {
    /// Commit the replacement procedure and its encoding in one owner mutation. # C: O(N_windows)
    pub fn set_window_long_with_encoding(&mut self, window: WindowId, offset: i32, width: usize,
        value: u64, unicode: bool) -> Result<u64, LongPtrError> {
        let previous = self.set_window_long(window, offset, width, value)?;
        let nonzero = if width == 4 { value as u32 != 0 } else { value != 0 };
        if offset == GWLP_WNDPROC && nonzero {
            let entry = &mut self.windows.iter_mut().find(|(id, _)| *id == window).ok_or(LongPtrError::InvalidWindow)?.1;
            entry.unicode = unicode;
        }
        Ok(previous)
    }
    /// Query canonical scalar state without copying the owned extra buffer. # C: O(N_windows)
    pub fn get_window_long_ptr(&self, window: WindowId, offset: i32) -> Result<u64, LongPtrError> {
        self.get_window_long(window, offset, 8)
    }
    /// Width describes extra-byte access and truncates scalar query results. # C: O(N_windows)
    pub fn get_window_long(&self, window: WindowId, offset: i32, width: usize) -> Result<u64, LongPtrError> {
        let entry = &self.windows.iter().find(|(id, _)| *id == window).ok_or(LongPtrError::InvalidWindow)?.1;
        let mask = width_mask(width)?;
        if width == 2 && offset < 0 && offset != GWLP_USERDATA { return Err(LongPtrError::InvalidIndex); }
        let value = match offset {
            GWLP_USERDATA => Ok(entry.extra.userdata),
            GWLP_HINSTANCE => Ok(entry.extra.instance),
            GWLP_WNDPROC => Ok(entry.record.wndproc),
            GWL_STYLE => Ok(entry.record.style as u64),
            GWL_EXSTYLE => Ok(entry.record.ex_style as u64),
            GWLP_HWNDPARENT => Ok(entry.record.parent.or(entry.record.owner).map_or(0, |id| id.raw() as u64)),
            GWLP_ID => Ok(entry.record.id_menu),
            value if value >= 0 => entry.extra.read(value, width),
            _ => Err(LongPtrError::InvalidIndex),
        }?;
        Ok(value & mask)
    }
    /// Update local scalar state; callback-capable mutations require their owning transaction.
    /// WNDPROC values must already have passed the caller's A/W procedure resolution.
    /// # C: O(N_windows)
    pub fn set_window_long_ptr(&mut self, window: WindowId, offset: i32, value: u64) -> Result<u64, LongPtrError> {
        self.set_window_long(window, offset, 8, value)
    }
    /// Width-limited writes preserve unrelated bytes; style/parent changes need owner work.
    /// # C: O(N_windows)
    pub fn set_window_long(&mut self, window: WindowId, offset: i32, width: usize, value: u64) -> Result<u64, LongPtrError> {
        let entry = &mut self.windows.iter_mut().find(|(id, _)| *id == window).ok_or(LongPtrError::InvalidWindow)?.1;
        let mask = width_mask(width)?;
        let value = if width == 4 { value as u32 as i32 as i64 as u64 } else { value & mask };
        if width == 2 && offset < 0 && offset != GWLP_USERDATA { return Err(LongPtrError::InvalidIndex); }
        let slot = match offset {
            GWLP_USERDATA => &mut entry.extra.userdata,
            GWLP_HINSTANCE => &mut entry.extra.instance,
            GWLP_WNDPROC => &mut entry.record.wndproc,
            GWLP_ID => &mut entry.record.id_menu,
            GWLP_HWNDPARENT | GWL_STYLE | GWL_EXSTYLE => return Err(LongPtrError::OwnerTransaction),
            index if index >= 0 => return entry.extra.write(index, width, value),
            _ => return Err(LongPtrError::InvalidIndex),
        };
        let previous = *slot;
        if offset != GWLP_WNDPROC || value != 0 {
            *slot = match width {
                2 => (previous & 0xffff_0000) | (value & mask),
                4 => value as u32 as i32 as i64 as u64,
                _ => value,
            };
        }
        Ok(previous & mask)
    }
}

fn width_mask(width: usize) -> Result<u64, LongPtrError> {
    match width { 2 => Ok(u16::MAX as u64), 4 => Ok(u32::MAX as u64), 8 => Ok(u64::MAX), _ => Err(LongPtrError::InvalidSize) }
}

#[cfg(test)]
#[path = "tests/extra.rs"]
mod tests;
