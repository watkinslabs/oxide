//! Desktop hot keys: one (modifier set, virtual key) claim per desktop, keyed
//! back to the registering thread, window and id.

use alloc::vec::Vec;
use super::{WindowError, WindowId, WindowManager};

/// Modifier bits a registration matches on. Bits outside this set take part in
/// the stored flags but never in the duplicate test.
pub const MOD_ALT: u32 = 0x0001;
pub const MOD_CONTROL: u32 = 0x0002;
pub const MOD_SHIFT: u32 = 0x0004;
pub const MOD_WIN: u32 = 0x0008;
const MODIFIER_FLAGS: u32 = MOD_ALT | MOD_CONTROL | MOD_SHIFT | MOD_WIN;
const MAX_HOTKEYS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hotkey { pub tid: u64, pub window: Option<WindowId>, pub id: i32, pub flags: u32, pub vkey: u32 }

/// Why a hot-key registration was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HotkeyError {
    /// The named window belongs to another thread.
    OtherThread,
    /// The named window handle does not resolve.
    NoSuchWindow,
    /// Another registration already claims this modifier and key combination.
    AlreadyRegistered,
    /// No registration matches this thread, window and id.
    NotRegistered,
    NoMemory,
}

/// Registered hot keys for one desktop.
#[derive(Default)]
pub struct Hotkeys { entries: Vec<Hotkey> }

impl Hotkeys {
    /// # C: O(1)
    pub const fn new() -> Self { Self { entries: Vec::new() } }

    /// Claim one combination. A repeat registration by the same thread, window
    /// and id replaces the stored flags and key and reports the replaced entry;
    /// a different owner claiming the same combination is refused.
    /// # C: O(N_hotkeys)
    pub fn register(&mut self, key: Hotkey) -> Result<Option<Hotkey>, HotkeyError> {
        let mut replaced = None;
        for entry in &self.entries {
            if entry.vkey == key.vkey && entry.flags & MODIFIER_FLAGS == key.flags & MODIFIER_FLAGS {
                return Err(HotkeyError::AlreadyRegistered);
            }
            if entry.tid == key.tid && entry.window == key.window && entry.id == key.id { replaced = Some(*entry); }
        }
        if let Some(previous) = replaced {
            let slot = self.entries.iter_mut().find(|entry| **entry == previous).ok_or(HotkeyError::NotRegistered)?;
            slot.flags = key.flags; slot.vkey = key.vkey;
            return Ok(Some(previous));
        }
        if self.entries.len() >= MAX_HOTKEYS { return Err(HotkeyError::NoMemory); }
        self.entries.try_reserve(1).map_err(|_| HotkeyError::NoMemory)?;
        self.entries.push(key);
        Ok(None)
    }

    /// Release the registration matching this thread, window and id, answering
    /// the modifiers and key it held. # C: O(N_hotkeys)
    pub fn unregister(&mut self, tid: u64, window: Option<WindowId>, id: i32) -> Result<Hotkey, HotkeyError> {
        let index = self.entries.iter().position(|entry| entry.tid == tid && entry.window == window && entry.id == id)
            .ok_or(HotkeyError::NotRegistered)?;
        Ok(self.entries.remove(index))
    }

    /// # C: O(N_hotkeys)
    pub fn len(&self) -> usize { self.entries.len() }
    /// # C: O(N_hotkeys)
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
}

impl WindowManager {
    /// Register one hot key for the calling thread. A named window must belong
    /// to that thread. # C: O(N_windows + N_hotkeys)
    pub fn register_hotkey(&mut self, tid: u64, hwnd: Option<WindowId>, id: i32, flags: u32, vkey: u32)
        -> Result<Option<Hotkey>, HotkeyError> {
        if let Some(window) = hwnd {
            let record = self.get(window).ok_or(HotkeyError::NoSuchWindow)?;
            if record.owner_tid != tid { return Err(HotkeyError::OtherThread); }
        }
        self.hotkeys.register(Hotkey { tid, window: hwnd, id, flags, vkey })
    }

    /// # C: O(N_windows + N_hotkeys)
    pub fn unregister_hotkey(&mut self, tid: u64, hwnd: Option<WindowId>, id: i32) -> Result<Hotkey, HotkeyError> {
        if let Some(window) = hwnd {
            let record = self.get(window).ok_or(HotkeyError::NoSuchWindow)?;
            if record.owner_tid != tid { return Err(HotkeyError::OtherThread); }
        }
        self.hotkeys.unregister(tid, hwnd, id)
    }
}

/// Map the window-owner refusals onto the shared window error. # C: O(1)
pub const fn window_error(error: HotkeyError) -> WindowError {
    match error {
        HotkeyError::NoSuchWindow => WindowError::NoSuchWindow,
        HotkeyError::OtherThread => WindowError::WrongThread,
        HotkeyError::NoMemory => WindowError::NoMemory,
        _ => WindowError::InvalidParent,
    }
}

#[cfg(test)]
#[path = "tests/hotkey.rs"]
mod tests;
