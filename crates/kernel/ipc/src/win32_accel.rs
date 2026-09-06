//! Win32 accelerator tables: per-process HACCEL objects and the keystroke
//! match rule `TranslateAccelerator` applies before it sends a command.
extern crate alloc;
use alloc::vec::Vec;

pub const FVIRTKEY: u8 = 0x01;
pub const FSHIFT: u8 = 0x04;
pub const FCONTROL: u8 = 0x08;
pub const FALT: u8 = 0x10;
/// Bits the copy-out keeps; the high bit is the resource end marker.
pub const FVIRT_COPY_MASK: u8 = 0x7f;
pub const ACCEL_BYTES: usize = 6;

pub const WM_KEYDOWN: u32 = 0x0100;
pub const WM_KEYUP: u32 = 0x0101;
pub const WM_CHAR: u32 = 0x0102;
pub const WM_SYSKEYDOWN: u32 = 0x0104;
pub const WM_SYSKEYUP: u32 = 0x0105;
pub const WM_SYSCHAR: u32 = 0x0106;
const LPARAM_EXTENDED_KEY: u64 = 0x0100_0000;
const LPARAM_ALT_DOWN: u64 = 0x2000_0000;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Accel { pub virt: u8, pub key: u16, pub cmd: u16 }

impl Accel {
    /// Six-byte packed resource/API record. # C: O(1)
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < ACCEL_BYTES { return None; }
        Some(Self { virt: bytes[0], key: u16::from_le_bytes([bytes[2], bytes[3]]), cmd: u16::from_le_bytes([bytes[4], bytes[5]]) })
    }
    /// # C: O(1)
    pub fn encode(self) -> [u8; ACCEL_BYTES] {
        let key = self.key.to_le_bytes(); let cmd = self.cmd.to_le_bytes();
        [self.virt, 0, key[0], key[1], cmd[0], cmd[1]]
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AccelError { EmptyTable, NoSuchTable, NoMemory }

pub struct AcceleratorTables { next: u32, tables: Vec<(u32, Vec<Accel>)> }

impl Default for AcceleratorTables { fn default() -> Self { Self::new() } }

impl AcceleratorTables {
    /// # C: O(1)
    pub const fn new() -> Self { Self { next: 1, tables: Vec::new() } }
    /// An empty table is a parameter error, not an empty handle. # C: O(N_entries)
    pub fn create(&mut self, entries: &[Accel]) -> Result<u32, AccelError> {
        if entries.is_empty() { return Err(AccelError::EmptyTable); }
        let handle = self.next;
        self.next = self.next.checked_add(1).ok_or(AccelError::NoMemory)?;
        self.tables.push((handle, entries.to_vec()));
        Ok(handle)
    }
    /// # C: O(N_tables)
    pub fn entries(&self, handle: u32) -> Result<&[Accel], AccelError> {
        self.tables.iter().find(|(id, _)| *id == handle).map(|(_, entries)| entries.as_slice()).ok_or(AccelError::NoSuchTable)
    }
    /// Copy-out strips the end-marker bit from every flag byte. # C: O(N_entries)
    pub fn copy(&self, handle: u32, limit: usize) -> Result<Vec<Accel>, AccelError> {
        Ok(self.entries(handle)?.iter().take(limit).map(|accel| Accel { virt: accel.virt & FVIRT_COPY_MASK, ..*accel }).collect())
    }
    /// # C: O(N_tables)
    pub fn destroy(&mut self, handle: u32) -> Result<(), AccelError> {
        let index = self.tables.iter().position(|(id, _)| *id == handle).ok_or(AccelError::NoSuchTable)?;
        self.tables.swap_remove(index);
        Ok(())
    }
    /// # C: O(N_tables)
    pub fn contains(&self, handle: u32) -> bool { self.tables.iter().any(|(id, _)| *id == handle) }
}

/// Only keyboard messages can carry an accelerator. # C: O(1)
pub const fn is_accelerator_message(message: u32) -> bool {
    matches!(message, WM_KEYDOWN | WM_SYSKEYDOWN | WM_CHAR | WM_SYSCHAR)
}

/// `modifiers` holds the FSHIFT/FCONTROL/FALT bits currently held down.
/// Character accelerators match by character and ALT state only; virtual-key
/// accelerators demand the exact modifier set; plain-key entries match only
/// an ALT-held non-extended keystroke. # C: O(1)
pub const fn matches(message: u32, wparam: u64, lparam: u64, modifiers: u8, accel: Accel) -> bool {
    if wparam as u16 != accel.key { return false; }
    let virt = accel.virt & FVIRT_COPY_MASK;
    if message == WM_CHAR || message == WM_SYSCHAR {
        return virt & FVIRTKEY == 0 && (modifiers & FALT) == (virt & FALT);
    }
    if virt & FVIRTKEY != 0 { return modifiers == virt & (FSHIFT | FCONTROL | FALT); }
    lparam & LPARAM_EXTENDED_KEY == 0 && virt & FALT != 0 && lparam & LPARAM_ALT_DOWN != 0
}

/// First matching entry, in table order. # C: O(N_entries)
pub fn find(message: u32, wparam: u64, lparam: u64, modifiers: u8, entries: &[Accel]) -> Option<Accel> {
    entries.iter().copied().find(|accel| matches(message, wparam, lparam, modifiers, *accel))
}

#[cfg(test)]
#[path = "win32_accel/tests.rs"]
mod tests;
