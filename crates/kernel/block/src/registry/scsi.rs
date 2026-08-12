//! Shared SCSI disk-name reservation.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use sync::{Devices as DevicesClass, Spinlock};

static NAMES: Spinlock<Vec<bool>, DevicesClass> = Spinlock::new(Vec::new());

/// A reserved SCSI disk identity. Keeping this token alive reserves its
/// Linux-style `sd*` name; dropping it makes the index reusable. # C: O(1)
pub struct ScsiDiskName { index: usize, name: String }

impl ScsiDiskName {
    /// Text form of the reserved SCSI disk name. # C: O(1)
    pub fn as_str(&self) -> &str { &self.name }
}

impl Drop for ScsiDiskName {
    fn drop(&mut self) {
        let mut names = NAMES.lock();
        if let Some(used) = names.get_mut(self.index) { *used = false; }
    }
}

/// Reserve one reusable Linux-style SCSI disk name (`sda`, `sdb`, …). # C: O(N_names)
pub fn reserve_scsi_disk_name() -> Option<ScsiDiskName> {
    let index = {
        let mut names = NAMES.lock();
        match names.iter().position(|used| !*used) {
            Some(index) => { names[index] = true; index }
            None => { names.push(true); names.len().checked_sub(1)? }
        }
    };
    let mut suffix = Vec::new();
    let mut n = index.checked_add(1)?;
    while n != 0 {
        n -= 1;
        suffix.push(b'a'.checked_add((n % 26) as u8)?);
        n /= 26;
    }
    let mut name = String::from("sd");
    while let Some(letter) = suffix.pop() { name.push(letter as char); }
    Some(ScsiDiskName { index, name })
}
