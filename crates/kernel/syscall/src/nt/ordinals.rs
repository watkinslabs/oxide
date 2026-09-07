//! Translating a shipped module's raw system-service ordinal into the tagged
//! service word the NT entry admits.
//!
//! A shipped service stub loads a bare 32-bit ordinal and issues the
//! architectural syscall instruction. The word is not a Linux syscall number
//! and carries no namespace tag: its low twelve bits are the service number
//! within a service table, and the two bits above them name the table. Table
//! zero is the runtime's own service set; the next table up is the window
//! surface, which already has its own raw route.
//!
//! Ordinals are fixed when the module is built, so the numbering is decoded
//! from the module the guest runs and installed here at load time rather than
//! transcribed. Nothing is admitted until a module has been decoded: an
//! ordinal that reaches an empty table is not a service this kernel knows, and
//! must never be allowed to mean a Linux syscall of the same number.

use core::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use super::{NtCall, NtService, decode};
use crate::SyscallArgs;

/// Service numbers one table can hold: the width of the ordinal's number field.
pub const TABLE_SLOTS: usize = 0x1000;
/// Tables the ordinal word can name.
pub const TABLE_COUNT: u32 = 4;
/// The table the runtime's own services occupy.
pub const RUNTIME_TABLE: u32 = 0;
/// Empty slot marker. Slots hold the service selector biased by one so that a
/// zero-valued selector is still distinguishable from an unfilled slot.
const EMPTY: u16 = 0;

/// Table a raw ordinal word names. # C: O(1)
pub const fn table_of(id: u32) -> u32 { (id >> 12) & (TABLE_COUNT - 1) }

/// Service number a raw ordinal word carries. # C: O(1)
pub const fn number_of(id: u32) -> u32 { id & (TABLE_SLOTS as u32 - 1) }

/// The service number a raw ordinal names in the runtime table, or `None` when
/// the word names another table. # C: O(1)
pub const fn runtime_number(id: u32) -> Option<u32> {
    if table_of(id) != RUNTIME_TABLE { return None; }
    Some(number_of(id))
}

/// Slot encoding for one service selector. # C: O(1)
pub const fn slot_for(service: NtService) -> u16 { (service as u16) + 1 }

/// Selector a slot value carries, or `None` for an unfilled slot. # C: O(1)
pub const fn selector_of(slot: u16) -> Option<u32> {
    if slot == EMPTY { return None; }
    Some((slot - 1) as u32)
}

#[allow(clippy::declare_interior_mutable_const)]
const UNFILLED: AtomicU16 = AtomicU16::new(EMPTY);
static SLOTS: [AtomicU16; TABLE_SLOTS] = [UNFILLED; TABLE_SLOTS];
static FILLED: AtomicUsize = AtomicUsize::new(0);
static INSTALLED: AtomicBool = AtomicBool::new(false);

/// Whether a module's numbering has been installed. Until it has, no raw
/// ordinal may be claimed. # C: O(1)
pub fn installed() -> bool { INSTALLED.load(Ordering::Acquire) }

/// How many service numbers the installed table answers. # C: O(1)
pub fn filled() -> usize { FILLED.load(Ordering::Acquire) }

/// Install the decoded numbering. Ordinals outside the runtime table, and
/// names the kernel publishes no service for, are not this table's business
/// and are counted as skipped by the caller. Returns the number of slots the
/// table now answers.
/// # C: O(entries)
pub fn install(entries: impl Iterator<Item = (u32, NtService)>) -> usize {
    let mut filled = 0usize;
    for (id, service) in entries {
        let Some(number) = runtime_number(id) else { continue; };
        let slot = &SLOTS[number as usize];
        if slot.swap(slot_for(service), Ordering::Release) == EMPTY { filled += 1; }
    }
    FILLED.store(filled, Ordering::Release);
    INSTALLED.store(true, Ordering::Release);
    filled
}

/// Forget the installed numbering. # C: O(TABLE_SLOTS)
pub fn clear() {
    for slot in SLOTS.iter() { slot.store(EMPTY, Ordering::Release); }
    FILLED.store(0, Ordering::Release);
    INSTALLED.store(false, Ordering::Release);
}

/// The tagged NT call a raw ordinal names, or `None` when the word names no
/// service in the runtime table. An uninstalled table holds no slots, so it
/// answers nothing; the install flag is not re-tested here.
/// # C: O(1)
pub fn call_for_ordinal(id: u32, args: SyscallArgs) -> Option<NtCall> {
    let number = runtime_number(id)?;
    let selector = selector_of(SLOTS[number as usize].load(Ordering::Acquire))?;
    decode(selector, args)
}

/// Whether a raw ordinal belongs to the runtime table at all, installed or
/// not. A word that does must never reach the Linux syscall tables.
/// # C: O(1)
pub fn is_runtime_ordinal(id: u32) -> bool { installed() && runtime_number(id).is_some() }

#[cfg(test)]
#[path = "ordinals/tests.rs"]
mod tests;
