//! The read-only shared page every NT process maps at a fixed address.
//!
//! The page is built here, ungated, because one byte in it decides how every
//! system-service stub in a stock PE `ntdll` reaches the kernel. Each stub
//! copies its first argument register, loads its service ordinal, tests bit 0
//! of the `SystemCall` field, and then either executes the architecture's
//! syscall instruction or calls an indirect user-mode dispatcher. A host that
//! cannot own the syscall instruction sets the bit; this kernel owns it, so
//! the field stays clear and stock stubs take the architectural entry.
//!
//! Building the bytes in a module that compiles off-target is what makes that
//! decision testable: the mapping call is target-gated, and a test written
//! beside it would never be compiled.

use alloc::{vec, vec::Vec};
use pe::Error;

use super::processor_features::{self, PROCESSOR_FEATURE_MAX};

/// Fixed user-mode address of the shared page.
pub const USER_SHARED_DATA_BASE: u64 = 0x7ffe_0000;
/// The page is exactly one 4 KiB frame; the layout below is defined within it.
pub const USER_SHARED_DATA_BYTES: usize = 0x1000;

/// Field offsets within the page, by the published layout.
const NT_SYSTEM_ROOT_OFF: usize = 0x030;
const NT_BUILD_NUMBER_OFF: usize = 0x260;
const NT_MAJOR_VERSION_OFF: usize = 0x26c;
const NT_MINOR_VERSION_OFF: usize = 0x270;
/// One byte per feature slot; an image indexes this array directly.
const PROCESSOR_FEATURES_OFF: usize = 0x274;
/// Bit 0 selects the user-mode dispatcher over the syscall instruction.
pub const SYSTEM_CALL_OFF: usize = 0x308;
/// The value that keeps stock service stubs on the architectural entry.
pub const SYSTEM_CALL_ARCHITECTURAL: u32 = 0;
/// Absolute address of the flag byte, as a stub encodes it.
pub const SYSTEM_CALL_ADDRESS: u64 = USER_SHARED_DATA_BASE + SYSTEM_CALL_OFF as u64;

const NT_SYSTEM_ROOT: &str = "C:\\Windows";
const NT_BUILD_NUMBER: u32 = 0x0a00_0000;
const NT_MAJOR_VERSION: u32 = 10;
const NT_MINOR_VERSION: u32 = 0;

fn put_u16(b: &mut [u8], o: usize, v: u16) { b[o..o + 2].copy_from_slice(&v.to_le_bytes()); }
fn put_u32(b: &mut [u8], o: usize, v: u32) { b[o..o + 4].copy_from_slice(&v.to_le_bytes()); }

/// Build the page image the process maps read-only.
/// # C: O(page bytes)
pub fn page_bytes() -> Result<Vec<u8>, Error> {
    if NT_SYSTEM_ROOT.contains('\0') { return Err(Error::Einval); }
    let mut page = vec![0u8; USER_SHARED_DATA_BYTES];
    let mut off = NT_SYSTEM_ROOT_OFF;
    for unit in NT_SYSTEM_ROOT.encode_utf16() { put_u16(&mut page, off, unit); off += 2; }
    put_u32(&mut page, NT_BUILD_NUMBER_OFF, NT_BUILD_NUMBER);
    put_u32(&mut page, NT_MAJOR_VERSION_OFF, NT_MAJOR_VERSION);
    put_u32(&mut page, NT_MINOR_VERSION_OFF, NT_MINOR_VERSION);
    put_u32(&mut page, SYSTEM_CALL_OFF, SYSTEM_CALL_ARCHITECTURAL);
    page[PROCESSOR_FEATURES_OFF..PROCESSOR_FEATURES_OFF + PROCESSOR_FEATURE_MAX]
        .copy_from_slice(&processor_features::local());
    Ok(page)
}

#[cfg(test)]
#[path = "tests/user_shared_data.rs"]
mod tests;
