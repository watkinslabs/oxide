// Byte layout of the hardware-debug regset buffer (`user_hwdebug_state`).
//
// One owner of the offset arithmetic: the ptrace regset shim reads and writes
// through these helpers and never computes an offset itself (`07§5`).
//
// Layout: a `u32` info word, a `u32` pad, then a fixed sixteen entries of
// `{ u64 addr; u32 ctrl; u32 pad; }`. The buffer is sized by the ARCHITECTURAL
// slot ceiling, not by the implemented count — the implemented count is
// reported inside the info word instead.

use super::idreg::{ARM_MAX_BRP, ARM_MAX_WRP};

/// Entries the regset buffer always carries, whatever the machine implements.
pub const REGSET_SLOTS: usize = if ARM_MAX_BRP > ARM_MAX_WRP { ARM_MAX_BRP } else { ARM_MAX_WRP };

/// Offset of the `dbg_info` word.
pub const DBG_INFO_OFF: usize = 0;
/// Offset of the header pad word.
pub const HDR_PAD_OFF: usize = 4;
/// Offset of the first `(addr, ctrl, pad)` entry — the header size.
pub const DBG_REGS_OFF: usize = 8;
/// Offset of `addr` within one entry.
pub const SLOT_ADDR_OFF: usize = 0;
/// Offset of `ctrl` within one entry.
pub const SLOT_CTRL_OFF: usize = 8;
/// Offset of the per-entry pad.
pub const SLOT_PAD_OFF: usize = 12;
/// Bytes one `(addr, ctrl, pad)` entry occupies.
pub const SLOT_BYTES: usize = 16;
/// Total bytes of the regset buffer.
pub const STATE_BYTES: usize = DBG_REGS_OFF + REGSET_SLOTS * SLOT_BYTES;
/// Granule the regset reports registers in.
pub const REGSET_GRANULE: usize = 4;
/// Register count the regset advertises — the buffer measured in granules.
pub const REGSET_N: usize = STATE_BYTES / REGSET_GRANULE;

/// Byte offset of entry `idx`'s `addr`.
/// # C: O(1)
pub const fn slot_addr_off(idx: usize) -> usize { DBG_REGS_OFF + idx * SLOT_BYTES + SLOT_ADDR_OFF }

/// Byte offset of entry `idx`'s `ctrl`.
/// # C: O(1)
pub const fn slot_ctrl_off(idx: usize) -> usize { DBG_REGS_OFF + idx * SLOT_BYTES + SLOT_CTRL_OFF }

/// Byte offset of entry `idx`'s pad.
/// # C: O(1)
pub const fn slot_pad_off(idx: usize) -> usize { DBG_REGS_OFF + idx * SLOT_BYTES + SLOT_PAD_OFF }

/// Entry index a byte offset falls in, or `None` for the header and for any
/// offset past the last entry.
/// # C: O(1)
pub const fn slot_of_off(off: usize) -> Option<usize> {
    if off < DBG_REGS_OFF || off >= STATE_BYTES { return None; }
    Some((off - DBG_REGS_OFF) / SLOT_BYTES)
}

/// Write the info word and zero the header pad.
/// # C: O(1)
pub fn put_header(buf: &mut [u8], dbg_info: u32) -> bool {
    if buf.len() < DBG_REGS_OFF { return false; }
    buf[DBG_INFO_OFF..DBG_INFO_OFF + 4].copy_from_slice(&dbg_info.to_ne_bytes());
    buf[HDR_PAD_OFF..HDR_PAD_OFF + 4].copy_from_slice(&0u32.to_ne_bytes());
    true
}

/// Read the info word.
/// # C: O(1)
pub fn get_header(buf: &[u8]) -> Option<u32> {
    if buf.len() < DBG_REGS_OFF { return None; }
    let mut w = [0u8; 4];
    w.copy_from_slice(&buf[DBG_INFO_OFF..DBG_INFO_OFF + 4]);
    Some(u32::from_ne_bytes(w))
}

/// Write entry `idx`, zeroing its pad. False when the buffer is short or the
/// index is past the architectural ceiling.
/// # C: O(1)
pub fn put_slot(buf: &mut [u8], idx: usize, addr: u64, ctrl: u32) -> bool {
    if idx >= REGSET_SLOTS { return false; }
    let a = slot_addr_off(idx);
    if buf.len() < a + SLOT_BYTES { return false; }
    buf[a..a + 8].copy_from_slice(&addr.to_ne_bytes());
    buf[a + SLOT_CTRL_OFF..a + SLOT_CTRL_OFF + 4].copy_from_slice(&ctrl.to_ne_bytes());
    buf[a + SLOT_PAD_OFF..a + SLOT_PAD_OFF + 4].copy_from_slice(&0u32.to_ne_bytes());
    true
}

/// Read entry `idx` as `(addr, ctrl)`.
/// # C: O(1)
pub fn get_slot(buf: &[u8], idx: usize) -> Option<(u64, u32)> {
    if idx >= REGSET_SLOTS { return None; }
    let a = slot_addr_off(idx);
    if buf.len() < a + SLOT_BYTES { return None; }
    let mut w8 = [0u8; 8];
    w8.copy_from_slice(&buf[a..a + 8]);
    let mut w4 = [0u8; 4];
    w4.copy_from_slice(&buf[a + SLOT_CTRL_OFF..a + SLOT_CTRL_OFF + 4]);
    Some((u64::from_ne_bytes(w8), u32::from_ne_bytes(w4)))
}
