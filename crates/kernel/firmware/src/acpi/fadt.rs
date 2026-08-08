// FADT (`FACP`) decode + the reset-register decision it exists to answer.
//
// The parse is a pure byte-slice function so the offsets, the version
// gating and the reset-register admission ladder are all hosted-testable;
// `decode_fadt` is the thin unsafe shim that copies the firmware table out
// of the HHDM and publishes the derived action. Only what a consumer reads
// is published — a stored-but-unconsumed register block is the defect class
// this project bans, so the pm/sleep blocks stay in the parsed value and
// nothing latches them until a caller exists.

use crate::acpi::log::{alog_dec, alog_hex, alog_raw};
use crate::acpi::read::read_u32_le;

/// Generic Address Structure: the 12-byte descriptor ACPI uses wherever a
/// register may live in port, MMIO or PCI-config space.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Gas {
    pub space_id: u8,
    pub bit_width: u8,
    pub bit_offset: u8,
    pub access_width: u8,
    pub address: u64,
}

/// Address-space ids a reset register is permitted to name.
pub const SPACE_SYSTEM_MEMORY: u8 = 0;
pub const SPACE_SYSTEM_IO: u8 = 1;
pub const SPACE_PCI_CONFIG: u8 = 2;

/// FADT flag bit 10: the RESET_REG field is meaningful.
pub const FADT_RESET_REGISTER: u32 = 1 << 10;

/// Smallest FADT that carries `flags` — anything shorter predates the
/// reset register entirely.
pub const FADT_V1_LEN: usize = 116;
/// Smallest FADT that carries `reset_register` + `reset_value`.
pub const FADT_V2_LEN: usize = 132;

// Field offsets. The table is packed, so these are byte positions, not
// naturally-aligned ones (`boot_flags` at 109 is the tell).
const OFF_REVISION: usize = 8;
const OFF_DSDT32: usize = 40;
const OFF_FLAGS: usize = 112;
const OFF_RESET_REG: usize = 116;
const OFF_RESET_VALUE: usize = 128;
const OFF_XDSDT: usize = 140;
const OFF_XPM1A_CNT: usize = 172;
const OFF_XPM1B_CNT: usize = 184;
const OFF_SLEEP_CONTROL: usize = 244;
const OFF_SLEEP_STATUS: usize = 256;
const OFF_PM1A_CNT32: usize = 64;
const OFF_PM1B_CNT32: usize = 68;
const OFF_PM1_CNT_LEN: usize = 89;
const GAS_LEN: usize = 12;

/// Parsed FADT. `revision` is the table header's, which is what gates the
/// reset register — the reference reads the header revision, not a minor one.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Fadt {
    pub revision: u8,
    pub flags: u32,
    pub reset_register: Gas,
    pub reset_value: u8,
    pub dsdt_pa: u64,
    pub pm1a_control: Gas,
    pub pm1b_control: Gas,
    pub sleep_control: Gas,
    pub sleep_status: Gas,
}

/// What a reset through the FADT register costs the caller.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ResetAction {
    /// Write `value` as a byte to x86 I/O port `port`.
    PortIo { port: u16, value: u8 },
    /// Write `value` as a byte to physical address `pa`.
    Mmio { pa: u64, value: u8 },
    /// Write `value` to bus-0 PCI config space at device/function/offset.
    PciConfig { device: u8, function: u8, offset: u16, value: u8 },
}

/// Decode a GAS at `off`. Returns the default (all-zero, space 0) when the
/// table is too short to carry it, which reads as "absent" everywhere.
fn gas_at(t: &[u8], off: usize) -> Gas {
    if t.len() < off + GAS_LEN { return Gas::default(); }
    let mut address = 0u64;
    let mut i = 0usize;
    while i < 8 { address |= (t[off + 4 + i] as u64) << (i * 8); i += 1; }
    Gas { space_id: t[off], bit_width: t[off + 1], bit_offset: t[off + 2], access_width: t[off + 3], address }
}

fn u32_at(t: &[u8], off: usize) -> u32 {
    if t.len() < off + 4 { return 0; }
    (t[off] as u32) | ((t[off + 1] as u32) << 8) | ((t[off + 2] as u32) << 16) | ((t[off + 3] as u32) << 24)
}

fn u64_at(t: &[u8], off: usize) -> u64 {
    if t.len() < off + 8 { return 0; }
    let mut v = 0u64;
    let mut i = 0usize;
    while i < 8 { v |= (t[off + i] as u64) << (i * 8); i += 1; }
    v
}

/// Parse a FADT body. `None` when the table is too short to carry the
/// version-1 fields, which is the only length the reference trusts the
/// header revision about.
///
/// # C: O(1)
pub fn parse_fadt(t: &[u8]) -> Option<Fadt> {
    if t.len() < FADT_V1_LEN { return None; }
    // 64-bit DSDT pointer wins when present and non-zero; the reference
    // falls back to the 32-bit field, which is all a version-1 table has.
    let x = u64_at(t, OFF_XDSDT);
    let dsdt_pa = if x != 0 { x } else { u32_at(t, OFF_DSDT32) as u64 };
    // Extended PM1 control blocks likewise supersede the 32-bit ports.
    let xa = gas_at(t, OFF_XPM1A_CNT);
    let xb = gas_at(t, OFF_XPM1B_CNT);
    let len32 = if t.len() > OFF_PM1_CNT_LEN { t[OFF_PM1_CNT_LEN] } else { 0 };
    let pm1a_control = if xa.address != 0 { xa } else { port_gas(u32_at(t, OFF_PM1A_CNT32) as u64, len32) };
    let pm1b_control = if xb.address != 0 { xb } else { port_gas(u32_at(t, OFF_PM1B_CNT32) as u64, len32) };
    Some(Fadt {
        revision: t[OFF_REVISION],
        flags: u32_at(t, OFF_FLAGS),
        reset_register: gas_at(t, OFF_RESET_REG),
        reset_value: if t.len() > OFF_RESET_VALUE { t[OFF_RESET_VALUE] } else { 0 },
        dsdt_pa,
        pm1a_control,
        pm1b_control,
        sleep_control: gas_at(t, OFF_SLEEP_CONTROL),
        sleep_status: gas_at(t, OFF_SLEEP_STATUS),
    })
}

/// Synthesise a port-space GAS for a legacy 32-bit PM block address.
fn port_gas(address: u64, byte_len: u8) -> Gas {
    if address == 0 { return Gas::default(); }
    Gas { space_id: SPACE_SYSTEM_IO, bit_width: byte_len.saturating_mul(8), bit_offset: 0, access_width: 0, address }
}

/// The reset-register admission ladder.
///
/// Three gates, in the reference's order: the reset register was introduced
/// with table revision 2, the flag bit must claim it, and the register must
/// name port, memory or bus-0 PCI-config space. The declared bit width and
/// offset are deliberately NOT consulted — firmware fills them wrongly often
/// enough that the reference ignores them too, and a kernel that honoured
/// them would refuse resets that hardware performs.
///
/// # C: O(1)
pub fn reset_action(f: &Fadt) -> Option<ResetAction> {
    if f.revision < 2 { return None; }
    if f.flags & FADT_RESET_REGISTER == 0 { return None; }
    let rr = f.reset_register;
    match rr.space_id {
        SPACE_SYSTEM_IO => {
            if rr.address == 0 || rr.address > u16::MAX as u64 { return None; }
            Some(ResetAction::PortIo { port: rr.address as u16, value: f.reset_value })
        }
        SPACE_SYSTEM_MEMORY => {
            if rr.address == 0 { return None; }
            Some(ResetAction::Mmio { pa: rr.address, value: f.reset_value })
        }
        SPACE_PCI_CONFIG => {
            let device = ((rr.address >> 32) & 0xffff) as u16;
            let function = ((rr.address >> 16) & 0xffff) as u16;
            let offset = (rr.address & 0xffff) as u16;
            if device > 31 || function > 7 { return None; }
            Some(ResetAction::PciConfig { device: device as u8, function: function as u8, offset, value: f.reset_value })
        }
        _ => None,
    }
}

/// Copy the firmware FADT out of the HHDM, parse it, and publish the
/// derived reset action for the power subsystem.
///
/// # SAFETY: caller asserts `pa` is an XSDT-listed `FACP` table whose
/// declared length is readable at `hhdm_offset + pa`, per the same
/// bootloader-owned-ACPI-memory contract the rest of this walk relies on.
/// # C: O(1)
/// # Ctx: pre-init, single-CPU
pub unsafe fn decode_fadt(pa: u64, hhdm_offset: u64) {
    let p = (hhdm_offset.wrapping_add(pa)) as *const u8;
    // SAFETY: every XSDT entry points at an SDT with a ≥36-byte header; offset 4..8 is the declared length.
    let length = unsafe { read_u32_le(p.add(4)) } as usize;
    if length < FADT_V1_LEN || length > 4096 {
        alog_raw(b"[ERROR] fadt: implausible length\n");
        return;
    }
    let mut buf = [0u8; 512];
    let n = if length > buf.len() { buf.len() } else { length };
    let mut i = 0usize;
    while i < n {
        // SAFETY: i < n <= the table's own declared length, which the caller asserts is readable.
        buf[i] = unsafe { core::ptr::read_volatile(p.add(i)) };
        i += 1;
    }
    let Some(f) = parse_fadt(&buf[..n]) else {
        alog_raw(b"[ERROR] fadt: short table\n");
        return;
    };
    alog_raw(b"[INFO]  fadt: revision=");
    alog_dec(f.revision as u64);
    alog_raw(b" flags=");
    alog_hex(f.flags as u64);
    alog_raw(b" dsdt=");
    alog_hex(f.dsdt_pa);
    alog_raw(b"\n");
    match reset_action(&f) {
        Some(a) => {
            crate::set_reset_action(a);
            alog_raw(b"[INFO]  fadt: reset register usable\n");
        }
        None => alog_raw(b"[INFO]  fadt: no usable reset register\n"),
    }
}

#[cfg(test)]
mod tests;
