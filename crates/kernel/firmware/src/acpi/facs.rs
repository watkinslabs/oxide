// FACS decode + the firmware-waking-vector write plan it exists to answer.
//
// The FACS is the one ACPI table the OS WRITES: the resume entry point a
// deep sleep comes back through lives in it, and firmware reads it after
// the sleep register write. Everything here is a pure byte-slice function
// so the offsets, the length gating and the 32-vs-64-bit vector rule are
// hosted-testable; `install_facs` is the thin unsafe shim that copies the
// firmware table out of the HHDM and publishes what a consumer reads.

use sync::{Devices, Spinlock};

use crate::acpi::log::{alog_hex, alog_raw};
use crate::acpi::read::read_u32_le;

/// Table signature, ASCII, offset 0. A pointer that does not carry it is
/// not a FACS however plausible the rest of the bytes look.
pub const FACS_SIGNATURE: [u8; 4] = *b"FACS";

/// Shortest FACS whose fields an OS consumes: signature, length, hardware
/// signature, the 32-bit waking vector, the global lock and the flags.
/// A conformant table is 64 bytes; the extended (64-bit) vector and the
/// version byte only exist above [`FACS_EXTENDED_MIN_LEN`].
pub const FACS_MIN_LEN: usize = 24;
/// Largest table length this decoder will believe.
pub const FACS_MAX_LEN: usize = 4096;
/// A FACS longer than this carries the 64-bit vector and the version byte.
pub const FACS_EXTENDED_MIN_LEN: u32 = 32;
/// Table version that makes the 64-bit waking vector meaningful.
pub const FACS_VERSION_XVECTOR: u8 = 1;

/// FACS flag bit 1: firmware supports the 64-bit wake vector.
pub const FACS_64BIT_WAKE: u32 = 1 << 1;

// Field offsets. The table is packed; these are byte positions.
const OFF_SIGNATURE: usize = 0;
const OFF_LENGTH: usize = 4;
const OFF_HARDWARE_SIGNATURE: usize = 8;
const OFF_FIRMWARE_WAKING_VECTOR: usize = 12;
const OFF_GLOBAL_LOCK: usize = 16;
const OFF_FLAGS: usize = 20;
const OFF_XFIRMWARE_WAKING_VECTOR: usize = 24;
const OFF_VERSION: usize = 32;

/// Parsed FACS. `version` is zero on a table too short to carry the byte,
/// which is the same thing the reference concludes from the length alone.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Facs {
    pub length: u32,
    pub hardware_signature: u32,
    pub firmware_waking_vector: u32,
    pub global_lock: u32,
    pub flags: u32,
    pub xfirmware_waking_vector: u64,
    pub version: u8,
}

/// Where the resume address must be written, given one parsed FACS.
///
/// The reference writes the 32-bit vector unconditionally and only then
/// decides about the extended one: a table long enough to carry it gets
/// either the 64-bit address (version ≥ 1) or an explicit zero (version 0),
/// because leaving a stale 64-bit vector behind makes firmware resume
/// through it in protected mode and never reach the real-mode stub.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WakingVectorWrites {
    /// Always written, at [`vector32_offset`].
    pub vector32: u32,
    /// Written at [`xvector_offset`] when present; `None` leaves the field
    /// alone because the table is too short to have one.
    pub xvector: Option<u64>,
}

/// Byte offset of the 32-bit firmware waking vector within the FACS. # C: O(1)
pub const fn vector32_offset() -> usize { OFF_FIRMWARE_WAKING_VECTOR }
/// Byte offset of the 64-bit firmware waking vector within the FACS. # C: O(1)
pub const fn xvector_offset() -> usize { OFF_XFIRMWARE_WAKING_VECTOR }

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

/// Parse a FACS body.
///
/// `None` for every table an OS must not write into: a wrong signature, a
/// declared length below the consumed fields or beyond what a firmware
/// table plausibly is, and a declared length the supplied bytes do not
/// cover. The last one matters because the caller copies a bounded window
/// out of firmware memory — believing a length longer than the copy would
/// publish uninitialised bytes as table content.
///
/// # C: O(1)
pub fn parse_facs(t: &[u8]) -> Option<Facs> {
    if t.len() < FACS_MIN_LEN { return None; }
    if t[OFF_SIGNATURE..OFF_SIGNATURE + 4] != FACS_SIGNATURE { return None; }
    let length = u32_at(t, OFF_LENGTH);
    if (length as usize) < FACS_MIN_LEN { return None; }
    if (length as usize) > FACS_MAX_LEN { return None; }
    if (length as usize) > t.len() { return None; }
    let extended = length > FACS_EXTENDED_MIN_LEN;
    Some(Facs {
        length,
        hardware_signature: u32_at(t, OFF_HARDWARE_SIGNATURE),
        firmware_waking_vector: u32_at(t, OFF_FIRMWARE_WAKING_VECTOR),
        global_lock: u32_at(t, OFF_GLOBAL_LOCK),
        flags: u32_at(t, OFF_FLAGS),
        xfirmware_waking_vector: if extended { u64_at(t, OFF_XFIRMWARE_WAKING_VECTOR) } else { 0 },
        version: if extended && t.len() > OFF_VERSION { t[OFF_VERSION] } else { 0 },
    })
}

/// The writes that publish `pa32`/`pa64` as this machine's resume entry.
///
/// `pa64` is zero on the path this port uses: firmware resumes in real mode
/// at the 32-bit vector, and machines exist that fail to resume at all when
/// the 64-bit vector is non-zero.
/// # C: O(1)
pub fn waking_vector_writes(facs: &Facs, pa32: u32, pa64: u64) -> WakingVectorWrites {
    if facs.length <= FACS_EXTENDED_MIN_LEN {
        return WakingVectorWrites { vector32: pa32, xvector: None };
    }
    let xvector = if facs.version >= FACS_VERSION_XVECTOR { pa64 } else { 0 };
    WakingVectorWrites { vector32: pa32, xvector: Some(xvector) }
}

static FACS_PA: Spinlock<Option<u64>, Devices> = Spinlock::new(None);
static FACS: Spinlock<Option<Facs>, Devices> = Spinlock::new(None);

/// Retain the one validated FACS and its physical address (first wins).
/// # C: O(1)
pub fn set_facs(pa: u64, facs: Facs) {
    let mut present = FACS.lock();
    if present.is_none() {
        *present = Some(facs);
        *FACS_PA.lock() = Some(pa);
    }
}

/// The validated FACS firmware published, if any. # C: O(1)
pub fn facs() -> Option<Facs> { *FACS.lock() }

/// Physical address of the validated FACS. The sleep path maps it to write
/// the waking vector, so the address is published beside the parse rather
/// than re-derived. # C: O(1)
pub fn facs_pa() -> Option<u64> { *FACS_PA.lock() }

/// Copy the firmware FACS out of the HHDM, validate it, and publish it.
///
/// # SAFETY: caller asserts `pa` is the FADT-declared FACS address whose
/// first [`FACS_MIN_LEN`] bytes are readable at `hhdm_offset + pa`, under
/// the same bootloader-owned-ACPI-memory contract the rest of the table
/// walk relies on.
/// # C: O(1)
/// # Ctx: pre-init, single-CPU
pub unsafe fn install_facs(pa: u64, hhdm_offset: u64) {
    if pa == 0 { return; }
    let p = (hhdm_offset.wrapping_add(pa)) as *const u8;
    // SAFETY: the FADT-declared FACS address carries a ≥24-byte header; offset 4..8 is the declared length.
    let length = unsafe { read_u32_le(p.add(OFF_LENGTH)) } as usize;
    if length < FACS_MIN_LEN || length > FACS_MAX_LEN {
        alog_raw(b"[ERROR] facs: implausible length\n");
        return;
    }
    let mut buf = [0u8; 256];
    let n = if length > buf.len() { buf.len() } else { length };
    let mut i = 0usize;
    while i < n {
        // SAFETY: i < n <= the table's own declared length, which the caller asserts is readable.
        buf[i] = unsafe { core::ptr::read_volatile(p.add(i)) };
        i += 1;
    }
    // A truncated copy must not be believed: the parse is handed only the
    // bytes actually read, and rejects a declared length beyond them.
    let Some(f) = parse_facs(&buf[..n]) else {
        alog_raw(b"[ERROR] facs: rejected table\n");
        return;
    };
    alog_raw(b"[INFO]  facs: pa=");
    alog_hex(pa);
    alog_raw(b" hwsig=");
    alog_hex(f.hardware_signature as u64);
    alog_raw(b"\n");
    set_facs(pa, f);
}

#[cfg(test)]
#[path = "facs/tests.rs"]
mod tests;
