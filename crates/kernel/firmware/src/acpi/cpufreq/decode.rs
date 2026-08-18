//! Pure ACPI processor-performance object decoding.

use alloc::vec::Vec;

use crate::acpi::aml_eval::AmlField;

const PSS_FIELDS: usize = 6;
const PSD_FIELDS: usize = 5;
const PCT_ROWS: usize = 2;
const PSD_ROWS: usize = 1;
const SPACE_SYSTEM_IO: u64 = 1;
const SPACE_FIXED_HARDWARE: u64 = 0x7f;
const COORDINATION_SW_ALL: u64 = 0xfc;
const COORDINATION_SW_ANY: u64 = 0xfd;
const COORDINATION_HW_ALL: u64 = 0xfe;
const ACCESS_ANY: u64 = 0;
const ACCESS_BYTE: u64 = 1;
const ACCESS_WORD: u64 = 2;
const ACCESS_DWORD: u64 = 3;
const ACCESS_QWORD: u64 = 4;
const BITS_PER_BYTE: u8 = 8;
const MAX_PORT: u64 = u16::MAX as u64;
const PORT_SPACE_BYTES: u64 = u16::MAX as u64 + 1;
const NS_PER_US: u64 = 1_000;

/// Address-space implementation a processor's P-state control uses.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PctSpace { SystemIo, FixedHardware }

/// One ACPI generic-address record admitted for P-state access.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PctRegister { pub space: PctSpace, pub width_bits: u8, pub address: u64 }

/// One usable performance state. `index` remains the firmware's original
/// `_PSS` index because `_PPC` limits name that index rather than a filtered
/// frequency-table position.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Pstate {
    pub index: u32,
    pub frequency_khz: u32,
    pub transition_latency_ns: u64,
    pub control: u32,
    pub status: u32,
}

/// How a firmware performance domain coordinates transitions across CPUs.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Coordination { SoftwareAll, SoftwareAny, HardwareAll }

/// Firmware's processor-domain declaration.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Psd { pub domain: u32, pub processors: u32, pub coordination: Coordination }

/// A malformed or unsupported processor-performance object.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DecodeError {
    PssShape, PssValue, PssStates, PctShape, PctRegister, PctMismatch,
    PsdShape, PsdValue,
}

/// Decode, validate, and normalise the performance states in `_PSS`.
/// Firmware declares highest performance first; non-descending entries are
/// omitted because two table entries at one or an increasing frequency cannot
/// name a deterministic platform ceiling. # C: O(states)
pub fn decode_pss(rows: &[Vec<AmlField>]) -> Result<Vec<Pstate>, DecodeError> {
    let mut states = Vec::with_capacity(rows.len());
    let mut previous = None;
    for (index, row) in rows.iter().enumerate() {
        if row.len() != PSS_FIELDS { return Err(DecodeError::PssShape); }
        let frequency_mhz = integer(&row[0]).ok_or(DecodeError::PssValue)?;
        let frequency_khz = frequency_mhz.checked_mul(1_000).and_then(|v| u32::try_from(v).ok())
            .filter(|v| *v != 0).ok_or(DecodeError::PssValue)?;
        let latency_us = integer(&row[2]).ok_or(DecodeError::PssValue)?;
        let transition_latency_ns = latency_us.checked_mul(NS_PER_US).ok_or(DecodeError::PssValue)?;
        let control = integer(&row[4]).and_then(|v| u32::try_from(v).ok()).ok_or(DecodeError::PssValue)?;
        let status = integer(&row[5]).and_then(|v| u32::try_from(v).ok()).ok_or(DecodeError::PssValue)?;
        if previous.is_some_and(|higher| frequency_khz >= higher) { continue; }
        let index = u32::try_from(index).map_err(|_| DecodeError::PssStates)?;
        states.push(Pstate { index, frequency_khz, transition_latency_ns, control, status });
        previous = Some(frequency_khz);
    }
    if states.len() < 2 { return Err(DecodeError::PssStates); }
    Ok(states)
}

/// Decode the two resource-template buffers in `_PCT`. # C: O(bytes)
pub fn decode_pct(buffers: &[Vec<u8>]) -> Result<(PctRegister, PctRegister), DecodeError> {
    if buffers.len() != PCT_ROWS { return Err(DecodeError::PctShape); }
    let control = decode_gas(&buffers[0])?;
    let status = decode_gas(&buffers[1])?;
    if control.space != status.space { return Err(DecodeError::PctMismatch); }
    Ok((control, status))
}

/// Decode `_PPC`'s current maximum performance-state index. A missing method
/// has no platform ceiling; an index outside the original `_PSS` array is not
/// a valid limit. # C: O(1)
pub fn decode_ppc(value: Option<u64>, original_state_count: usize) -> Option<u32> {
    let value = value?;
    let index = u32::try_from(value).ok()?;
    (usize::try_from(index).ok()? < original_state_count).then_some(index)
}

/// Decode `_PSD` when firmware declares a shared performance domain.
/// # C: O(1)
pub fn decode_psd(rows: &[Vec<AmlField>]) -> Result<Psd, DecodeError> {
    if rows.len() != PSD_ROWS || rows[0].len() != PSD_FIELDS { return Err(DecodeError::PsdShape); }
    let fields = &rows[0];
    if integer(&fields[0]) != Some(PSD_FIELDS as u64) || integer(&fields[1]) != Some(0) {
        return Err(DecodeError::PsdValue);
    }
    let domain = integer(&fields[2]).and_then(|v| u32::try_from(v).ok()).ok_or(DecodeError::PsdValue)?;
    let coordination = match integer(&fields[3]) {
        Some(COORDINATION_SW_ALL) => Coordination::SoftwareAll,
        Some(COORDINATION_SW_ANY) => Coordination::SoftwareAny,
        Some(COORDINATION_HW_ALL) => Coordination::HardwareAll,
        _ => return Err(DecodeError::PsdValue),
    };
    let processors = integer(&fields[4]).and_then(|v| u32::try_from(v).ok())
        .filter(|v| *v != 0).ok_or(DecodeError::PsdValue)?;
    Ok(Psd { domain, processors, coordination })
}

/// Largest latency any state reports, in nanoseconds. # C: O(states)
pub fn max_latency(states: &[Pstate]) -> u64 {
    states.iter().map(|state| state.transition_latency_ns).max().unwrap_or(0)
}

/// Frequency at the performance-state index `_PPC` names. # C: O(states)
pub fn frequency_at(states: &[Pstate], index: u32) -> Option<u32> {
    states.iter().find(|state| state.index == index).map(|state| state.frequency_khz)
}

/// Frequency whose firmware status value is `value`. Every ACPI P-state
/// hardware readback is translated through `_PSS` status encodings, which may
/// differ from the value used to program the control register. # C: O(states)
pub fn frequency_for_status(states: &[Pstate], value: u32) -> Option<u32> {
    states.iter().find(|state| state.status == value).map(|state| state.frequency_khz)
}

/// Frequency whose MSR status value is `value`. Linux reports the highest
/// table frequency when a performance MSR holds an unlisted transient value;
/// System I/O readback deliberately remains unknown instead. # C: O(states)
pub fn frequency_for_msr_status(states: &[Pstate], value: u32) -> Option<u32> {
    frequency_for_status(states, value).or_else(|| states.first().map(|state| state.frequency_khz))
}

/// One integer field, rejecting text where firmware promised a number.
/// # C: O(1)
fn integer(field: &AmlField) -> Option<u64> { field.int() }

/// Generic Register Descriptor found within one resource-template buffer.
const LARGE_GENERIC_REGISTER: u8 = 2;
const GENERIC_REGISTER_BYTES: usize = 12;

/// One generic-address descriptor, reduced to the P-state-safe address
/// spaces. A resource template may contain an EndTag after it; descriptors
/// other than the one register are ignored, while a malformed stream fails.
/// # C: O(buffer bytes)
fn decode_gas(buffer: &[u8]) -> Result<PctRegister, DecodeError> {
    let fields = generic_register(buffer).ok_or(DecodeError::PctRegister)?;
    let space = match u64::from(fields[0]) {
        SPACE_SYSTEM_IO => PctSpace::SystemIo,
        SPACE_FIXED_HARDWARE => PctSpace::FixedHardware,
        _ => return Err(DecodeError::PctRegister),
    };
    let width = fields[1];
    if fields[2] != 0 { return Err(DecodeError::PctRegister); }
    let access = u64::from(fields[3]);
    let address = u64::from_le_bytes(fields[4..].try_into().map_err(|_| DecodeError::PctRegister)?);
    if space == PctSpace::FixedHardware { return Ok(PctRegister { space, width_bits: 0, address }); }
    let width_bits = access_width(width, access).ok_or(DecodeError::PctRegister)?;
    let bytes = u64::from(width_bits / BITS_PER_BYTE);
    if address > MAX_PORT || address.checked_add(bytes).is_none_or(|end| end > PORT_SPACE_BYTES) {
        return Err(DecodeError::PctRegister);
    }
    Ok(PctRegister { space, width_bits, address })
}

/// Find exactly one Generic Register Descriptor in a resource template.
/// # C: O(buffer bytes)
fn generic_register(buffer: &[u8]) -> Option<[u8; GENERIC_REGISTER_BYTES]> {
    let mut cursor = 0usize;
    let mut found = None;
    while cursor < buffer.len() {
        let tag = *buffer.get(cursor)?;
        cursor += 1;
        let (kind, bytes) = if tag & 0x80 == 0 {
            (None, usize::from(tag & 0x07))
        } else {
            let length = buffer.get(cursor..cursor.checked_add(2)?)?;
            cursor += 2;
            (Some(tag & 0x7f), usize::from(u16::from_le_bytes(length.try_into().ok()?)))
        };
        let data = buffer.get(cursor..cursor.checked_add(bytes)?)?;
        cursor += bytes;
        if kind != Some(LARGE_GENERIC_REGISTER) { continue; }
        if data.len() != GENERIC_REGISTER_BYTES || found.is_some() { return None; }
        let mut register = [0u8; GENERIC_REGISTER_BYTES];
        register.copy_from_slice(data);
        found = Some(register);
    }
    found
}

/// Effective width of a GAS access. Access-size zero means bit width supplies
/// the width; otherwise the two declarations must agree. # C: O(1)
fn access_width(bit_width: u8, access: u64) -> Option<u8> {
    let width = match access {
        ACCESS_ANY => bit_width,
        ACCESS_BYTE => 8,
        ACCESS_WORD => 16,
        ACCESS_DWORD => 32,
        ACCESS_QWORD => 64,
        _ => return None,
    };
    if !matches!(width, 8 | 16 | 32) || (access != ACCESS_ANY && bit_width != width) { return None; }
    Some(width)
}

#[cfg(test)]
#[path = "decode_tests.rs"]
mod tests;
