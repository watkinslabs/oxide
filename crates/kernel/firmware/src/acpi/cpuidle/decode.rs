//! Pure `_CST` validation and normalization.

extern crate alloc;

use alloc::vec::Vec;

use cpuidle::{Entry, IdleState};

use crate::acpi::aml_eval::{CstField, CstPackage};

const CST_ROW_FIELDS: usize = 4;
const GAS_BYTES: usize = 12;
const SPACE_SYSTEM_IO: u8 = 1;
const SPACE_FIXED_HARDWARE: u8 = 0x7f;
const C1: u8 = 1;
const C2: u8 = 2;
const C3: u8 = 3;
const TARGET_FACTOR: u64 = 2;
const POWER_UW_PER_MW: u64 = 1_000;

/// One C-state admitted from firmware, with the ACPI type retained for the
/// C3 bus-master and cache rules at entry time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CstState {
    pub cstate: u8,
    pub state: IdleState,
    /// Fixed-hardware C3 can explicitly declare that the PM1 bus-master bit
    /// is not part of its wake contract.
    pub skip_bus_master_status: bool,
}

/// A package that cannot describe the number of rows it contains.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DecodeError { Count }

/// Validate and normalize an evaluated C-state package. Invalid individual
/// rows are ignored, as firmware often carries an entry for an unavailable
/// depth; an inconsistent outer count rejects the whole package. # C: O(rows)
pub fn decode_cst(package: &CstPackage, fixed_supported: fn(u32) -> bool)
    -> Result<Vec<CstState>, DecodeError>
{
    if package.count == 0 || usize::try_from(package.count).ok() != Some(package.rows.len()) {
        return Err(DecodeError::Count);
    }
    let mut states = Vec::new();
    for row in &package.rows {
        let Some((gas, cstate, latency_us, power_uw)) = row_fields(row) else { continue; };
        if !matches!(cstate, C1 | C2 | C3) || states.iter().any(|state: &CstState| state.cstate == cstate) {
            continue;
        }
        let entry = match gas.space {
            SPACE_SYSTEM_IO => {
                let Some(port) = u16::try_from(gas.address).ok() else { continue; };
                Entry::SystemIo { port: u64::from(port), width: 8 }
            }
            SPACE_FIXED_HARDWARE => {
                if gas.bit_offset != C2 { continue; }
                let Some(hint) = u32::try_from(gas.address).ok() else { continue; };
                if fixed_supported(hint) { Entry::Mwait { hint } }
                else if cstate == C1 { Entry::Halt }
                else { continue; }
            }
            _ => continue,
        };
        states.push(CstState {
            cstate,
            state: state(cstate, latency_us, power_uw, entry),
            skip_bus_master_status: gas.space == SPACE_FIXED_HARDWARE && gas.access_width & 2 == 0,
        });
    }
    normalize_order(&mut states);
    Ok(states)
}

/// Architected C1 becomes the safe fallback when `_CST` omits it or firmware
/// supplied no usable implementation. # C: O(states)
pub fn with_c1_fallback(mut states: Vec<CstState>) -> Vec<CstState> {
    if !states.iter().any(|state| state.cstate == C1) {
        states.push(CstState { cstate: C1, state: state(C1, 1, 0, Entry::Halt), skip_bus_master_status: false });
        normalize_order(&mut states);
    }
    states
}

#[derive(Copy, Clone)]
struct Gas { space: u8, bit_offset: u8, access_width: u8, address: u64 }

/// Decode one exact four-field row, including its raw Generic Address
/// Structure. # C: O(1)
fn row_fields(row: &[CstField]) -> Option<(Gas, u8, u64, u32)> {
    if row.len() != CST_ROW_FIELDS { return None; }
    let CstField::Buffer(buffer) = &row[0] else { return None; };
    if buffer.len() != GAS_BYTES { return None; }
    let CstField::Int(cstate) = row[1] else { return None; };
    let CstField::Int(latency_us) = row[2] else { return None; };
    let CstField::Int(power_mw) = row[3] else { return None; };
    let cstate = u8::try_from(cstate).ok()?;
    let power_uw = power_mw.checked_mul(POWER_UW_PER_MW).and_then(|value| u32::try_from(value).ok())?;
    let address = u64::from_le_bytes(buffer[4..GAS_BYTES].try_into().ok()?);
    Some((Gas { space: buffer[0], bit_offset: buffer[2], access_width: buffer[3], address }, cstate, latency_us, power_uw))
}

/// Construct the public idle state from normalized ACPI units. # C: O(1)
fn state(cstate: u8, latency_us: u64, power_uw: u32, entry: Entry) -> IdleState {
    let (name, desc) = match cstate {
        C1 => ("C1", "ACPI C1"), C2 => ("C2", "ACPI C2"), C3 => ("C3", "ACPI C3"),
        _ => ("C?", "ACPI C state"),
    };
    let mut state = IdleState::from_us(name, desc, latency_us, latency_us.saturating_mul(TARGET_FACTOR), entry);
    state.power_uw = power_uw;
    state
}

/// Retain C-state depth order while repairing a firmware latency ladder that
/// would otherwise be rejected by the generic governor. # C: O(states)
fn normalize_order(states: &mut [CstState]) {
    states.sort_by_key(|state| state.cstate);
    let mut previous = 0u64;
    for entry in states {
        let latency = entry.state.exit_latency_ns.max(previous);
        entry.state.exit_latency_ns = latency;
        entry.state.target_residency_ns = latency.saturating_mul(TARGET_FACTOR);
        previous = latency;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn gas(space: u8, bit_offset: u8, address: u64) -> CstField {
        let mut bytes = vec![0; GAS_BYTES];
        bytes[0] = space;
        bytes[2] = bit_offset;
        bytes[4..].copy_from_slice(&address.to_le_bytes());
        CstField::Buffer(bytes)
    }

    fn row(space: u8, offset: u8, address: u64, cstate: u64, latency: u64) -> Vec<CstField> {
        vec![gas(space, offset, address), CstField::Int(cstate), CstField::Int(latency), CstField::Int(5)]
    }

    fn mwait(hint: u32) -> bool { hint == 0x30 }

    #[test]
    fn rows_keep_acpi_power_and_are_sorted_for_the_governor() {
        let package = CstPackage { count: 2, rows: vec![
            row(SPACE_SYSTEM_IO, 0, 0x415, C3.into(), 30),
            row(SPACE_FIXED_HARDWARE, C2, 0x30, C2.into(), 10),
        ] };
        let states = decode_cst(&package, mwait).expect("package");
        assert_eq!(states.iter().map(|state| state.cstate).collect::<Vec<_>>(), [C2, C3]);
        assert_eq!(states[0].state.entry, Entry::Mwait { hint: 0x30 });
        assert_eq!(states[1].state.entry, Entry::SystemIo { port: 0x415, width: 8 });
        assert_eq!(states[0].state.target_residency_us(), 20);
        assert_eq!(states[0].state.power_uw, 5_000);
    }

    #[test]
    fn count_must_exactly_describe_the_package_rows() {
        let package = CstPackage { count: 2, rows: vec![row(SPACE_SYSTEM_IO, 0, 0x414, C1.into(), 1)] };
        assert_eq!(decode_cst(&package, mwait), Err(DecodeError::Count));
    }

    #[test]
    fn unsupported_fixed_c1_demotes_to_halt_but_deeper_rows_are_refused() {
        let package = CstPackage { count: 3, rows: vec![
            row(SPACE_FIXED_HARDWARE, C2, 0x10, C1.into(), 1),
            row(SPACE_FIXED_HARDWARE, C2, 0x20, C2.into(), 2),
            vec![CstField::Int(0)],
        ] };
        let states = decode_cst(&package, mwait).expect("outer package");
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].state.entry, Entry::Halt);
        assert_eq!(with_c1_fallback(states).len(), 1);
    }

    #[test]
    fn missing_c1_gets_the_architected_safe_state() {
        let package = CstPackage { count: 1, rows: vec![row(SPACE_SYSTEM_IO, 0, 0x415, C3.into(), 30)] };
        let states = with_c1_fallback(decode_cst(&package, mwait).expect("package"));
        assert_eq!(states.iter().map(|state| state.cstate).collect::<Vec<_>>(), [C1, C3]);
        assert_eq!(states[0].state.entry, Entry::Halt);
    }

    #[test]
    fn out_of_order_latency_never_reorders_the_hardware_ladder() {
        let package = CstPackage { count: 2, rows: vec![
            row(SPACE_SYSTEM_IO, 0, 0x414, C1.into(), 20),
            row(SPACE_SYSTEM_IO, 0, 0x415, C2.into(), 5),
        ] };
        let states = decode_cst(&package, mwait).expect("package");
        assert_eq!(states.iter().map(|state| state.cstate).collect::<Vec<_>>(), [C1, C2]);
        assert_eq!(states[1].state.exit_latency_us(), 20);
    }
}
