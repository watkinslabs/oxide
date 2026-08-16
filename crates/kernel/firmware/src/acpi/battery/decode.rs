//! `_BIF` / `_BIX` / `_BST` package decoding.
//!
//! Firmware reports milli-units; the class contract is micro-units, and the
//! packages differ in length and field order between the two info methods. All
//! of that is resolved here, on plain field vectors, so it is checkable
//! without a namespace.

use alloc::string::String;

use crate::acpi::aml_eval::AmlField;

/// Field value firmware did not report.
pub const VALUE_UNKNOWN: u32 = 0xFFFF_FFFF;

/// `_BST` state bit: the battery is discharging.
pub const STATE_DISCHARGING: u32 = 1 << 0;
/// `_BST` state bit: the battery is charging.
pub const STATE_CHARGING: u32 = 1 << 1;
/// `_BST` state bit: the charge is critically low.
pub const STATE_CRITICAL: u32 = 1 << 2;
/// `_BST` state bit: charging is being held back deliberately.
pub const STATE_CHARGE_LIMITING: u32 = 1 << 3;

/// `power_unit` value meaning the capacity fields are in mAh and the rate in mA.
pub const POWER_UNIT_MA: u32 = 1;

/// Field count of a `_BIF` package.
pub const BIF_FIELDS: usize = 13;
/// Field count of a `_BIX` package.
pub const BIX_FIELDS: usize = 20;
/// Field count of a `_BST` package.
pub const BST_FIELDS: usize = 4;

/// Constant battery description from `_BIF` or `_BIX`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Info {
    pub power_unit_ma: bool,
    pub design_capacity: u32,
    pub full_charge_capacity: u32,
    pub design_voltage: u32,
    pub design_capacity_warning: u32,
    pub design_capacity_low: u32,
    /// Only `_BIX` reports it; `_BIF` batteries leave it unknown.
    pub cycle_count: u32,
    pub model_number: String,
    pub serial_number: String,
    pub battery_type: String,
    pub oem_info: String,
}

/// Varying battery reading from `_BST`.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct State {
    pub state: u32,
    pub rate_now: u32,
    pub capacity_now: u32,
    pub voltage_now: u32,
}

/// Integer field, or the unknown sentinel when firmware supplied something
/// that is not an integer. # C: O(1)
fn int_at(fields: &[AmlField], index: usize) -> u32 {
    fields.get(index).and_then(AmlField::int).map_or(VALUE_UNKNOWN, |value| value as u32)
}

/// Text field. # C: O(n)
fn text_at(fields: &[AmlField], index: usize) -> String {
    fields.get(index).map(AmlField::text).unwrap_or_default()
}

/// Decode a `_BIF` package. # C: O(1)
pub fn parse_bif(fields: &[AmlField]) -> Option<Info> {
    if fields.len() < BIF_FIELDS { return None; }
    Some(Info {
        power_unit_ma: int_at(fields, 0) == POWER_UNIT_MA,
        design_capacity: int_at(fields, 1),
        full_charge_capacity: int_at(fields, 2),
        design_voltage: int_at(fields, 4),
        design_capacity_warning: int_at(fields, 5),
        design_capacity_low: int_at(fields, 6),
        cycle_count: VALUE_UNKNOWN,
        model_number: text_at(fields, 9),
        serial_number: text_at(fields, 10),
        battery_type: text_at(fields, 11),
        oem_info: text_at(fields, 12),
    })
}

/// Decode a `_BIX` package. The extra leading revision field shifts every
/// `_BIF` field along, and five sampling fields sit before the granularities.
/// # C: O(1)
pub fn parse_bix(fields: &[AmlField]) -> Option<Info> {
    if fields.len() < BIX_FIELDS { return None; }
    Some(Info {
        power_unit_ma: int_at(fields, 1) == POWER_UNIT_MA,
        design_capacity: int_at(fields, 2),
        full_charge_capacity: int_at(fields, 3),
        design_voltage: int_at(fields, 5),
        design_capacity_warning: int_at(fields, 6),
        design_capacity_low: int_at(fields, 7),
        cycle_count: int_at(fields, 8),
        model_number: text_at(fields, 16),
        serial_number: text_at(fields, 17),
        battery_type: text_at(fields, 18),
        oem_info: text_at(fields, 19),
    })
}

/// Decode a `_BST` package. A rate reported as a negative 16-bit quantity is
/// a wrapped magnitude, not a direction: the direction lives in the state
/// bits, so a signed reading here would otherwise show a battery drawing
/// four billion microamps. # C: O(1)
pub fn parse_bst(fields: &[AmlField], power_unit_ma: bool) -> Option<State> {
    if fields.len() < BST_FIELDS { return None; }
    let mut rate_now = int_at(fields, 1);
    if power_unit_ma && rate_now != VALUE_UNKNOWN && (rate_now as u16 as i16) < 0 {
        rate_now = u32::from((rate_now as u16 as i16).unsigned_abs());
    }
    Some(State {
        state: int_at(fields, 0),
        rate_now,
        capacity_now: int_at(fields, 2),
        voltage_now: int_at(fields, 3),
    })
}

/// A capacity field is usable only when firmware reported it and it is not
/// zero — a zero full-charge capacity would make every percentage a division
/// by zero. # C: O(1)
pub fn capacity_valid(value: u32) -> bool { value != 0 && value != VALUE_UNKNOWN }

/// Firmware milli-units to the class micro-units. # C: O(1)
pub fn to_micro(value: u32) -> i32 { (u64::from(value) * MILLI_TO_MICRO) as i32 }

/// Milli-unit to micro-unit factor.
const MILLI_TO_MICRO: u64 = 1000;

/// Neither capacity reference is usable, so nothing derived from a full
/// charge can be published for this battery. # C: O(1)
pub fn full_cap_broken(info: &Info) -> bool {
    !capacity_valid(info.full_charge_capacity) && !capacity_valid(info.design_capacity)
}

/// The capacity reference a percentage is taken against: the measured full
/// charge when firmware tracks it, otherwise the design figure. # C: O(1)
pub fn full_capacity(info: &Info) -> Option<u32> {
    if capacity_valid(info.full_charge_capacity) { return Some(info.full_charge_capacity); }
    if capacity_valid(info.design_capacity) { return Some(info.design_capacity); }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn ints(values: &[u64]) -> Vec<AmlField> {
        values.iter().map(|value| AmlField::Int(*value)).collect()
    }

    fn bif() -> Vec<AmlField> {
        let mut fields = ints(&[1, 5000, 4800, 1, 11400, 480, 240, 10, 10]);
        fields.push(AmlField::Text(String::from("OXP-1")));
        fields.push(AmlField::Text(String::from("SN123")));
        fields.push(AmlField::Text(String::from("LIon")));
        fields.push(AmlField::Text(String::from("OxideCorp")));
        fields
    }

    fn bix() -> Vec<AmlField> {
        let mut fields = ints(&[0, 0, 60000, 57000, 1, 11400, 5700, 2850, 143, 1, 0, 0, 0, 0, 10, 10]);
        fields.push(AmlField::Text(String::from("OXP-2")));
        fields.push(AmlField::Text(String::from("SN456")));
        fields.push(AmlField::Text(String::from("LiP")));
        fields.push(AmlField::Text(String::from("OxideCorp")));
        fields
    }

    #[test]
    fn a_bif_package_decodes_into_the_constant_description() {
        let info = parse_bif(&bif()).expect("bif");
        assert!(info.power_unit_ma);
        assert_eq!(info.design_capacity, 5000);
        assert_eq!(info.full_charge_capacity, 4800);
        assert_eq!(info.design_voltage, 11400);
        assert_eq!(info.design_capacity_warning, 480);
        assert_eq!(info.design_capacity_low, 240);
        assert_eq!(info.cycle_count, VALUE_UNKNOWN, "_BIF does not report a cycle count");
        assert_eq!(info.model_number, "OXP-1");
        assert_eq!(info.serial_number, "SN123");
        assert_eq!(info.battery_type, "LIon");
        assert_eq!(info.oem_info, "OxideCorp");
    }

    #[test]
    fn a_bix_package_reads_the_same_fields_from_their_shifted_positions() {
        let info = parse_bix(&bix()).expect("bix");
        assert!(!info.power_unit_ma, "the revision field must not be read as the power unit");
        assert_eq!(info.design_capacity, 60000);
        assert_eq!(info.full_charge_capacity, 57000);
        assert_eq!(info.design_voltage, 11400);
        assert_eq!(info.design_capacity_warning, 5700);
        assert_eq!(info.design_capacity_low, 2850);
        assert_eq!(info.cycle_count, 143);
        assert_eq!(info.model_number, "OXP-2");
        assert_eq!(info.serial_number, "SN456");
        assert_eq!(info.battery_type, "LiP");
    }

    #[test]
    fn a_short_package_is_refused_rather_than_read_past_its_end() {
        assert_eq!(parse_bif(&ints(&[1, 2, 3])), None);
        assert_eq!(parse_bix(&bif()), None, "a _BIF package is not a _BIX package");
        assert_eq!(parse_bst(&ints(&[1, 2]), false), None);
    }

    #[test]
    fn a_non_integer_field_becomes_the_unknown_sentinel() {
        let mut fields = bif();
        fields[2] = AmlField::Text(String::from("broken"));
        let info = parse_bif(&fields).expect("bif");
        assert_eq!(info.full_charge_capacity, VALUE_UNKNOWN);
        assert!(!capacity_valid(info.full_charge_capacity));
    }

    #[test]
    fn a_wrapped_negative_rate_is_read_as_a_magnitude() {
        let wrapped = u64::from(u16::MAX - 999);
        let state = parse_bst(&ints(&[STATE_DISCHARGING as u64, wrapped, 2400, 11000]), true)
            .expect("bst");
        assert_eq!(state.rate_now, 1000);
        // With mWh units the same word is a plain value and is left alone.
        let state = parse_bst(&ints(&[STATE_DISCHARGING as u64, wrapped, 2400, 11000]), false)
            .expect("bst");
        assert_eq!(state.rate_now, wrapped as u32);
    }

    #[test]
    fn an_unknown_rate_is_not_mistaken_for_a_wrapped_one() {
        let state = parse_bst(
            &ints(&[0, u64::from(VALUE_UNKNOWN), 2400, 11000]), true,
        ).expect("bst");
        assert_eq!(state.rate_now, VALUE_UNKNOWN);
    }

    #[test]
    fn milli_units_convert_to_the_class_micro_units() {
        assert_eq!(to_micro(11400), 11_400_000);
        assert_eq!(to_micro(0), 0);
    }

    #[test]
    fn zero_and_the_sentinel_are_both_unusable_capacities() {
        assert!(!capacity_valid(0));
        assert!(!capacity_valid(VALUE_UNKNOWN));
        assert!(capacity_valid(1));
    }

    #[test]
    fn the_percentage_reference_falls_back_to_the_design_capacity() {
        let mut info = parse_bif(&bif()).expect("bif");
        assert_eq!(full_capacity(&info), Some(4800));
        assert!(!full_cap_broken(&info));
        info.full_charge_capacity = 0;
        assert_eq!(full_capacity(&info), Some(5000));
        assert!(!full_cap_broken(&info));
        info.design_capacity = VALUE_UNKNOWN;
        assert_eq!(full_capacity(&info), None);
        assert!(full_cap_broken(&info));
    }
}
