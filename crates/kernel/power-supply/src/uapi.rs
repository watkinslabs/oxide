// The property enumeration and its attribute table. One `properties!`
// invocation declares the ordinal, the sysfs file name and the value kind
// together, so a property cannot exist with no attribute row or drift onto
// the wrong one.
//
// Units are the class contract and are not negotiable per driver: voltages in
// microvolts, currents in microamps, power in microwatts, charge in
// microamp-hours, energy in microwatt-hours, time in seconds, temperature in
// tenths of a degree Celsius, capacity and the alert/threshold percentages in
// whole percent. A provider that reports milliunits shows a wrong battery.

use alloc::string::String;

use crate::values::{CAPACITY_LEVEL_TEXT, CHARGE_BEHAVIOUR_TEXT, CHARGE_TYPE_TEXT, HEALTH_TEXT,
                    SCOPE_TEXT, STATUS_TEXT, TECHNOLOGY_TEXT, TYPE_TEXT, USB_TYPE_TEXT};

/// How a property's value is rendered.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Decimal integer.
    Int,
    /// Free-form string.
    Str,
    /// One entry of a text table, selected by the value.
    Enum(&'static [&'static str]),
    /// The full list of values the supply declares support for, with the
    /// current one in brackets. Rendered as a plain enum inside a uevent,
    /// where a multi-valued body would be unparseable.
    Available(&'static [&'static str]),
}

/// One row of the class attribute table.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AttrRow {
    pub prop: Property,
    /// The `/sys/class/power_supply/<name>/<attr>` file name.
    pub attr: &'static str,
    pub kind: Kind,
}

macro_rules! properties {
    ($($variant:ident = $ord:literal, $attr:literal, $kind:expr;)+) => {
        /// A power-supply property. The ordinal is ABI: drivers, providers and
        /// the attribute table all index on it.
        #[derive(Copy, Clone, Debug, Eq, PartialEq)]
        #[repr(u32)]
        pub enum Property { $($variant = $ord),+ }

        /// Attribute row per property, in property order.
        pub const ATTRS: &[AttrRow] = &[
            $(AttrRow { prop: Property::$variant, attr: $attr, kind: $kind }),+
        ];
    };
}

properties! {
    Status = 0, "status", Kind::Enum(STATUS_TEXT);
    ChargeType = 1, "charge_type", Kind::Enum(CHARGE_TYPE_TEXT);
    ChargeTypes = 2, "charge_types", Kind::Available(CHARGE_TYPE_TEXT);
    Health = 3, "health", Kind::Enum(HEALTH_TEXT);
    Present = 4, "present", Kind::Int;
    Online = 5, "online", Kind::Int;
    Authentic = 6, "authentic", Kind::Int;
    Technology = 7, "technology", Kind::Enum(TECHNOLOGY_TEXT);
    CycleCount = 8, "cycle_count", Kind::Int;
    VoltageMax = 9, "voltage_max", Kind::Int;
    VoltageMin = 10, "voltage_min", Kind::Int;
    VoltageMaxDesign = 11, "voltage_max_design", Kind::Int;
    VoltageMinDesign = 12, "voltage_min_design", Kind::Int;
    VoltageNow = 13, "voltage_now", Kind::Int;
    VoltageAvg = 14, "voltage_avg", Kind::Int;
    VoltageOcv = 15, "voltage_ocv", Kind::Int;
    VoltageBoot = 16, "voltage_boot", Kind::Int;
    CurrentMax = 17, "current_max", Kind::Int;
    CurrentNow = 18, "current_now", Kind::Int;
    CurrentAvg = 19, "current_avg", Kind::Int;
    CurrentBoot = 20, "current_boot", Kind::Int;
    PowerNow = 21, "power_now", Kind::Int;
    PowerAvg = 22, "power_avg", Kind::Int;
    ChargeFullDesign = 23, "charge_full_design", Kind::Int;
    ChargeEmptyDesign = 24, "charge_empty_design", Kind::Int;
    ChargeFull = 25, "charge_full", Kind::Int;
    ChargeEmpty = 26, "charge_empty", Kind::Int;
    ChargeNow = 27, "charge_now", Kind::Int;
    ChargeAvg = 28, "charge_avg", Kind::Int;
    ChargeCounter = 29, "charge_counter", Kind::Int;
    ConstantChargeCurrent = 30, "constant_charge_current", Kind::Int;
    ConstantChargeCurrentMax = 31, "constant_charge_current_max", Kind::Int;
    ConstantChargeVoltage = 32, "constant_charge_voltage", Kind::Int;
    ConstantChargeVoltageMax = 33, "constant_charge_voltage_max", Kind::Int;
    ChargeControlLimit = 34, "charge_control_limit", Kind::Int;
    ChargeControlLimitMax = 35, "charge_control_limit_max", Kind::Int;
    ChargeControlStartThreshold = 36, "charge_control_start_threshold", Kind::Int;
    ChargeControlEndThreshold = 37, "charge_control_end_threshold", Kind::Int;
    ChargeBehaviour = 38, "charge_behaviour", Kind::Available(CHARGE_BEHAVIOUR_TEXT);
    InputCurrentLimit = 39, "input_current_limit", Kind::Int;
    InputVoltageLimit = 40, "input_voltage_limit", Kind::Int;
    InputPowerLimit = 41, "input_power_limit", Kind::Int;
    EnergyFullDesign = 42, "energy_full_design", Kind::Int;
    EnergyEmptyDesign = 43, "energy_empty_design", Kind::Int;
    EnergyFull = 44, "energy_full", Kind::Int;
    EnergyEmpty = 45, "energy_empty", Kind::Int;
    EnergyNow = 46, "energy_now", Kind::Int;
    EnergyAvg = 47, "energy_avg", Kind::Int;
    Capacity = 48, "capacity", Kind::Int;
    CapacityAlertMin = 49, "capacity_alert_min", Kind::Int;
    CapacityAlertMax = 50, "capacity_alert_max", Kind::Int;
    CapacityErrorMargin = 51, "capacity_error_margin", Kind::Int;
    CapacityLevel = 52, "capacity_level", Kind::Enum(CAPACITY_LEVEL_TEXT);
    Temp = 53, "temp", Kind::Int;
    TempMax = 54, "temp_max", Kind::Int;
    TempMin = 55, "temp_min", Kind::Int;
    TempAlertMin = 56, "temp_alert_min", Kind::Int;
    TempAlertMax = 57, "temp_alert_max", Kind::Int;
    TempAmbient = 58, "temp_ambient", Kind::Int;
    TempAmbientAlertMin = 59, "temp_ambient_alert_min", Kind::Int;
    TempAmbientAlertMax = 60, "temp_ambient_alert_max", Kind::Int;
    TimeToEmptyNow = 61, "time_to_empty_now", Kind::Int;
    TimeToEmptyAvg = 62, "time_to_empty_avg", Kind::Int;
    TimeToFullNow = 63, "time_to_full_now", Kind::Int;
    TimeToFullAvg = 64, "time_to_full_avg", Kind::Int;
    Type = 65, "type", Kind::Enum(TYPE_TEXT);
    UsbType = 66, "usb_type", Kind::Available(USB_TYPE_TEXT);
    Scope = 67, "scope", Kind::Enum(SCOPE_TEXT);
    PrechargeCurrent = 68, "precharge_current", Kind::Int;
    ChargeTermCurrent = 69, "charge_term_current", Kind::Int;
    Calibrate = 70, "calibrate", Kind::Int;
    ManufactureYear = 71, "manufacture_year", Kind::Int;
    ManufactureMonth = 72, "manufacture_month", Kind::Int;
    ManufactureDay = 73, "manufacture_day", Kind::Int;
    InternalResistance = 74, "internal_resistance", Kind::Int;
    StateOfHealth = 75, "state_of_health", Kind::Int;
    ModelName = 76, "model_name", Kind::Str;
    Manufacturer = 77, "manufacturer", Kind::Str;
    SerialNumber = 78, "serial_number", Kind::Str;
}

/// Number of properties the class knows about.
pub const PROPERTY_COUNT: usize = ATTRS.len();

impl Property {
    /// Attribute table row. # C: O(1)
    pub fn row(self) -> &'static AttrRow { &ATTRS[self as usize] }

    /// The sysfs attribute file name. # C: O(1)
    pub fn attr(self) -> &'static str { self.row().attr }

    /// How the value renders. # C: O(1)
    pub fn kind(self) -> Kind { self.row().kind }

    /// The uevent variable name, `POWER_SUPPLY_` plus the attribute name
    /// upper-cased. # C: O(n)
    pub fn uevent_var(self) -> String {
        let mut name = String::from(crate::values::UEVENT_PREFIX);
        name.push_str(&self.attr().to_ascii_uppercase());
        name
    }

    /// Resolve a property from its sysfs attribute name. # C: O(N_props)
    pub fn from_attr(attr: &str) -> Option<Property> {
        ATTRS.iter().find(|row| row.attr == attr).map(|row| row.prop)
    }

    /// Resolve a property from its ordinal. # C: O(1)
    pub fn from_ordinal(ordinal: u32) -> Option<Property> {
        ATTRS.get(ordinal as usize).map(|row| row.prop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn every_row_sits_at_its_own_ordinal() {
        for (index, row) in ATTRS.iter().enumerate() {
            assert_eq!(row.prop as usize, index, "{:?} is filed at {index}", row.prop);
            assert_eq!(Property::from_ordinal(index as u32), Some(row.prop));
        }
        assert_eq!(PROPERTY_COUNT, 79);
        assert_eq!(Property::from_ordinal(PROPERTY_COUNT as u32), None);
    }

    #[test]
    fn attribute_names_are_unique_and_lowercase() {
        let mut seen: Vec<&str> = ATTRS.iter().map(|row| row.attr).collect();
        let total = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), total, "duplicate attribute name in the table");
        for row in ATTRS {
            assert_eq!(row.attr, row.attr.to_ascii_lowercase(), "{:?}", row.prop);
            assert!(!row.attr.is_empty());
        }
    }

    #[test]
    fn the_attribute_names_a_power_daemon_reads_are_pinned() {
        assert_eq!(Property::Status.attr(), "status");
        assert_eq!(Property::Present.attr(), "present");
        assert_eq!(Property::Online.attr(), "online");
        assert_eq!(Property::Capacity.attr(), "capacity");
        assert_eq!(Property::CapacityLevel.attr(), "capacity_level");
        assert_eq!(Property::VoltageNow.attr(), "voltage_now");
        assert_eq!(Property::CurrentNow.attr(), "current_now");
        assert_eq!(Property::ChargeFullDesign.attr(), "charge_full_design");
        assert_eq!(Property::EnergyFullDesign.attr(), "energy_full_design");
        assert_eq!(Property::CycleCount.attr(), "cycle_count");
        assert_eq!(Property::Temp.attr(), "temp");
        assert_eq!(Property::ModelName.attr(), "model_name");
        assert_eq!(Property::Manufacturer.attr(), "manufacturer");
        assert_eq!(Property::SerialNumber.attr(), "serial_number");
        assert_eq!(Property::Type.attr(), "type");
    }

    #[test]
    fn a_uevent_variable_is_the_upper_cased_attribute_name() {
        assert_eq!(Property::Status.uevent_var(), "POWER_SUPPLY_STATUS");
        assert_eq!(Property::CapacityLevel.uevent_var(), "POWER_SUPPLY_CAPACITY_LEVEL");
        assert_eq!(Property::ChargeFullDesign.uevent_var(), "POWER_SUPPLY_CHARGE_FULL_DESIGN");
        assert_eq!(Property::SerialNumber.uevent_var(), "POWER_SUPPLY_SERIAL_NUMBER");
    }

    #[test]
    fn only_the_three_identity_properties_are_strings() {
        let strings: Vec<Property> = ATTRS.iter()
            .filter(|row| row.kind == Kind::Str)
            .map(|row| row.prop)
            .collect();
        assert_eq!(strings, alloc::vec![
            Property::ModelName, Property::Manufacturer, Property::SerialNumber,
        ]);
    }

    #[test]
    fn the_multi_valued_properties_render_an_availability_list() {
        let available: Vec<Property> = ATTRS.iter()
            .filter(|row| matches!(row.kind, Kind::Available(_)))
            .map(|row| row.prop)
            .collect();
        assert_eq!(available, alloc::vec![
            Property::ChargeTypes, Property::ChargeBehaviour, Property::UsbType,
        ]);
        assert_eq!(Property::ChargeType.kind(), Kind::Enum(CHARGE_TYPE_TEXT));
    }

    #[test]
    fn lookup_by_attribute_name_round_trips() {
        for row in ATTRS {
            assert_eq!(Property::from_attr(row.attr), Some(row.prop));
        }
        assert_eq!(Property::from_attr("uevent"), None);
        assert_eq!(Property::from_attr("STATUS"), None);
    }
}
