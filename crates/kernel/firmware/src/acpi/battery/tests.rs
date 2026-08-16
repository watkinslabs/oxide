use alloc::string::String;
use power_supply::{CapacityLevel, Property, PropVal, Status, Technology};
use vfs::VfsError;

use super::decode::{Info, State, STATE_CHARGE_LIMITING, STATE_CHARGING, STATE_CRITICAL,
                    STATE_DISCHARGING, VALUE_UNKNOWN};
use super::props::{capacity_level, capacity_percent, device_name, get, is_charged, properties,
                   status, technology, Reading};

/// A milliamp-hour battery: 5000 mAh design, 4800 mAh measured full.
fn charge_info() -> Info {
    Info {
        power_unit_ma: true,
        design_capacity: 5000,
        full_charge_capacity: 4800,
        design_voltage: 11_400,
        design_capacity_warning: 480,
        design_capacity_low: 240,
        cycle_count: 143,
        model_number: String::from("OXP-1"),
        serial_number: String::from("SN123"),
        battery_type: String::from("LIon"),
        oem_info: String::from("OxideCorp"),
    }
}

/// A milliwatt-hour battery.
fn energy_info() -> Info {
    Info { power_unit_ma: false, design_capacity: 60_000, full_charge_capacity: 57_000,
           ..charge_info() }
}

fn discharging() -> State {
    State { state: STATE_DISCHARGING, rate_now: 1200, capacity_now: 3500, voltage_now: 11_000 }
}

fn reading<'a>(info: &'a Info, state: &'a State) -> Reading<'a> {
    Reading { present: true, info, state, alarm: Some(info.design_capacity_warning),
              system_supplied: false }
}

#[test]
fn the_chemistry_string_maps_case_insensitively() {
    assert_eq!(technology("NiCd"), Technology::NiCd);
    assert_eq!(technology("nicd"), Technology::NiCd);
    assert_eq!(technology("NIMH"), Technology::NiMh);
    assert_eq!(technology("LIon"), Technology::LiIon);
    assert_eq!(technology("Li-Ion"), Technology::LiIon);
    assert_eq!(technology("li-ion 2"), Technology::LiIon, "a suffixed type is still Li-ion");
    assert_eq!(technology("LiP"), Technology::LiPoly);
    assert_eq!(technology("Unobtanium"), Technology::Unknown);
    assert_eq!(technology(""), Technology::Unknown);
}

#[test]
fn the_status_ladder_follows_the_state_bits() {
    let info = charge_info();
    assert_eq!(status(&info, &discharging(), false), Status::Discharging);
    let charging = State { state: STATE_CHARGING, rate_now: 900, ..discharging() };
    assert_eq!(status(&info, &charging, false), Status::Charging);
    let stalled = State { state: STATE_CHARGING, rate_now: 0, ..discharging() };
    assert_eq!(status(&info, &stalled, false), Status::NotCharging,
               "charging at zero rate is not charging");
    let limited = State { state: STATE_CHARGE_LIMITING, ..discharging() };
    assert_eq!(status(&info, &limited, false), Status::NotCharging);
    let idle = State { state: 0, rate_now: 0, capacity_now: 4800, voltage_now: 11_400 };
    assert_eq!(status(&info, &idle, false), Status::Full);
    let idle_partial = State { capacity_now: 2000, ..idle };
    assert_eq!(status(&info, &idle_partial, false), Status::NotCharging);
}

#[test]
fn a_docked_machine_is_not_discharging_at_zero_rate() {
    let info = charge_info();
    let stalled = State { state: STATE_DISCHARGING, rate_now: 0, ..discharging() };
    assert_eq!(status(&info, &stalled, false), Status::Discharging);
    assert_eq!(status(&info, &stalled, true), Status::NotCharging,
               "mains connected and no current means it is not draining");
    // A real discharge rate still reads as discharging even on mains.
    assert_eq!(status(&info, &discharging(), true), Status::Discharging);
}

#[test]
fn a_battery_is_charged_only_when_nothing_is_happening_to_it() {
    let info = charge_info();
    assert!(is_charged(&info, &State { state: 0, rate_now: 0, capacity_now: 4800,
                                       voltage_now: 11_400 }));
    assert!(!is_charged(&info, &State { state: STATE_CHARGING, rate_now: 0, capacity_now: 4800,
                                        voltage_now: 11_400 }));
    assert!(!is_charged(&info, &State { state: 0, rate_now: 0, capacity_now: 0,
                                        voltage_now: 11_400 }));
    assert!(!is_charged(&info, &State { state: 0, rate_now: 0, capacity_now: VALUE_UNKNOWN,
                                        voltage_now: 11_400 }));
    // A charge at or past the design figure counts even when the measured
    // full-charge figure disagrees.
    assert!(is_charged(&info, &State { state: 0, rate_now: 0, capacity_now: 5200,
                                       voltage_now: 11_400 }));
}

#[test]
fn the_percentage_rounds_to_nearest_against_the_measured_full_charge() {
    let info = charge_info();
    assert_eq!(capacity_percent(&info, &discharging()), Some(73));
    let full = State { capacity_now: 4800, ..discharging() };
    assert_eq!(capacity_percent(&info, &full), Some(100));
    let empty = State { capacity_now: 0, ..discharging() };
    assert_eq!(capacity_percent(&info, &empty), Some(0));
    // 24 / 4800 = 0.5% rounds up, 23 rounds down.
    assert_eq!(capacity_percent(&info, &State { capacity_now: 24, ..discharging() }), Some(1));
    assert_eq!(capacity_percent(&info, &State { capacity_now: 23, ..discharging() }), Some(0));
    let unknown = State { capacity_now: VALUE_UNKNOWN, ..discharging() };
    assert_eq!(capacity_percent(&info, &unknown), None);
}

#[test]
fn the_percentage_falls_back_to_the_design_capacity() {
    let info = Info { full_charge_capacity: VALUE_UNKNOWN, ..charge_info() };
    // 3500 / 5000 = 70%.
    assert_eq!(capacity_percent(&info, &discharging()), Some(70));
    let broken = Info { design_capacity: 0, ..info };
    assert_eq!(capacity_percent(&broken, &discharging()), None);
}

#[test]
fn the_firmware_critical_flag_outranks_the_alarm_threshold() {
    let info = charge_info();
    let critical = State { state: STATE_DISCHARGING | STATE_CRITICAL, ..discharging() };
    assert_eq!(capacity_level(&info, &critical, Some(480)), CapacityLevel::Critical);
    let low = State { capacity_now: 400, ..discharging() };
    assert_eq!(capacity_level(&info, &low, Some(480)), CapacityLevel::Low);
    assert_eq!(capacity_level(&info, &low, None), CapacityLevel::Normal,
               "no trip point means no low report");
    assert_eq!(capacity_level(&info, &discharging(), Some(480)), CapacityLevel::Normal);
    let charged = State { state: 0, rate_now: 0, capacity_now: 4800, voltage_now: 11_400 };
    assert_eq!(capacity_level(&info, &charged, Some(480)), CapacityLevel::Full);
}

#[test]
fn the_unit_the_firmware_reports_in_selects_the_property_family() {
    let charge = properties(&charge_info());
    assert!(charge.contains(&Property::CurrentNow));
    assert!(charge.contains(&Property::ChargeFullDesign));
    assert!(charge.contains(&Property::ChargeFull));
    assert!(charge.contains(&Property::ChargeNow));
    assert!(!charge.contains(&Property::PowerNow));
    assert!(!charge.contains(&Property::EnergyNow));

    let energy = properties(&energy_info());
    assert!(energy.contains(&Property::PowerNow));
    assert!(energy.contains(&Property::EnergyFullDesign));
    assert!(energy.contains(&Property::EnergyNow));
    assert!(!energy.contains(&Property::CurrentNow));
    assert!(!energy.contains(&Property::ChargeNow));

    for family in [charge, energy] {
        assert!(family.contains(&Property::Status));
        assert!(family.contains(&Property::Capacity));
        assert!(family.contains(&Property::CapacityLevel));
        assert!(family.contains(&Property::ModelName));
        assert!(!family.contains(&Property::Online), "a battery is not a mains supply");
    }
}

#[test]
fn a_battery_with_no_usable_full_charge_publishes_no_percentage() {
    let info = Info { design_capacity: 0, full_charge_capacity: VALUE_UNKNOWN, ..charge_info() };
    let props = properties(&info);
    assert!(!props.contains(&Property::Capacity),
            "a percentage that cannot be computed must not be published");
    assert!(!props.contains(&Property::CapacityLevel));
    assert!(!props.contains(&Property::ChargeFull));
    assert!(!props.contains(&Property::ChargeFullDesign));
    assert!(props.contains(&Property::ChargeNow), "the raw charge is still known");
    assert!(props.contains(&Property::Status));
}

#[test]
fn readings_are_published_in_the_class_micro_units() {
    let info = charge_info();
    let state = discharging();
    let reading = reading(&info, &state);
    assert_eq!(get(&reading, Property::VoltageNow), Ok(PropVal::Int(11_000_000)));
    assert_eq!(get(&reading, Property::VoltageMinDesign), Ok(PropVal::Int(11_400_000)));
    assert_eq!(get(&reading, Property::CurrentNow), Ok(PropVal::Int(1_200_000)));
    assert_eq!(get(&reading, Property::ChargeNow), Ok(PropVal::Int(3_500_000)));
    assert_eq!(get(&reading, Property::ChargeFull), Ok(PropVal::Int(4_800_000)));
    assert_eq!(get(&reading, Property::ChargeFullDesign), Ok(PropVal::Int(5_000_000)));
    assert_eq!(get(&reading, Property::Capacity), Ok(PropVal::Int(73)),
               "the percentage is not scaled");
    assert_eq!(get(&reading, Property::CycleCount), Ok(PropVal::Int(143)));
    assert_eq!(get(&reading, Property::ModelName), Ok(PropVal::Str(String::from("OXP-1"))));
    assert_eq!(get(&reading, Property::SerialNumber), Ok(PropVal::Str(String::from("SN123"))));
    assert_eq!(get(&reading, Property::Manufacturer), Ok(PropVal::Str(String::from("OxideCorp"))));
}

#[test]
fn a_field_the_firmware_did_not_report_is_enodev() {
    let info = Info { design_voltage: VALUE_UNKNOWN, full_charge_capacity: 0, ..charge_info() };
    let state = State { voltage_now: VALUE_UNKNOWN, rate_now: VALUE_UNKNOWN, ..discharging() };
    let reading = reading(&info, &state);
    assert_eq!(get(&reading, Property::VoltageMinDesign), Err(VfsError::Enodev));
    assert_eq!(get(&reading, Property::VoltageNow), Err(VfsError::Enodev));
    assert_eq!(get(&reading, Property::CurrentNow), Err(VfsError::Enodev));
    assert_eq!(get(&reading, Property::ChargeFull), Err(VfsError::Enodev),
               "a zero full-charge capacity is not a reading");
    assert_eq!(get(&reading, Property::Present), Ok(PropVal::Int(1)));
}

#[test]
fn an_absent_battery_answers_only_whether_it_is_there() {
    let info = charge_info();
    let state = State::default();
    let absent = Reading { present: false, info: &info, state: &state, alarm: None,
                           system_supplied: false };
    assert_eq!(get(&absent, Property::Present), Ok(PropVal::Int(0)));
    for prop in [Property::Status, Property::Capacity, Property::VoltageNow,
                 Property::ModelName, Property::CapacityLevel] {
        assert_eq!(get(&absent, prop), Err(VfsError::Enodev),
                   "{prop:?} must not answer from a stale reading");
    }
}

#[test]
fn a_property_this_provider_does_not_answer_is_einval() {
    let info = charge_info();
    let state = discharging();
    assert_eq!(get(&reading(&info, &state), Property::Online), Err(VfsError::Einval));
    assert_eq!(get(&reading(&info, &state), Property::Temp), Err(VfsError::Einval));
}

#[test]
fn the_class_name_comes_from_the_firmware_object_name() {
    assert_eq!(device_name("\\_SB.PCI0.BAT0"), "BAT0");
    assert_eq!(device_name("\\_SB.BAT1"), "BAT1");
    assert_eq!(device_name("\\_SB.AC__"), "AC");
    assert_eq!(device_name("BAT0"), "BAT0");
}
