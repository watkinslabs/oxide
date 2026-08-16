use super::*;

#[test]
fn a_firmware_reading_converts_to_millidegrees_celsius() {
    // 300.0 K is 26.85 C.
    assert_eq!(to_millicelsius(3_000, KELVIN_OFFSET_DEFAULT_MC), 26_800);
    // 373.2 K is exactly 100 C under the common offset.
    assert_eq!(to_millicelsius(3_732, KELVIN_OFFSET_DEFAULT_MC), 100_000);
    assert_eq!(to_millicelsius(3_731, KELVIN_OFFSET_ALTERNATE_MC), 100_000);
}

#[test]
fn a_degree_where_a_millidegree_belongs_would_be_a_hundredfold_error() {
    let celsius_scale = to_millicelsius(3_732, KELVIN_OFFSET_DEFAULT_MC);
    assert_eq!(celsius_scale, 100_000);
    assert_ne!(celsius_scale, 100, "a boiling-point trip reported as 100 mC is 0.1 C");
}

#[test]
fn a_reading_outside_what_a_sensor_can_report_is_refused() {
    assert_eq!(to_millicelsius(0, KELVIN_OFFSET_DEFAULT_MC), TEMP_INVALID);
    assert_eq!(to_millicelsius(TEMP_MIN_DECIK - 1, KELVIN_OFFSET_DEFAULT_MC), TEMP_INVALID);
    assert_eq!(to_millicelsius(TEMP_MAX_DECIK + 1, KELVIN_OFFSET_DEFAULT_MC), TEMP_INVALID);
    assert_ne!(to_millicelsius(TEMP_MAX_DECIK, KELVIN_OFFSET_DEFAULT_MC), TEMP_INVALID);
    // The bottom of the plausible firmware range is below freezing, which the
    // second gate then refuses: a trip at or below absolute zero Celsius is a
    // trip no reading can fail to cross.
    assert_eq!(to_millicelsius(TEMP_MIN_DECIK, KELVIN_OFFSET_DEFAULT_MC), TEMP_INVALID);
}

#[test]
fn a_reading_that_converts_to_absolute_zero_or_below_is_refused() {
    // 218.0 K is inside the plausible range but below the kelvin offset.
    assert_eq!(to_millicelsius(2_732, KELVIN_OFFSET_DEFAULT_MC), TEMP_INVALID);
    assert_eq!(to_millicelsius(2_733, KELVIN_OFFSET_DEFAULT_MC), 100);
}

#[test]
fn the_kelvin_offset_is_inferred_from_the_critical_trip() {
    assert_eq!(kelvin_offset_mc(Some(3_731)), KELVIN_OFFSET_ALTERNATE_MC);
    assert_eq!(kelvin_offset_mc(Some(3_732)), KELVIN_OFFSET_DEFAULT_MC);
    assert_eq!(kelvin_offset_mc(None), KELVIN_OFFSET_DEFAULT_MC);
}

#[test]
fn a_cadence_in_tenths_of_a_second_becomes_milliseconds() {
    assert_eq!(deciseconds_to_ms(0), 0);
    assert_eq!(deciseconds_to_ms(10), 1_000);
    assert_eq!(deciseconds_to_ms(600), 60_000);
}

#[test]
fn the_active_trip_object_names_run_from_zero_to_nine() {
    assert_eq!(active_trip_name(0).as_ref().map(|n| &n[..]), Some(&b"_AC0"[..]));
    assert_eq!(active_trip_name(9).as_ref().map(|n| &n[..]), Some(&b"_AC9"[..]));
    assert!(active_trip_name(10).is_none());
    assert_eq!(active_devices_name(3).as_ref().map(|n| &n[..]), Some(&b"_AL3"[..]));
    assert!(active_devices_name(MAX_ACTIVE_TRIPS).is_none());
}
