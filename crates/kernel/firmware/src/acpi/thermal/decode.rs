// Firmware temperature and cadence decoding.
//
// Firmware reports temperature in tenths of a kelvin and cadences in tenths of
// a second; the thermal class works in millidegrees Celsius and milliseconds.
// The conversions are here, ungated, because a temperature converted with the
// wrong offset is a trip point a few degrees away from where the platform
// intended and nothing else will notice.

use thermal::TEMP_INVALID;

/// Millidegrees per tenth of a degree.
pub const MILLI_PER_DECI: i64 = 100;

/// Kelvin offset the conversion assumes by default, in millidegrees. Firmware
/// overwhelmingly uses 273.2 K as its zero.
pub const KELVIN_OFFSET_DEFAULT_MC: i64 = 273_200;
/// The other offset in use, 273.1 K.
pub const KELVIN_OFFSET_ALTERNATE_MC: i64 = 273_100;

/// Coldest temperature a firmware reading may plausibly be, deci-kelvin
/// (218 K, about -55 C).
pub const TEMP_MIN_DECIK: u64 = 2_180;
/// Hottest, deci-kelvin (448 K, about 175 C).
pub const TEMP_MAX_DECIK: u64 = 4_480;

/// Which kelvin offset this platform's firmware uses.
///
/// Inferred from the critical trip, which is the one value every thermal zone
/// declares. Firmware that computed it with 273.1 as its zero leaves a
/// residue of one in five tenths of a degree; firmware using 273.2 does not.
/// A platform declaring no usable critical trip gets the common offset, which
/// is what a wrong guess would cost a tenth of a degree anyway. # C: O(1)
pub fn kelvin_offset_mc(critical_decik: Option<u64>) -> i64 {
    match critical_decik {
        Some(value) if value % 5 == 1 => KELVIN_OFFSET_ALTERNATE_MC,
        _ => KELVIN_OFFSET_DEFAULT_MC,
    }
}

/// Convert a firmware temperature to millidegrees Celsius, refusing one
/// outside the range a real sensor can report. A reading that survives the
/// conversion but lands at or below absolute zero is refused too: it would
/// otherwise become a trip point no temperature can fail to cross. # C: O(1)
pub fn to_millicelsius(decik: u64, offset_mc: i64) -> i32 {
    if !(TEMP_MIN_DECIK..=TEMP_MAX_DECIK).contains(&decik) { return TEMP_INVALID; }
    let millicelsius = decik as i64 * MILLI_PER_DECI - offset_mc;
    if millicelsius <= 0 { return TEMP_INVALID; }
    i32::try_from(millicelsius).unwrap_or(TEMP_INVALID)
}

/// Milliseconds from the tenths of a second firmware reports a cadence in.
/// # C: O(1)
pub fn deciseconds_to_ms(deciseconds: u64) -> u64 { deciseconds.saturating_mul(100) }

/// Most active trip levels the firmware object names can express: `_AC0`
/// through `_AC9`.
pub const MAX_ACTIVE_TRIPS: usize = 10;

/// Object name of active trip level `index`, or `None` past the last one the
/// naming scheme can reach. # C: O(1)
pub fn active_trip_name(index: usize) -> Option<[u8; 4]> {
    if index >= MAX_ACTIVE_TRIPS { return None; }
    Some([b'_', b'A', b'C', b'0' + index as u8])
}

/// Object name of the device list for active trip level `index`. # C: O(1)
pub fn active_devices_name(index: usize) -> Option<[u8; 4]> {
    if index >= MAX_ACTIVE_TRIPS { return None; }
    Some([b'_', b'A', b'L', b'0' + index as u8])
}

#[cfg(test)]
#[path = "decode_tests.rs"]
mod tests;
