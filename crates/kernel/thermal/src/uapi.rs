// Thermal ABI constants: trip categories and their sysfs text, the zone mode
// text, the temperature sentinels, and the "no state requested" marker. The
// numeric trip values are the userspace-visible enumeration, so they are
// pinned here rather than derived from declaration order.

use alloc::string::String;

/// Trip categories, in their ABI order.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum TripType {
    /// Engage a cooling device that can be switched on and off.
    Active = 0,
    /// Slow the load down; the zone polls faster while one is engaged.
    Passive = 1,
    /// The platform wants to leave the running state.
    Hot = 2,
    /// Past this the hardware is being damaged; the machine goes down.
    Critical = 3,
}

/// `active` trip text.
pub const TRIP_TEXT_ACTIVE: &str = "active";
/// `passive` trip text.
pub const TRIP_TEXT_PASSIVE: &str = "passive";
/// `hot` trip text.
pub const TRIP_TEXT_HOT: &str = "hot";
/// `critical` trip text.
pub const TRIP_TEXT_CRITICAL: &str = "critical";

impl TripType {
    /// Text a `trip_point_<n>_type` read returns. # C: O(1)
    pub fn text(self) -> &'static str {
        match self {
            TripType::Active => TRIP_TEXT_ACTIVE,
            TripType::Passive => TRIP_TEXT_PASSIVE,
            TripType::Hot => TRIP_TEXT_HOT,
            TripType::Critical => TRIP_TEXT_CRITICAL,
        }
    }

    /// Whether a crossing of this trip is the governor's business. The two
    /// terminal categories are handled by the zone itself: a governor asked to
    /// cool past them would be choosing a fan speed for a machine that is
    /// already shutting down. # C: O(1)
    pub fn governed(self) -> bool {
        matches!(self, TripType::Active | TripType::Passive)
    }
}

/// Trip flag: userspace may write the temperature.
pub const TRIP_FLAG_RW_TEMP: u8 = 1 << 0;
/// Trip flag: userspace may write the hysteresis.
pub const TRIP_FLAG_RW_HYST: u8 = 1 << 1;

/// "No temperature" sentinel, in millidegrees Celsius. Below absolute zero, so
/// it can never collide with a reading.
pub const TEMP_INVALID: i32 = -274_000;

/// Marker for an instance whose governor has not asked for any cooling.
pub const NO_TARGET: u64 = u64::MAX;

/// Bind-time marker meaning "whatever range the cooling device supports".
pub const NO_LIMIT: u64 = u64::MAX;

/// Zone mode: whether the zone participates in updates at all.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Mode { Disabled, Enabled }

/// `mode` text for an enabled zone.
pub const MODE_TEXT_ENABLED: &str = "enabled";
/// `mode` text for a disabled zone.
pub const MODE_TEXT_DISABLED: &str = "disabled";

impl Mode {
    /// Text a `mode` read returns. # C: O(1)
    pub fn text(self) -> &'static str {
        match self { Mode::Enabled => MODE_TEXT_ENABLED, Mode::Disabled => MODE_TEXT_DISABLED }
    }

    /// Parse a `mode` write. A prefix match, because a shell redirect writes
    /// the word with a newline and a daemon writes it without. # C: O(1)
    pub fn parse(buf: &[u8]) -> Option<Mode> {
        let text = core::str::from_utf8(buf).ok()?;
        if text.starts_with(MODE_TEXT_ENABLED) { return Some(Mode::Enabled); }
        if text.starts_with(MODE_TEXT_DISABLED) { return Some(Mode::Disabled); }
        None
    }
}

/// Which way a trip was crossed.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Direction { Up, Down }

/// Temperature trend between the last two samples.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Trend { Stable, Raising, Dropping }

/// The sysfs class both zones and cooling devices appear under.
pub const CLASS_NAME: &str = "thermal";
/// Zone device-name prefix.
pub const ZONE_PREFIX: &str = "thermal_zone";
/// Cooling-device device-name prefix.
pub const CDEV_PREFIX: &str = "cooling_device";

/// Device name of zone `id`. # C: O(1)
pub fn zone_name(id: u32) -> String {
    let mut name = String::from(ZONE_PREFIX);
    let _ = core::fmt::Write::write_fmt(&mut name, format_args!("{id}"));
    name
}

/// Device name of cooling device `id`. # C: O(1)
pub fn cdev_name(id: u32) -> String {
    let mut name = String::from(CDEV_PREFIX);
    let _ = core::fmt::Write::write_fmt(&mut name, format_args!("{id}"));
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trip_text_is_the_userspace_spelling() {
        assert_eq!(TripType::Active.text(), "active");
        assert_eq!(TripType::Passive.text(), "passive");
        assert_eq!(TripType::Hot.text(), "hot");
        assert_eq!(TripType::Critical.text(), "critical");
    }

    #[test]
    fn only_the_two_coolable_categories_reach_a_governor() {
        assert!(TripType::Active.governed());
        assert!(TripType::Passive.governed());
        assert!(!TripType::Hot.governed(), "a governor must not cool past a hot trip");
        assert!(!TripType::Critical.governed());
    }

    #[test]
    fn the_trip_enumeration_keeps_its_abi_values() {
        assert_eq!(TripType::Active as u32, 0);
        assert_eq!(TripType::Passive as u32, 1);
        assert_eq!(TripType::Hot as u32, 2);
        assert_eq!(TripType::Critical as u32, 3);
    }

    #[test]
    fn mode_round_trips_with_and_without_the_newline_a_shell_adds() {
        assert_eq!(Mode::parse(b"enabled"), Some(Mode::Enabled));
        assert_eq!(Mode::parse(b"enabled\n"), Some(Mode::Enabled));
        assert_eq!(Mode::parse(b"disabled\n"), Some(Mode::Disabled));
        assert_eq!(Mode::parse(b"on"), None);
        assert_eq!(Mode::parse(b""), None);
        assert_eq!(Mode::Enabled.text(), "enabled");
        assert_eq!(Mode::Disabled.text(), "disabled");
    }

    #[test]
    fn the_invalid_temperature_is_below_absolute_zero() {
        assert!(TEMP_INVALID < -273_150, "a real reading must never collide with the sentinel");
    }

    #[test]
    fn device_names_carry_the_class_prefixes() {
        assert_eq!(zone_name(0), "thermal_zone0");
        assert_eq!(zone_name(12), "thermal_zone12");
        assert_eq!(cdev_name(3), "cooling_device3");
    }
}
