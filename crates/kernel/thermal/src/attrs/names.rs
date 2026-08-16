// Attribute names. The trip and binding families are generated per device,
// because how many of each exists is a property of the zone, not of the class.

use alloc::string::String;
use alloc::vec::Vec;

/// Zone: provider-declared kind.
pub const TYPE: &str = "type";
/// Zone: current temperature, millidegrees Celsius.
pub const TEMP: &str = "temp";
/// Zone: whether the zone is being updated.
pub const MODE: &str = "mode";
/// Zone: governor in force.
pub const POLICY: &str = "policy";
/// Zone: every governor that may be selected.
pub const AVAILABLE_POLICIES: &str = "available_policies";

/// Cooling device: deepest supported state.
pub const MAX_STATE: &str = "max_state";
/// Cooling device: state it is in now.
pub const CUR_STATE: &str = "cur_state";
/// Cooling device: accepted transitions.
pub const TOTAL_TRANS: &str = "total_trans";
/// Cooling device: occupancy per state, milliseconds.
pub const TIME_IN_STATE_MS: &str = "time_in_state_ms";
/// Cooling device: transition counts by state pair.
pub const TRANS_TABLE: &str = "trans_table";
/// Cooling device: clear the statistics.
pub const STATS_RESET: &str = "reset";

/// Trip attribute prefix.
pub const TRIP_PREFIX: &str = "trip_point_";
/// Trip attribute suffix: category.
pub const TRIP_TYPE: &str = "type";
/// Trip attribute suffix: temperature.
pub const TRIP_TEMP: &str = "temp";
/// Trip attribute suffix: hysteresis band.
pub const TRIP_HYST: &str = "hyst";

/// Binding link prefix.
pub const CDEV_PREFIX: &str = "cdev";
/// Binding attribute suffix: which trip it cools.
pub const CDEV_TRIP_POINT: &str = "_trip_point";
/// Binding attribute suffix: its share.
pub const CDEV_WEIGHT: &str = "_weight";

/// `trip_point_<index>_<suffix>`. # C: O(1)
pub fn trip_attr(index: usize, suffix: &str) -> String {
    let mut name = String::from(TRIP_PREFIX);
    let _ = core::fmt::Write::write_fmt(&mut name, format_args!("{index}_{suffix}"));
    name
}

/// Split a trip attribute name back into its index and suffix. # C: O(n)
pub fn parse_trip_attr(name: &str) -> Option<(usize, &str)> {
    let rest = name.strip_prefix(TRIP_PREFIX)?;
    let (index, suffix) = rest.split_once('_')?;
    Some((index.parse().ok()?, suffix))
}

/// `cdev<id>`. # C: O(1)
pub fn cdev_link(id: u32) -> String {
    let mut name = String::from(CDEV_PREFIX);
    let _ = core::fmt::Write::write_fmt(&mut name, format_args!("{id}"));
    name
}

/// `cdev<id><suffix>`. # C: O(1)
pub fn cdev_attr(id: u32, suffix: &str) -> String {
    let mut name = cdev_link(id);
    name.push_str(suffix);
    name
}

/// Split a binding attribute name back into its id and suffix. # C: O(n)
pub fn parse_cdev_attr(name: &str) -> Option<(u32, &str)> {
    let rest = name.strip_prefix(CDEV_PREFIX)?;
    let split = rest.find('_')?;
    let (id, suffix) = rest.split_at(split);
    Some((id.parse().ok()?, suffix))
}

/// Every trip attribute of a zone with `count` trips, in trip order.
/// # C: O(N_trips)
pub fn trip_attrs(count: usize) -> Vec<String> {
    let mut names = Vec::with_capacity(count * 3);
    for index in 0..count {
        names.push(trip_attr(index, TRIP_TYPE));
        names.push(trip_attr(index, TRIP_TEMP));
        names.push(trip_attr(index, TRIP_HYST));
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_trip_attribute_name_round_trips() {
        assert_eq!(trip_attr(0, TRIP_TEMP), "trip_point_0_temp");
        assert_eq!(trip_attr(12, TRIP_HYST), "trip_point_12_hyst");
        assert_eq!(parse_trip_attr("trip_point_0_temp"), Some((0, "temp")));
        assert_eq!(parse_trip_attr("trip_point_12_hyst"), Some((12, "hyst")));
        assert_eq!(parse_trip_attr("trip_point_3_type"), Some((3, "type")));
    }

    #[test]
    fn a_name_that_is_not_a_trip_attribute_does_not_parse_as_one() {
        assert_eq!(parse_trip_attr("temp"), None);
        assert_eq!(parse_trip_attr("trip_point_x_temp"), None);
        assert_eq!(parse_trip_attr("trip_point_0"), None);
        assert_eq!(parse_trip_attr(""), None);
    }

    #[test]
    fn a_binding_attribute_name_round_trips_and_the_bare_link_does_not() {
        assert_eq!(cdev_link(0), "cdev0");
        assert_eq!(cdev_attr(2, CDEV_WEIGHT), "cdev2_weight");
        assert_eq!(parse_cdev_attr("cdev2_weight"), Some((2, "_weight")));
        assert_eq!(parse_cdev_attr("cdev0_trip_point"), Some((0, "_trip_point")));
        assert_eq!(parse_cdev_attr("cdev0"), None, "the bare link is not an attribute");
    }

    #[test]
    fn a_zone_publishes_three_attributes_per_trip_in_trip_order() {
        let names = trip_attrs(2);
        assert_eq!(names, alloc::vec![
            "trip_point_0_type", "trip_point_0_temp", "trip_point_0_hyst",
            "trip_point_1_type", "trip_point_1_temp", "trip_point_1_hyst",
        ]);
        assert!(trip_attrs(0).is_empty());
    }
}
