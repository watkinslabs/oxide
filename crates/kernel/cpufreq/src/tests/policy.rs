use super::*;
use crate::table::FreqEntry;

const HW: Limits = Limits { min: 800_000, max: 2_400_000 };

fn requests(user: Request, platform: Request, thermal: Request)
    -> alloc::vec::Vec<(LimitSource, Request)>
{
    alloc::vec![
        (LimitSource::User, user),
        (LimitSource::Platform, platform),
        (LimitSource::Thermal, thermal),
    ]
}

fn table() -> FreqTable {
    FreqTable::new(alloc::vec![
        FreqEntry::new(2_400_000, 0), FreqEntry::new(1_800_000, 1),
        FreqEntry::new(1_200_000, 2), FreqEntry::new(800_000, 3),
    ]).expect("table")
}

fn policy() -> alloc::sync::Arc<Policy> {
    Policy::new(alloc::vec![0], table(), 10_000, 1_200_000, "schedutil").expect("policy")
}

#[test]
fn with_nothing_constraining_the_limits_are_the_hardware_range() {
    assert_eq!(aggregate(HW, &requests(Request::default(), Request::default(),
                                       Request::default())), HW);
}

#[test]
fn the_tightest_ceiling_wins_and_the_others_are_not_lost() {
    let limits = aggregate(HW, &requests(
        Request { min: None, max: Some(2_000_000) },
        Request { min: None, max: Some(1_800_000) },
        Request { min: None, max: Some(2_200_000) },
    ));
    assert_eq!(limits.max, 1_800_000, "a thermal cap must not be released by a user write");
    assert_eq!(limits.min, HW.min);
}

#[test]
fn the_highest_floor_wins() {
    let limits = aggregate(HW, &requests(
        Request { min: Some(1_000_000), max: None },
        Request { min: Some(1_400_000), max: None },
        Request::default(),
    ));
    assert_eq!(limits.min, 1_400_000);
}

#[test]
fn a_floor_above_the_effective_ceiling_is_pulled_down_to_it() {
    let limits = aggregate(HW, &requests(
        Request { min: Some(2_400_000), max: None },
        Request::default(),
        Request { min: None, max: Some(1_200_000) },
    ));
    assert_eq!(limits.max, 1_200_000,
               "the cap is the half that must hold; exceeding it damages hardware");
    assert_eq!(limits.min, 1_200_000);
    assert!(limits.min <= limits.max);
}

#[test]
fn cooling_requests_for_sibling_processors_are_aggregated_independently() {
    let policy = policy();
    policy.set_thermal_request(0, Request { min: None, max: Some(1_800_000) });
    policy.set_thermal_request(1, Request { min: None, max: Some(1_200_000) });
    assert_eq!(policy.limits().max, 1_200_000);
    policy.set_thermal_request(0, Request::default());
    assert_eq!(policy.limits().max, 1_200_000,
               "releasing one processor cannot release its sibling's thermal cap");
    policy.set_thermal_request(1, Request::default());
    assert_eq!(policy.limits().max, HW.max);
}

#[test]
fn a_request_outside_the_hardware_range_cannot_widen_it() {
    let limits = aggregate(HW, &requests(
        Request { min: Some(100_000), max: Some(9_000_000) },
        Request::default(), Request::default(),
    ));
    assert_eq!(limits, HW);
}

#[test]
fn one_source_releasing_its_request_leaves_the_others_in_force() {
    let policy = policy();
    policy.set_request(LimitSource::Thermal, Request { min: None, max: Some(1_200_000) });
    policy.set_request(LimitSource::User, Request { min: None, max: Some(1_800_000) });
    assert_eq!(policy.limits().max, 1_200_000);

    policy.set_request(LimitSource::User, Request::default());
    assert_eq!(policy.limits().max, 1_200_000, "the thermal cap survives the user releasing");

    policy.set_request(LimitSource::Thermal, Request::default());
    assert_eq!(policy.limits().max, HW.max);
}

#[test]
fn a_recorded_request_reads_back_unchanged() {
    let policy = policy();
    let request = Request { min: Some(1_000_000), max: Some(2_000_000) };
    policy.set_request(LimitSource::Platform, request);
    assert_eq!(policy.request(LimitSource::Platform), request);
    assert_eq!(policy.request(LimitSource::Thermal), Request::default());
}

#[test]
fn a_resolution_honours_the_aggregated_limits() {
    let policy = policy();
    policy.set_request(LimitSource::Thermal, Request { min: None, max: Some(1_200_000) });
    assert_eq!(policy.resolve(2_400_000, crate::uapi::Relation::Lowest), Some(1_200_000));
    assert_eq!(policy.resolve(800_000, crate::uapi::Relation::Lowest), Some(800_000));
}

#[test]
fn the_cpu_list_is_space_separated_with_no_trailing_space() {
    assert_eq!(Policy::cpu_list(&[0]), "0\n");
    assert_eq!(Policy::cpu_list(&[0, 1, 2, 3]), "0 1 2 3\n");
    assert_eq!(Policy::cpu_list(&[]), "\n");
}

#[test]
fn a_policy_starts_at_the_hardware_range_and_the_frequency_it_was_built_with() {
    let policy = policy();
    assert_eq!(policy.hw, HW);
    assert_eq!(policy.limits(), HW);
    assert_eq!(policy.cur(), 1_200_000);
    assert_eq!(policy.governor(), "schedutil");
    assert!(!policy.boost());
    assert_eq!(policy.setspeed(), None);
}

#[test]
fn a_suspend_opp_is_resolved_against_the_limits_in_force() {
    let policy = Policy::new_with_suspend(alloc::vec![0], table(), 10_000, 1_200_000, Some(3), "schedutil").expect("policy");
    assert_eq!(policy.suspend_freq(), Some(800_000));
    assert_eq!(policy.suspend_target_index(), Some(3));
    policy.set_request(LimitSource::Platform, Request { min: Some(1_800_000), max: None });
    assert_eq!(policy.suspend_target_index(), Some(1));
    assert!(Policy::new_with_suspend(alloc::vec![0], table(), 10_000, 1_200_000, Some(4), "schedutil").is_none());
}
