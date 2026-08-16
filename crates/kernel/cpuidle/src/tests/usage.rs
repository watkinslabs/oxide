use super::*;
use crate::state::Entry;

fn state(latency_us: u64, residency_us: u64) -> IdleState {
    IdleState::from_us("C", "", latency_us, residency_us, Entry::Halt)
}

/// POLL, C1 (1 us latency / 1 us residency), C2 (40 / 100), C3 (100 / 400).
fn ladder() -> alloc::vec::Vec<IdleState> {
    alloc::vec![state(0, 0), state(1, 1), state(40, 100), state(100, 400)]
}

#[test]
fn a_sleep_shorter_than_the_state_was_worth_counts_as_too_deep() {
    let states = ladder();
    let usage = new_usage(&states);
    // Entered C2 (worth 100 us) but woke after 50 us.
    assert_eq!(classify(&states, &usage, 2, 50_000), Mispredict::Above);
    // Exactly at the target residency is not a mispredict.
    assert_eq!(classify(&states, &usage, 2, 100_000), Mispredict::None);
}

#[test]
fn the_shallowest_state_can_never_be_too_deep() {
    let states = ladder();
    let usage = new_usage(&states);
    assert_eq!(classify(&states, &usage, 0, 0), Mispredict::None,
               "there was no shallower answer to have chosen");
}

#[test]
fn a_state_with_nothing_shallower_enabled_is_not_a_mispredict() {
    let states = ladder();
    let mut usage = new_usage(&states);
    usage[0].set_user_disable(true);
    usage[1].set_user_disable(true);
    assert_eq!(classify(&states, &usage, 2, 10_000), Mispredict::None);
    usage[1].set_user_disable(false);
    assert_eq!(classify(&states, &usage, 2, 10_000), Mispredict::Above);
}

#[test]
fn a_sleep_long_enough_for_the_next_state_down_counts_as_too_shallow() {
    let states = ladder();
    let usage = new_usage(&states);
    // Entered C2: 40 us to leave, C3 wants 400 us resident. A 500 us sleep
    // leaves 460 us net, which covers C3.
    assert_eq!(classify(&states, &usage, 2, 500_000), Mispredict::Below);
    // 420 us leaves 380 us net, short of C3's 400.
    assert_eq!(classify(&states, &usage, 2, 420_000), Mispredict::None);
}

#[test]
fn the_exit_latency_is_deducted_before_the_deeper_state_is_considered() {
    // Without the deduction a 400 us sleep would look like it covered C3.
    let states = ladder();
    let usage = new_usage(&states);
    assert_eq!(classify(&states, &usage, 2, 400_000), Mispredict::None);
    assert_eq!(classify(&states, &usage, 2, 440_000), Mispredict::Below);
}

#[test]
fn the_deepest_state_can_never_be_too_shallow() {
    let states = ladder();
    let usage = new_usage(&states);
    assert_eq!(classify(&states, &usage, 3, 10_000_000), Mispredict::None);
}

#[test]
fn only_the_nearest_enabled_deeper_state_is_consulted() {
    let states = ladder();
    let mut usage = new_usage(&states);
    // With C3 disabled, a long sleep out of C2 has nowhere deeper to have gone.
    usage[3].set_user_disable(true);
    assert_eq!(classify(&states, &usage, 2, 5_000_000), Mispredict::None);
}

#[test]
fn recording_an_entry_accumulates_the_time_and_the_verdict() {
    let states = ladder();
    let mut usage = new_usage(&states);
    record_entry(&states, &mut usage, 2, 50_000);
    record_entry(&states, &mut usage, 2, 500_000);
    record_entry(&states, &mut usage, 2, 150_000);
    assert_eq!(usage[2].usage, 3);
    assert_eq!(usage[2].time_ns, 700_000);
    assert_eq!(usage[2].above, 1);
    assert_eq!(usage[2].below, 1);
}

#[test]
fn a_refusal_is_attributed_to_the_state_that_was_asked_for() {
    let states = ladder();
    let mut usage = new_usage(&states);
    record_rejection(&mut usage, 3);
    assert_eq!(usage[3].rejected, 1);
    assert_eq!(usage[3].usage, 0, "a refusal is not an entry");
    assert_eq!(usage[3].time_ns, 0);
}

#[test]
fn a_driver_disabled_state_stays_disabled_however_hard_userspace_asks() {
    let mut states = ladder();
    states[3].flags |= crate::uapi::FLAG_UNUSABLE;
    let mut usage = new_usage(&states);
    assert!(!usage[3].enabled());
    assert!(usage[3].driver_disabled());
    usage[3].set_user_disable(false);
    assert!(!usage[3].enabled(), "clearing the user bit must not unpin the driver's");
    assert!(!usage[3].user_disabled());
}

#[test]
fn a_user_disabled_state_reads_back_and_re_enables() {
    let states = ladder();
    let mut usage = new_usage(&states);
    assert!(usage[2].enabled());
    usage[2].set_user_disable(true);
    assert!(!usage[2].enabled() && usage[2].user_disabled());
    usage[2].set_user_disable(false);
    assert!(usage[2].enabled() && !usage[2].user_disabled());
}
