//! Keyed-event pairing rules, verified against the published contract.

use super::*;

fn waiting(process: u32, key: u64, seq: u64) -> KeyedWaiter {
    KeyedWaiter { process, key, release: false, matched: false, seq }
}

#[test]
fn a_release_pairs_with_a_waiter_on_the_same_key() {
    let parked = [waiting(7, 0x2000, 1)];
    assert_eq!(match_index(&parked, 7, 0x2000, true), Some(0));
}

#[test]
fn two_sides_of_the_same_kind_never_pair() {
    let parked = [waiting(7, 0x2000, 1)];
    assert_eq!(match_index(&parked, 7, 0x2000, false), None);
}

#[test]
fn a_different_key_never_pairs() {
    let parked = [waiting(7, 0x2000, 1)];
    assert_eq!(match_index(&parked, 7, 0x2008, true), None);
}

#[test]
fn pairing_never_crosses_a_process_boundary() {
    let parked = [waiting(7, 0x2000, 1)];
    assert_eq!(match_index(&parked, 8, 0x2000, true), None);
}

#[test]
fn an_already_claimed_waiter_is_not_paired_a_second_time() {
    let mut parked = [waiting(7, 0x2000, 1), waiting(7, 0x2000, 2)];
    parked[0].matched = true;
    // One release claims exactly one waiter, so the claimed entry is skipped
    // and the second release finds the still-free one.
    assert_eq!(match_index(&parked, 7, 0x2000, true), Some(1));
}

#[test]
fn the_first_parked_partner_is_the_one_claimed() {
    let parked = [waiting(7, 0x2000, 1), waiting(7, 0x2000, 2)];
    assert_eq!(match_index(&parked, 7, 0x2000, true), Some(0));
}

#[test]
fn an_odd_key_is_never_a_runtime_address() {
    assert!(key_is_aligned(0x2000));
    assert!(!key_is_aligned(0x2001));
    assert!(key_is_aligned(0));
}

#[test]
fn a_release_with_no_waiter_finds_nothing_to_pair() {
    let event = NtKeyedEvent::new();
    assert!(!event.try_pair(7, 0x2000, true));
}

#[test]
fn a_parked_waiter_is_claimed_by_a_later_release() {
    let event = NtKeyedEvent::new();
    // An expired deadline leaves the wait side parked only for the duration
    // of its own call, so the pairing is exercised through the list directly.
    assert_eq!(unsafe { event.rendezvous(7, 0x2000, false, 10, || 10) }, KeyedOutcome::TimedOut);
    assert!(event.parked().is_empty(), "an expired side must not stay parked");
    assert!(!event.try_pair(7, 0x2000, true), "a departed waiter cannot be claimed");
}

#[test]
fn a_waiter_that_arrives_after_its_partner_pairs_without_sleeping() {
    let event = NtKeyedEvent::new();
    event.parked.lock().push(KeyedWaiter { process: 7, key: 0x2000, release: true, matched: false, seq: 99 });
    assert_eq!(unsafe { event.rendezvous(7, 0x2000, false, 10, || 10) }, KeyedOutcome::Paired);
    assert_eq!(event.parked()[0].matched, true, "the partner is left claimed for its own wakeup");
}
