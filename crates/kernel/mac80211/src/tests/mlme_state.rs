// The client state machine: every transition, every timeout, and the
// invariant that exactly one terminal outcome reaches userspace per attempt.
//
// The invariant is the reason this is a state machine and not a sequence of
// calls. A response can arrive after the step that was waiting for it gave
// up, and a machine that reported both would leave a supplicant with a
// connect that succeeded and failed.

use alloc::vec::Vec;

use wireless::ieee80211::status::{reason, status};
use wireless::uapi::enums::timeout_reason;

use crate::limits;
use crate::mlme::state::{MlmeAction, MlmeEvent, MlmeState, MlmeStep};
use crate::tests_fixture as f;

fn started() -> MlmeState {
    let mut m = MlmeState::default();
    let a = m.start(f::AP, Vec::new(), 0, 0);
    assert_eq!(a, MlmeAction::SendAuth);
    m.auth_sent(0);
    m
}

#[test]
fn the_happy_path_walks_every_step_once() {
    let mut m = started();
    assert_eq!(m.step, MlmeStep::Authenticating);
    assert_eq!(m.on_event(MlmeEvent::AuthResp(status::SUCCESS), 0), MlmeAction::SendAssoc);
    assert_eq!(m.step, MlmeStep::Authenticated);
    m.assoc_sent(0);
    assert_eq!(m.step, MlmeStep::Associating);
    let out = m.on_event(MlmeEvent::AssocResp { status: status::SUCCESS, aid: 7 }, 0);
    assert_eq!(out, MlmeAction::Success { bssid: f::AP, aid: 7 });
    assert_eq!(m.step, MlmeStep::Associated);
    assert!(m.is_associated());
    assert_eq!(m.aid, 7);
}

#[test]
fn a_refused_authentication_is_the_single_outcome() {
    let mut m = started();
    let out = m.on_event(MlmeEvent::AuthResp(status::NOT_SUPPORTED_AUTH_ALG), 0);
    assert_eq!(out, MlmeAction::Refused { status: status::NOT_SUPPORTED_AUTH_ALG });
    assert!(out.is_terminal());
    // A late success for the same attempt produces nothing further.
    assert_eq!(m.on_event(MlmeEvent::AuthResp(status::SUCCESS), 0), MlmeAction::None);
    assert_eq!(m.on_event(MlmeEvent::AuthTimeout, 0), MlmeAction::None);
}

#[test]
fn a_refused_association_is_the_single_outcome() {
    let mut m = started();
    m.on_event(MlmeEvent::AuthResp(status::SUCCESS), 0);
    m.assoc_sent(0);
    let out = m.on_event(MlmeEvent::AssocResp { status: status::ASSOC_DENIED_RATES, aid: 0 }, 0);
    assert_eq!(out, MlmeAction::Refused { status: status::ASSOC_DENIED_RATES });
    assert_eq!(m.step, MlmeStep::Authenticated, "the authentication survives a refusal");
    assert_eq!(m.on_event(MlmeEvent::AssocResp { status: status::SUCCESS, aid: 1 }, 0),
               MlmeAction::None);
}

#[test]
fn an_authenticate_is_retried_up_to_its_limit_and_then_gives_up_once() {
    let mut m = started();
    let mut terminals = 0;
    // The first attempt already went out; the machine retries until its
    // limit and then produces exactly one timeout.
    for _ in 0..10 {
        let out = m.on_event(MlmeEvent::AuthTimeout, 0);
        if out.is_terminal() { terminals += 1; }
        if out == MlmeAction::SendAuth { m.auth_sent(0); }
    }
    assert_eq!(terminals, 1, "exactly one terminal outcome per attempt");
    assert_eq!(m.auth_tries, limits::AUTH_MAX_TRIES);
}

#[test]
fn the_authenticate_timeout_reports_the_step_it_ran_out_in() {
    let mut m = started();
    for _ in 1..limits::AUTH_MAX_TRIES {
        assert_eq!(m.on_event(MlmeEvent::AuthTimeout, 0), MlmeAction::SendAuth);
        m.auth_sent(0);
    }
    assert_eq!(m.on_event(MlmeEvent::AuthTimeout, 0),
               MlmeAction::TimedOut { reason: timeout_reason::AUTH });
}

#[test]
fn an_associate_is_retried_and_then_gives_up_once() {
    let mut m = started();
    m.on_event(MlmeEvent::AuthResp(status::SUCCESS), 0);
    m.assoc_sent(0);
    let mut terminals = 0;
    for _ in 0..10 {
        let out = m.on_event(MlmeEvent::AssocTimeout, 0);
        if out.is_terminal() {
            terminals += 1;
            assert_eq!(out, MlmeAction::TimedOut { reason: timeout_reason::ASSOC });
        }
        if out == MlmeAction::SendAssoc { m.assoc_sent(0); }
    }
    assert_eq!(terminals, 1);
    assert_eq!(m.assoc_tries, limits::ASSOC_MAX_TRIES);
}

#[test]
fn a_deadline_is_only_live_while_something_is_outstanding() {
    let mut m = MlmeState::default();
    assert!(!m.expired(u64::MAX), "nothing outstanding cannot expire");
    m.start(f::AP, Vec::new(), 0, 0);
    m.auth_sent(1000);
    assert!(!m.expired(1000 + limits::AUTH_TIMEOUT_NS - 1));
    assert!(m.expired(1000 + limits::AUTH_TIMEOUT_NS));
    m.on_event(MlmeEvent::AuthResp(status::SUCCESS), 0);
    assert!(!m.expired(u64::MAX), "between steps there is no deadline");
}

#[test]
fn a_local_disconnect_before_anything_was_sent_says_nothing_to_the_peer() {
    let mut m = MlmeState::default();
    m.start(f::AP, Vec::new(), 0, 0);
    let out = m.on_event(MlmeEvent::LocalDisconnect, 0);
    assert_eq!(out, MlmeAction::TimedOut { reason: timeout_reason::UNSPECIFIED });
    assert_eq!(m.step, MlmeStep::Idle);
}

#[test]
fn a_local_disconnect_mid_attempt_tells_the_peer() {
    let mut m = started();
    let out = m.on_event(MlmeEvent::LocalDisconnect, 0);
    assert_eq!(out, MlmeAction::SendDeauth { reason: reason::DEAUTH_LEAVING });
    assert_eq!(m.step, MlmeStep::Idle);
}

#[test]
fn a_peer_teardown_mid_attempt_is_the_attempts_outcome() {
    let mut m = started();
    let out = m.on_event(MlmeEvent::Deauth { reason: reason::PREV_AUTH_NOT_VALID }, 0);
    assert_eq!(out, MlmeAction::Refused { status: reason::PREV_AUTH_NOT_VALID });
    assert!(out.is_terminal());
}

#[test]
fn a_peer_teardown_of_an_established_link_is_always_reported() {
    // An association that has already produced its success event still
    // reports the disconnection: it is a new fact, not a second answer to the
    // attempt.
    let mut m = started();
    m.on_event(MlmeEvent::AuthResp(status::SUCCESS), 0);
    m.assoc_sent(0);
    assert!(m.on_event(MlmeEvent::AssocResp { status: status::SUCCESS, aid: 3 }, 0)
             .is_terminal());
    let out = m.on_event(MlmeEvent::Deauth { reason: reason::DEAUTH_LEAVING }, 0);
    assert_eq!(out, MlmeAction::Refused { status: reason::DEAUTH_LEAVING });
    assert!(!m.is_associated());
}

#[test]
fn a_response_for_a_step_that_is_not_running_changes_nothing() {
    let mut m = MlmeState::default();
    assert_eq!(m.on_event(MlmeEvent::AuthResp(status::SUCCESS), 0), MlmeAction::None);
    assert_eq!(m.on_event(MlmeEvent::AssocResp { status: status::SUCCESS, aid: 1 }, 0),
               MlmeAction::None);
    assert_eq!(m.on_event(MlmeEvent::AssocTimeout, 0), MlmeAction::None);
    assert_eq!(m.step, MlmeStep::Idle);
}

#[test]
fn every_terminating_path_produces_exactly_one_outcome() {
    // Drive every ordering of events through a fresh attempt and count the
    // terminal outcomes. None of them may produce two.
    let events = [
        MlmeEvent::AuthResp(status::SUCCESS),
        MlmeEvent::AuthResp(status::UNSPECIFIED_FAILURE),
        MlmeEvent::AuthTimeout,
        MlmeEvent::AssocResp { status: status::SUCCESS, aid: 1 },
        MlmeEvent::AssocResp { status: status::ASSOC_DENIED_RATES, aid: 0 },
        MlmeEvent::AssocTimeout,
        MlmeEvent::LocalDisconnect,
    ];
    for a in events {
        for b in events {
            for c in events {
                let mut m = started();
                let mut terminals = 0;
                for ev in [a, b, c] {
                    let out = m.on_event(ev, 0);
                    match out {
                        MlmeAction::SendAuth => m.auth_sent(0),
                        MlmeAction::SendAssoc => m.assoc_sent(0),
                        _ => {}
                    }
                    // A teardown of an ESTABLISHED link is a disconnection,
                    // not an attempt outcome, and is excluded from the count.
                    let established_teardown = matches!(ev, MlmeEvent::Deauth { .. });
                    if out.is_terminal() && !established_teardown { terminals += 1; }
                }
                assert!(terminals <= 1, "{a:?} {b:?} {c:?} produced {terminals} outcomes");
            }
        }
    }
}

#[test]
fn beacon_loss_is_declared_only_after_the_agreed_number_of_misses() {
    let mut m = started();
    m.on_event(MlmeEvent::AuthResp(status::SUCCESS), 0);
    m.assoc_sent(0);
    m.on_event(MlmeEvent::AssocResp { status: status::SUCCESS, aid: 1 }, 0);
    let interval_tu = 100u16;
    let interval = limits::tu_to_ns(interval_tu as u64);
    m.note_beacon(1_000_000);

    let miss = |n: u32| 1_000_000 + interval * n as u64;
    assert!(!m.beacon_lost(interval_tu, miss(limits::BEACON_LOSS_COUNT - 1)));
    assert!(m.beacon_lost(interval_tu, miss(limits::BEACON_LOSS_COUNT)));
    // Between the probe threshold and the loss threshold a probe goes out
    // rather than a disconnect: a fading link is not a gone one.
    assert!(m.should_probe(interval_tu, miss(limits::PROBE_START_COUNT)));
    assert!(!m.should_probe(interval_tu, miss(limits::BEACON_LOSS_COUNT)));
    // A beacon resets everything.
    m.note_beacon(miss(limits::BEACON_LOSS_COUNT));
    assert!(!m.beacon_lost(interval_tu, miss(limits::BEACON_LOSS_COUNT)));
}

#[test]
fn beacon_loss_is_not_declared_when_not_associated() {
    let mut m = started();
    m.note_beacon(0);
    assert!(!m.beacon_lost(100, u64::MAX));
    assert!(!m.should_probe(100, u64::MAX));
}
