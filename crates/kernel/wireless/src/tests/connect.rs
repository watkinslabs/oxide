// The connect state machine.
//
// The invariant every test here defends: exactly ONE terminal outcome reaches
// userspace per connect attempt — a result or a disconnect, never both and
// never neither. A supplicant that gets two acts twice; one that gets none
// waits forever.

extern crate alloc;

use crate::ieee80211::mgmt::auth_alg;
use crate::ieee80211::status::status;
use crate::ieee80211::MacAddr;
use crate::sme::{alg_for_auth_type, ConnAction, ConnState, ConnStep, Conn, ConnectParams,
                 ConnectResult, MAX_CONN_SCANS};
use crate::uapi::enums::{auth_type, timeout_reason};

const AP: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0xaa]);
const AP2: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0xbb]);

fn params() -> ConnectParams {
    ConnectParams { ssid: b"net".to_vec(), auth_type: auth_type::OPEN_SYSTEM,
                    ..Default::default() }
}

/// Drive an attempt to its terminal step, collecting every action taken.
/// Panics rather than looping forever if the machine does not terminate.
fn run(conn: &mut Conn, mut respond: impl FnMut(&mut Conn, &ConnAction) -> bool)
    -> alloc::vec::Vec<ConnAction>
{
    let mut actions = alloc::vec::Vec::new();
    for _ in 0..32 {
        let action = conn.action();
        actions.push(action.clone());
        if matches!(action, ConnAction::Report(_)) { return actions; }
        if !respond(conn, &action) { return actions; }
    }
    panic!("the connect state machine did not terminate");
}

#[test]
fn the_happy_path_runs_scan_authenticate_associate_and_stops_connected() {
    let mut c = Conn::new(params());
    assert_eq!(c.step, ConnStep::Scanning);
    let actions = run(&mut c, |c, a| match a {
        ConnAction::Scan => { c.scan_found(AP); true }
        ConnAction::Authenticate { bssid, alg } => {
            assert_eq!(*bssid, AP);
            assert_eq!(*alg, auth_alg::OPEN);
            c.auth_sent();
            assert_eq!(c.step, ConnStep::Authenticating);
            c.auth_response(status::SUCCESS);
            true
        }
        ConnAction::Associate { bssid } => {
            assert_eq!(*bssid, AP);
            c.assoc_sent();
            assert_eq!(c.step, ConnStep::Associating);
            c.assoc_response(status::SUCCESS);
            true
        }
        ConnAction::None => false,
        other => panic!("unexpected {other:?}"),
    });
    assert_eq!(c.step, ConnStep::Connected);
    assert!(c.is_terminal());
    assert!(matches!(actions.last(), Some(ConnAction::None)));
}

#[test]
fn a_scan_that_finds_nothing_is_retried_once_and_then_abandoned() {
    let mut c = Conn::new(params());
    let actions = run(&mut c, |c, a| match a {
        ConnAction::Scan => { c.scan_missed(); true }
        _ => true,
    });
    let scans = actions.iter().filter(|a| matches!(a, ConnAction::Scan)).count();
    assert_eq!(scans as u32, MAX_CONN_SCANS);
    assert_eq!(c.step, ConnStep::Abandon);
    assert!(c.is_terminal());
    assert!(matches!(actions.last(),
        Some(ConnAction::Report(ConnectResult::TimedOut {
            reason: timeout_reason::UNSPECIFIED }))));
}

#[test]
fn an_automatic_request_retries_the_other_algorithm_exactly_once() {
    // This is the whole reason the automatic authentication type exists: the
    // open algorithm is tried first because every network accepts it, and the
    // shared-key algorithm only if that is refused.
    let mut c = Conn::new(ConnectParams { auth_type: auth_type::AUTOMATIC, ..params() });
    assert!(c.params.auto_auth);
    assert_eq!(c.auth_alg, auth_alg::OPEN);
    c.scan_found(AP);
    c.auth_sent();
    c.auth_response(status::NOT_SUPPORTED_AUTH_ALG);
    assert_eq!(c.step, ConnStep::AuthenticateNext);
    assert_eq!(c.auth_alg, auth_alg::SHARED_KEY);
    // A second refusal is final.
    c.auth_sent();
    c.auth_response(status::NOT_SUPPORTED_AUTH_ALG);
    assert_eq!(c.step, ConnStep::AssocFailed);
    assert!(c.is_terminal());
}

#[test]
fn a_pinned_algorithm_is_not_retried_with_another() {
    let mut c = Conn::new(ConnectParams { auth_type: auth_type::SHARED_KEY, ..params() });
    assert!(!c.params.auto_auth);
    assert_eq!(c.auth_alg, auth_alg::SHARED_KEY);
    c.scan_found(AP);
    c.auth_sent();
    c.auth_response(status::CHALLENGE_FAIL);
    assert_eq!(c.step, ConnStep::AssocFailed);
    assert_eq!(c.auth_alg, auth_alg::SHARED_KEY);
}

#[test]
fn each_authentication_type_maps_to_its_own_algorithm() {
    assert_eq!(alg_for_auth_type(auth_type::OPEN_SYSTEM), auth_alg::OPEN);
    assert_eq!(alg_for_auth_type(auth_type::SHARED_KEY), auth_alg::SHARED_KEY);
    assert_eq!(alg_for_auth_type(auth_type::FT), auth_alg::FT);
    assert_eq!(alg_for_auth_type(auth_type::SAE), auth_alg::SAE);
    assert_eq!(alg_for_auth_type(auth_type::NETWORK_EAP), auth_alg::NETWORK_EAP);
    assert_eq!(alg_for_auth_type(auth_type::FILS_SK), auth_alg::FILS_SK);
    // An automatic request starts with the algorithm every network accepts.
    assert_eq!(alg_for_auth_type(auth_type::AUTOMATIC), auth_alg::OPEN);
}

#[test]
fn each_timeout_reports_the_step_that_ran_out_of_time() {
    let mut c = Conn::new(params());
    c.scan_found(AP);
    c.auth_sent();
    c.auth_timeout();
    assert_eq!(c.action(),
        ConnAction::Report(ConnectResult::TimedOut { reason: timeout_reason::AUTH }));

    let mut c = Conn::new(params());
    c.scan_found(AP);
    c.auth_sent();
    c.auth_response(status::SUCCESS);
    c.assoc_sent();
    c.assoc_timeout();
    assert_eq!(c.action(),
        ConnAction::Report(ConnectResult::TimedOut { reason: timeout_reason::ASSOC }));
}

#[test]
fn a_refused_association_reports_a_refusal_and_not_a_timeout() {
    let mut c = Conn::new(params());
    c.scan_found(AP);
    c.auth_sent();
    c.auth_response(status::SUCCESS);
    c.assoc_sent();
    c.assoc_response(status::AP_UNABLE_TO_HANDLE_NEW_STA);
    assert_eq!(c.step, ConnStep::AssocFailed);
    assert!(matches!(c.action(), ConnAction::Report(ConnectResult::Refused { .. })));
}

#[test]
fn a_local_disconnect_before_the_exchange_sends_nothing() {
    // There is nothing to deauthenticate from before the authentication
    // exchange has started, and sending one would be a frame to a station
    // that has never heard from us.
    for step in [ConnStep::Scanning, ConnStep::ScanAgain, ConnStep::AuthenticateNext] {
        let mut c = Conn::new(params());
        c.step = step;
        c.local_disconnect();
        assert_eq!(c.step, ConnStep::Abandon, "from {step:?}");
        assert!(matches!(c.action(), ConnAction::Report(_)));
    }
}

#[test]
fn a_local_disconnect_after_the_exchange_started_tears_it_down() {
    for step in [ConnStep::Authenticating, ConnStep::AssociateNext, ConnStep::Associating,
                 ConnStep::Connected] {
        let mut c = Conn::new(params());
        c.bssid = AP;
        c.step = step;
        c.local_disconnect();
        assert_eq!(c.step, ConnStep::Deauth, "from {step:?}");
        assert_eq!(c.action(), ConnAction::Deauthenticate {
            bssid: AP,
            reason: crate::ieee80211::status::reason::DEAUTH_LEAVING,
        });
    }
}

#[test]
fn a_request_that_pins_an_address_starts_from_it() {
    let c = Conn::new(ConnectParams { bssid: Some(AP), ..params() });
    assert_eq!(c.bssid, AP);
    // A hint is used the same way when no address is pinned.
    let c = Conn::new(ConnectParams { bssid_hint: Some(AP2), ..params() });
    assert_eq!(c.bssid, AP2);
    // A pinned address wins over a hint.
    let c = Conn::new(ConnectParams { bssid: Some(AP), bssid_hint: Some(AP2), ..params() });
    assert_eq!(c.bssid, AP);
    // With neither, the scan supplies it.
    let c = Conn::new(params());
    assert_eq!(c.bssid, MacAddr::ZERO);
}

#[test]
fn a_reassociation_carries_the_previous_network_through() {
    let c = Conn::new(ConnectParams { prev_bssid: Some(AP2), ..params() });
    assert_eq!(c.prev_bssid, Some(AP2));
}

#[test]
fn a_second_connect_is_refused_while_one_is_live_or_a_link_is_up() {
    let mut s = ConnState::default();
    assert!(s.can_connect());
    s.conn = Some(Conn::new(params()));
    assert!(!s.can_connect(), "an attempt with a pending outcome is not replaced");
    s.conn = None;
    s.connected = true;
    assert!(!s.can_connect());
    s.disconnected();
    assert!(s.can_connect());
}

#[test]
fn associating_records_the_link_and_disconnecting_forgets_all_of_it() {
    let mut s = ConnState::default();
    s.note_authenticated(AP);
    assert!(s.is_authenticated(AP));
    assert!(!s.is_authenticated(AP2));
    // Recording the same peer twice does not duplicate it.
    s.note_authenticated(AP);
    assert_eq!(s.authenticated.len(), 1);

    s.conn = Some(Conn::new(params()));
    s.associated(AP, 7, b"req".to_vec(), b"resp".to_vec(), true);
    assert_eq!(s.current_bssid, Some(AP));
    assert!(s.connected);
    assert!(s.port_authorized);
    assert_eq!(s.aid, 7);
    assert_eq!(s.req_ie, b"req");
    assert_eq!(s.resp_ie, b"resp");
    assert!(s.conn.is_none(), "the attempt is over once it produced its outcome");

    s.disconnected();
    assert_eq!(s.current_bssid, None);
    assert!(!s.connected);
    assert!(!s.port_authorized);
    assert_eq!(s.aid, 0);
    assert!(s.req_ie.is_empty());
    assert!(s.resp_ie.is_empty());
    assert!(s.authenticated.is_empty());
}

#[test]
fn an_association_with_userspace_key_management_leaves_the_port_shut() {
    let mut s = ConnState::default();
    s.associated(AP, 1, alloc::vec::Vec::new(), alloc::vec::Vec::new(), false);
    assert!(s.connected);
    assert!(!s.port_authorized,
        "data must not flow until the key exchange userspace runs completes");
}

#[test]
fn every_reachable_step_produces_exactly_one_outcome_or_waits_for_a_frame() {
    // Nothing may sit in a step that neither acts nor terminates.
    for step in [ConnStep::Scanning, ConnStep::ScanAgain, ConnStep::AuthenticateNext,
                 ConnStep::Authenticating, ConnStep::AuthFailedTimeout,
                 ConnStep::AssociateNext, ConnStep::Associating, ConnStep::AssocFailed,
                 ConnStep::AssocFailedTimeout, ConnStep::Deauth, ConnStep::Abandon,
                 ConnStep::Connected] {
        let mut c = Conn::new(params());
        c.step = step;
        let a = c.action();
        let terminal = matches!(a, ConnAction::Report(_));
        assert_eq!(terminal, c.is_terminal() && !matches!(step, ConnStep::Connected),
            "step {step:?} produced {a:?}");
        // A waiting step is only ever one of the two that wait for a frame.
        if matches!(a, ConnAction::None) {
            assert!(matches!(step, ConnStep::Authenticating | ConnStep::Associating
                                   | ConnStep::Connected), "step {step:?} waits");
        }
    }
}
