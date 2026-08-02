// What a SYN-ACK teaches: which cookies are kept, when a missing one is
// evidence about the path, and when the data in the SYN has to go out again.

use super::*;

fn cookie() -> Cookie { Cookie::minted([9; 8], false) }

fn synack() -> Synack {
    Synack { syn_fastopen: true, syn_fastopen_exp: false, syn_data: false,
        total_retrans: 0, cookie: None, data_acked: false }
}

#[test]
fn a_cookie_answering_a_request_is_kept() {
    let mut s = synack();
    s.cookie = Some(cookie());
    let out = learn(&s);
    assert_eq!(out.cookie, Some(cookie()));
    assert_eq!(out.try_exp, TRY_EXP_NONE);
    assert!(!out.syn_lost);
}

#[test]
fn a_cookie_nobody_asked_for_is_ignored() {
    let mut s = synack();
    s.syn_fastopen = false;
    s.cookie = Some(cookie());
    assert_eq!(learn(&s).cookie, None,
        "recording it would let any peer seed this host's cache");
}

#[test]
fn an_empty_option_is_not_a_cookie() {
    let mut s = synack();
    s.cookie = Some(Cookie::request(false));
    assert_eq!(learn(&s).cookie, None);
}

#[test]
fn a_request_that_went_unanswered_switches_to_the_other_option_kind() {
    let s = synack();
    assert_eq!(learn(&s).try_exp, TRY_EXP_EXPERIMENTAL,
        "nothing distinguishes a server that will not fast open from a box that ate the option");
    let mut experimental = synack();
    experimental.syn_fastopen_exp = true;
    assert_eq!(learn(&experimental).try_exp, TRY_EXP_ASSIGNED);
}

#[test]
fn the_option_kind_is_only_reconsidered_on_a_first_try_that_carried_no_data() {
    let mut retransmitted = synack();
    retransmitted.total_retrans = 1;
    assert_eq!(learn(&retransmitted).try_exp, TRY_EXP_NONE,
        "a retransmitted SYN carries no option, so its answer says nothing about the kind");
    let mut with_data = synack();
    with_data.syn_data = true;
    assert_eq!(learn(&with_data).try_exp, TRY_EXP_NONE);
}

#[test]
fn data_the_peer_acknowledged_is_a_fast_open_that_worked() {
    let mut s = synack();
    s.syn_data = true;
    s.data_acked = true;
    let out = learn(&s);
    assert!(out.data_acked);
    assert!(!out.failed);
    assert!(!out.syn_lost);
}

#[test]
fn data_the_peer_did_not_take_is_owed_and_goes_out_again() {
    let mut s = synack();
    s.syn_data = true;
    let out = learn(&s);
    assert!(out.failed, "the bytes are still in the retransmit queue");
    assert!(!out.data_acked);
}

#[test]
fn a_fast_open_answered_only_after_a_retransmit_records_the_syn_as_lost() {
    let mut s = synack();
    s.syn_data = true;
    s.total_retrans = 1;
    let out = learn(&s);
    assert!(out.syn_lost, "the peer saw the plain retransmission, not the SYN carrying data");
    assert!(out.failed);
}

#[test]
fn a_retransmit_that_still_produced_a_cookie_is_not_a_lost_syn() {
    let mut s = synack();
    s.syn_data = true;
    s.total_retrans = 1;
    s.cookie = Some(cookie());
    let out = learn(&s);
    assert!(!out.syn_lost);
    assert_eq!(out.cookie, Some(cookie()));
}

#[test]
fn a_connection_that_carried_no_data_never_reports_a_failure() {
    for total_retrans in [0u32, 1, 5] {
        for cookie_back in [None, Some(cookie())] {
            let mut s = synack();
            s.total_retrans = total_retrans;
            s.cookie = cookie_back;
            let out = learn(&s);
            assert!(!out.failed, "no bytes rode the SYN, so none are owed");
            assert!(!out.syn_lost);
        }
    }
}

#[test]
fn the_reason_a_fast_open_did_not_take_is_reportable() {
    use super::super::client::{TFO_DATA_NOT_ACKED, TFO_STATUS_NONE, TFO_SYN_RETRANSMITTED};
    let mut took = synack();
    took.syn_data = true;
    took.data_acked = true;
    assert_eq!(learn(&took).client_fail, TFO_STATUS_NONE);

    let mut not_acked = synack();
    not_acked.syn_data = true;
    assert_eq!(learn(&not_acked).client_fail, TFO_DATA_NOT_ACKED);

    let mut retransmitted = synack();
    retransmitted.syn_data = true;
    retransmitted.total_retrans = 1;
    assert_eq!(learn(&retransmitted).client_fail, TFO_SYN_RETRANSMITTED);
}
