// Every rung of the active fast-open ladder, the deferral it turns into when
// `connect` asks, and the property that holds across the whole state
// cross-product: no rung ever refuses the connection.

use super::*;
use crate::tcp_fastopen::{TFO_CLIENT_ENABLE, TFO_CLIENT_NO_COOKIE};

const COOKIE_BYTES: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

fn cookie() -> Cookie { Cookie::minted(COOKIE_BYTES, false) }

fn active(source: Source) -> Active {
    Active {
        bits: TFO_CLIENT_ENABLE, source, sock_no_cookie: false, route_no_cookie: false,
        cached: None, try_exp: false, blackholed: false,
    }
}

#[test]
fn a_write_with_a_cached_cookie_puts_the_data_in_the_syn() {
    let mut a = active(Source::Write);
    a.cached = Some(cookie());
    assert_eq!(decide(&a), Open::Data { cookie: Some(cookie()) });
}

#[test]
fn a_connect_with_a_cached_cookie_sends_no_syn_and_waits_for_the_write() {
    let mut a = active(Source::Connect);
    a.cached = Some(cookie());
    assert_eq!(decide(&a), Open::Defer,
        "there is no payload yet; the SYN is what the first write produces");
    assert_eq!(syn_option(Open::Defer), None, "a deferred open emits no segment at all");
}

#[test]
fn a_cache_miss_asks_for_a_cookie_and_opens_the_ordinary_way() {
    for source in [Source::Connect, Source::Write] {
        let a = active(source);
        assert_eq!(decide(&a), Open::Request { exp: false });
        let option = syn_option(decide(&a)).expect("the SYN carries a cookie request");
        assert!(option.is_request(), "present and empty is the request; absent is silence");
    }
}

#[test]
fn a_cache_miss_that_asked_for_the_experimental_kind_requests_under_it() {
    let mut a = active(Source::Write);
    a.try_exp = true;
    assert_eq!(decide(&a), Open::Request { exp: true });
    assert!(syn_option(decide(&a)).expect("a request").exp);
}

#[test]
fn a_cached_request_is_not_a_cookie_and_falls_through_to_asking_for_one() {
    let mut a = active(Source::Write);
    a.cached = Some(Cookie::request(false));
    assert_eq!(decide(&a), Open::Request { exp: false },
        "an empty cached value records the absence of a cookie, not one to present");
}

#[test]
fn the_namespace_no_cookie_bit_fast_opens_with_no_cookie_at_all() {
    let mut a = active(Source::Write);
    a.bits |= TFO_CLIENT_NO_COOKIE;
    assert_eq!(decide(&a), Open::Data { cookie: None });
    assert_eq!(syn_option(decide(&a)), None,
        "no cookie was minted for this host pair, so the SYN presents none");
}

#[test]
fn the_socket_and_the_route_each_license_a_no_cookie_fast_open_alone() {
    let mut sock = active(Source::Write);
    sock.sock_no_cookie = true;
    assert_eq!(decide(&sock), Open::Data { cookie: None });
    let mut route = active(Source::Write);
    route.route_no_cookie = true;
    assert_eq!(decide(&route), Open::Data { cookie: None });
}

#[test]
fn a_no_cookie_license_outranks_a_cached_cookie() {
    let mut a = active(Source::Write);
    a.sock_no_cookie = true;
    a.cached = Some(cookie());
    assert_eq!(decide(&a), Open::Data { cookie: None });
}

#[test]
fn a_blackholed_path_sends_a_bare_syn_not_even_a_cookie_request() {
    let mut a = active(Source::Write);
    a.cached = Some(cookie());
    a.blackholed = true;
    assert_eq!(decide(&a), Open::Plain);
    assert_eq!(syn_option(Open::Plain), None,
        "the middlebox that ate the last one may have been reacting to the option");
}

#[test]
fn a_blackhole_outranks_every_no_cookie_license() {
    let mut a = active(Source::Connect);
    a.bits |= TFO_CLIENT_NO_COOKIE;
    a.sock_no_cookie = true;
    a.route_no_cookie = true;
    a.blackholed = true;
    assert_eq!(decide(&a), Open::Plain);
}

/// The whole point of the feature: every combination of state opens a working
/// connection. Enumerated rather than sampled, because a rung that refused
/// would be a lost connection and no single case would show it.
#[test]
fn no_combination_of_client_state_ever_refuses_the_connection() {
    let mut seen_plain = false;
    let mut seen_request = false;
    let mut seen_data = false;
    let mut seen_defer = false;
    for bits in [0, TFO_CLIENT_ENABLE, TFO_CLIENT_ENABLE | TFO_CLIENT_NO_COOKIE,
                 TFO_CLIENT_NO_COOKIE] {
        for source in [Source::Connect, Source::Write] {
            for sock_no_cookie in [false, true] {
                for route_no_cookie in [false, true] {
                    for cached in [None, Some(Cookie::request(false)), Some(cookie())] {
                        for try_exp in [false, true] {
                            for blackholed in [false, true] {
                                let a = Active { bits, source, sock_no_cookie, route_no_cookie,
                                    cached, try_exp, blackholed };
                                match decide(&a) {
                                    Open::Plain => seen_plain = true,
                                    Open::Request { .. } => seen_request = true,
                                    Open::Data { cookie } => {
                                        seen_data = true;
                                        assert_eq!(source, Source::Write,
                                            "only a call carrying a payload may put one in the SYN");
                                        assert!(!blackholed, "a paused path never carries data");
                                        assert!(cookie.is_some() || flags::no_cookie(
                                            bits, TFO_CLIENT_NO_COOKIE, sock_no_cookie,
                                            route_no_cookie),
                                            "data with no cookie needs a license for it");
                                    }
                                    Open::Defer => {
                                        seen_defer = true;
                                        assert_eq!(source, Source::Connect,
                                            "a write has the payload in hand; it never defers");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // Every outcome is reachable, so the enumeration above is testing four
    // live arms rather than one arm and three dead ones.
    assert!(seen_plain && seen_request && seen_data && seen_defer);
}

#[test]
fn a_deferred_open_and_a_plain_one_never_carry_data() {
    assert!(!carries_data(Open::Defer));
    assert!(!carries_data(Open::Plain));
    assert!(!carries_data(Open::Request { exp: false }));
    assert!(carries_data(Open::Data { cookie: None }));
}

#[test]
fn a_write_is_refused_only_when_the_host_does_not_do_active_fast_open() {
    assert_eq!(admit_send(TFO_CLIENT_ENABLE, false, false), SendAdmit::Open);
    assert_eq!(admit_send(0, false, false), SendAdmit::Eopnotsupp);
    assert_eq!(admit_send(crate::tcp_fastopen::TFO_SERVER_ENABLE, false, false),
        SendAdmit::Eopnotsupp, "the server half licenses nothing on the client side");
}

#[test]
fn a_write_naming_the_unspecified_address_is_a_disconnect_not_a_destination() {
    assert_eq!(admit_send(TFO_CLIENT_ENABLE, true, false), SendAdmit::Eopnotsupp);
}

#[test]
fn a_second_fast_open_while_one_is_in_flight_reports_ealready() {
    assert_eq!(admit_send(TFO_CLIENT_ENABLE, false, true), SendAdmit::Ealready);
    assert_eq!(admit_send(0, false, true), SendAdmit::Eopnotsupp,
        "the unsupported answer is decided before the in-flight one");
}
