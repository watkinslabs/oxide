// Every rung of the passive fast-open ladder, and the property that holds
// across all of them: no rung ever refuses the connection.

use super::*;
use crate::addr::Ipv4Addr;
use crate::tcp_conn::fastopen::Cookie;
use crate::tcp_fastopen::{Key, TFO_SERVER_ENABLE};

const KEY: [u8; crate::tcp_fastopen::KEY_LEN] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00];
const OLD: [u8; crate::tcp_fastopen::KEY_LEN] = [
    0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
    0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00];

const NOW: u64 = 1_000_000_000;

fn src() -> IpAddr { IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)) }
fn dst() -> IpAddr { IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)) }

fn ctx() -> KeyCtx { KeyCtx::new(Key::new(KEY), None) }

/// A listener with fast open enabled and room for `qlen` requests.
fn listener(max_qlen: i32) -> FastOpenQueue {
    let queue = FastOpenQueue::new();
    queue.set_max_qlen(max_qlen);
    queue
}

fn syn(option: FastOpen, syn_data: bool) -> Syn {
    Syn {
        bits: TFO_SERVER_ENABLE, option, syn_data,
        sock_no_cookie: false, route_no_cookie: false,
        keys: Some(ctx()), src: src(), dst: dst(),
    }
}

/// The cookie this listener would issue right now.
fn issued(exp: bool) -> Cookie { cookie::gen(&Key::new(KEY), src(), dst(), exp) }

#[test]
fn a_cookie_request_is_answered_with_a_cookie_and_an_ordinary_handshake() {
    let queue = listener(4);
    let out = decide(&queue, &syn(FastOpen::Request { exp: false }, false), NOW);
    assert_eq!(out, Passive::Offer(issued(false)));
    assert_eq!(queue.qlen(), 0, "an offer takes no slot: no data was accepted");
}

#[test]
fn a_cookie_request_under_the_experimental_kind_is_answered_under_it_too() {
    let queue = listener(4);
    let out = decide(&queue, &syn(FastOpen::Request { exp: true }, false), NOW);
    let Passive::Offer(c) = out else { unreachable!("a cookie request is answered") };
    assert!(c.exp, "a peer speaking only the experimental kind would not \
        recognise a reply under the assigned one");
}

#[test]
fn a_valid_cookie_takes_the_data_and_returns_no_cookie() {
    let queue = listener(4);
    let out = decide(&queue, &syn(FastOpen::Cookie(issued(false)), true), NOW);
    assert_eq!(out, Passive::Accept { reply: None },
        "the client's cookie is still current, so there is nothing to hand back");
    assert_eq!(queue.qlen(), 1, "an accepted request is charged against the bound");
}

#[test]
fn a_cookie_under_the_backup_key_is_honoured_and_upgraded() {
    let queue = listener(4);
    let rotated = Syn { keys: Some(KeyCtx::new(Key::new(KEY), Some(Key::new(OLD)))),
        ..syn(FastOpen::Cookie(cookie::gen(&Key::new(OLD), src(), dst(), false)), true) };
    assert_eq!(decide(&queue, &rotated, NOW),
        Passive::Accept { reply: Some(issued(false)) },
        "the data is taken and the client is moved to the current key");
    assert_eq!(queue.qlen(), 1);
}

#[test]
fn the_decision_names_each_tcp_ext_event_at_the_rung_that_caused_it() {
    let queue = listener(1);
    let request = decide_counted(&queue, &syn(FastOpen::Request { exp: false }, false), NOW);
    assert_eq!(request.counters().collect::<alloc::vec::Vec<_>>(),
        alloc::vec![Counter::CookieReqd]);

    let accepted = decide_counted(&queue, &syn(FastOpen::Cookie(issued(false)), true), NOW);
    assert_eq!(accepted.counters().collect::<alloc::vec::Vec<_>>(),
        alloc::vec![Counter::Passive]);

    let overflow = decide_counted(&queue, &syn(FastOpen::Request { exp: false }, false), NOW);
    assert_eq!(overflow.counters().collect::<alloc::vec::Vec<_>>(),
        alloc::vec![Counter::CookieReqd, Counter::ListenOverflow]);

    let failed_queue = listener(1);
    let forged = Cookie::new(&[0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef], false).unwrap();
    let failed = decide_counted(&failed_queue, &syn(FastOpen::Cookie(forged), true), NOW);
    assert_eq!(failed.counters().collect::<alloc::vec::Vec<_>>(), alloc::vec![Counter::PassiveFail]);

    let backup_queue = listener(1);
    let backup = Syn { keys: Some(KeyCtx::new(Key::new(KEY), Some(Key::new(OLD)))),
        ..syn(FastOpen::Cookie(cookie::gen(&Key::new(OLD), src(), dst(), false)), true) };
    let upgraded = decide_counted(&backup_queue, &backup, NOW);
    assert_eq!(upgraded.counters().collect::<alloc::vec::Vec<_>>(),
        alloc::vec![Counter::Passive, Counter::PassiveAltKey]);
}

#[test]
fn a_cookie_that_does_not_verify_gets_a_fresh_one_instead_of_a_refusal() {
    let queue = listener(4);
    let forged = Cookie::new(&[0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef], false)
        .expect("eight bytes is a permitted length");
    assert_eq!(decide(&queue, &syn(FastOpen::Cookie(forged), true), NOW),
        Passive::Offer(issued(false)),
        "the connection proceeds without the data, and the client can fast open next time");
    assert_eq!(queue.qlen(), 0, "nothing was accepted, so nothing is charged");
}

#[test]
fn the_server_bit_gates_everything() {
    let queue = listener(4);
    let off = Syn { bits: 0, ..syn(FastOpen::Request { exp: false }, false) };
    assert_eq!(decide(&queue, &off, NOW), Passive::Decline,
        "with the server half clear not even a cookie is minted");
}

#[test]
fn the_client_bit_alone_does_not_enable_the_server_half() {
    let queue = listener(4);
    let client_only = Syn { bits: crate::tcp_fastopen::TFO_CLIENT_ENABLE,
        ..syn(FastOpen::Request { exp: false }, false) };
    assert_eq!(decide(&queue, &client_only, NOW), Passive::Decline);
}

#[test]
fn a_plain_syn_that_says_nothing_about_fast_open_is_left_alone() {
    let queue = listener(4);
    assert_eq!(decide(&queue, &syn(FastOpen::Absent, false), NOW), Passive::Decline);
    assert_eq!(queue.qlen(), 0);
}

#[test]
fn an_unusable_option_weighs_the_same_as_no_option_at_all() {
    let queue = listener(4);
    // Present but its length cannot be a cookie: the peer meant something,
    // and there is nothing this side can answer.
    assert_eq!(decide(&queue, &syn(FastOpen::Invalid { exp: false }, false), NOW),
        Passive::Decline);
    assert_eq!(decide(&queue, &syn(FastOpen::Invalid { exp: false }, true), NOW),
        Passive::Decline, "data in the SYN does not make an unusable option usable");
}

#[test]
fn data_in_a_syn_with_no_option_is_not_taken() {
    let queue = listener(4);
    assert_eq!(decide(&queue, &syn(FastOpen::Absent, true), NOW), Passive::Decline,
        "nothing proved the peer's address, so the data waits for the handshake");
}

#[test]
fn a_zero_bound_is_the_listener_saying_no() {
    let queue = listener(0);
    assert_eq!(decide(&queue, &syn(FastOpen::Request { exp: false }, false), NOW),
        Passive::Decline, "no queue means not even a cookie request is answered");
}

#[test]
fn a_full_queue_declines_without_minting() {
    let queue = listener(1);
    assert_eq!(decide(&queue, &syn(FastOpen::Cookie(issued(false)), true), NOW),
        Passive::Accept { reply: None });
    assert_eq!(queue.qlen(), 1);
    // The bound is reached. The next SYN gets an ordinary handshake and no
    // cookie at all — a client cannot tell a full queue from a server that
    // does not do fast open.
    assert_eq!(decide(&queue, &syn(FastOpen::Cookie(issued(false)), true), NOW),
        Passive::Decline);
    assert_eq!(decide(&queue, &syn(FastOpen::Request { exp: false }, false), NOW),
        Passive::Decline);
    assert_eq!(queue.qlen(), 1, "a declined SYN charges nothing");
}

#[test]
fn a_finished_handshake_frees_the_slot_it_held() {
    let queue = listener(1);
    assert!(matches!(decide(&queue, &syn(FastOpen::Cookie(issued(false)), true), NOW),
        Passive::Accept { .. }));
    queue.release(NOW, false, false, true);
    assert_eq!(queue.qlen(), 0);
    assert!(matches!(decide(&queue, &syn(FastOpen::Cookie(issued(false)), true), NOW),
        Passive::Accept { .. }), "the bound admits again once the handshake finished");
}

#[test]
fn a_reset_connection_a_program_had_taken_keeps_charging_for_a_minute() {
    let queue = listener(1);
    assert!(matches!(decide(&queue, &syn(FastOpen::Cookie(issued(false)), true), NOW),
        Passive::Accept { .. }));
    queue.release(NOW, true, true, true);
    assert_eq!(queue.qlen(), 1, "the slot is not given back yet");
    assert_eq!(decide(&queue, &syn(FastOpen::Cookie(issued(false)), true), NOW),
        Passive::Decline, "which is what turns a flood of forged SYNs into no fast open");
    // One nanosecond before the penalty runs out it still holds.
    let expiry = NOW + crate::tcp_fastopen::RST_PENALTY_NS;
    assert_eq!(decide(&queue, &syn(FastOpen::Cookie(issued(false)), true), expiry - 1),
        Passive::Decline);
    assert!(matches!(decide(&queue, &syn(FastOpen::Cookie(issued(false)), true), expiry),
        Passive::Accept { .. }), "the penalty is reclaimed by the request that needs it");
    assert_eq!(queue.qlen(), 1, "reclaimed one, charged one");
}

#[test]
fn a_reset_before_the_program_took_the_connection_charges_nothing_extra() {
    let queue = listener(1);
    assert!(matches!(decide(&queue, &syn(FastOpen::Cookie(issued(false)), true), NOW),
        Passive::Accept { .. }));
    queue.release(NOW, true, false, true);
    assert_eq!(queue.qlen(), 0);
}

#[test]
fn a_listener_that_stopped_listening_charges_no_penalty() {
    let queue = listener(1);
    assert!(matches!(decide(&queue, &syn(FastOpen::Cookie(issued(false)), true), NOW),
        Passive::Accept { .. }));
    queue.release(NOW, true, true, false);
    assert_eq!(queue.qlen(), 0);
}

#[test]
fn the_namespace_may_waive_the_cookie_entirely() {
    let queue = listener(4);
    let waived = Syn { bits: TFO_SERVER_ENABLE | crate::tcp_fastopen::TFO_SERVER_COOKIE_NOT_REQD,
        ..syn(FastOpen::Request { exp: false }, true) };
    assert_eq!(decide(&queue, &waived, NOW), Passive::Accept { reply: None },
        "the data is taken and no cookie is minted for it");
    assert_eq!(queue.qlen(), 1);
}

#[test]
fn the_socket_and_the_route_waive_the_cookie_on_their_own() {
    for (sock, route) in [(true, false), (false, true)] {
        let queue = listener(4);
        let waived = Syn { sock_no_cookie: sock, route_no_cookie: route,
            ..syn(FastOpen::Absent, true) };
        assert_eq!(decide(&queue, &waived, NOW), Passive::Accept { reply: None },
            "any one of the three sources is enough");
    }
}

#[test]
fn waiving_the_cookie_does_not_waive_the_queue_bound() {
    let queue = listener(0);
    let waived = Syn { sock_no_cookie: true, ..syn(FastOpen::Absent, true) };
    assert_eq!(decide(&queue, &waived, NOW), Passive::Decline,
        "the bound is asked before the cookie rule, so it still governs");
}

#[test]
fn waiving_the_cookie_needs_no_key_at_all() {
    let queue = listener(4);
    let waived = Syn { sock_no_cookie: true, keys: None, ..syn(FastOpen::Absent, true) };
    assert_eq!(decide(&queue, &waived, NOW), Passive::Accept { reply: None });
}

#[test]
fn a_listener_with_no_key_yet_declines_rather_than_inventing_one() {
    let queue = listener(4);
    let keyless = Syn { keys: None, ..syn(FastOpen::Request { exp: false }, false) };
    assert_eq!(decide(&queue, &keyless, NOW), Passive::Decline);
    let keyless = Syn { keys: None, ..syn(FastOpen::Cookie(issued(false)), true) };
    assert_eq!(decide(&queue, &keyless, NOW), Passive::Decline);
}

#[test]
fn a_listener_key_and_a_namespace_key_mint_different_cookies() {
    let queue = listener(4);
    let own = Syn { keys: Some(KeyCtx::new(Key::new(OLD), None)),
        ..syn(FastOpen::Request { exp: false }, false) };
    let ns = syn(FastOpen::Request { exp: false }, false);
    assert_ne!(decide(&queue, &own, NOW), decide(&queue, &ns, NOW),
        "a listener that named its own key does not mint from the namespace's");
}

#[test]
fn no_rung_of_the_ladder_ever_refuses_the_connection() {
    // The exhaustive statement of the governing property: whatever the state,
    // the answer is one of three, and none of them is a refusal.
    let options = [FastOpen::Absent, FastOpen::Request { exp: false },
        FastOpen::Request { exp: true }, FastOpen::Invalid { exp: false },
        FastOpen::Cookie(issued(false)),
        FastOpen::Cookie(Cookie::new(&[1, 2, 3, 4], false).expect("permitted"))];
    for bits in [0, TFO_SERVER_ENABLE,
                 TFO_SERVER_ENABLE | crate::tcp_fastopen::TFO_SERVER_COOKIE_NOT_REQD] {
        for max in [0, 1, 4] {
            for option in options {
                for syn_data in [false, true] {
                    for keys in [None, Some(ctx())] {
                        let queue = listener(max);
                        let out = decide(&queue,
                            &Syn { bits, keys, ..syn(option, syn_data) }, NOW);
                        assert!(matches!(out, Passive::Decline | Passive::Offer(_)
                            | Passive::Accept { .. }));
                        assert!(queue.qlen() <= max.max(0),
                            "the bound is never exceeded: {bits:x} {max} {option:?}");
                        assert_eq!(matches!(out, Passive::Accept { .. }), queue.qlen() == 1,
                            "a slot is charged exactly when the data is taken");
                    }
                }
            }
        }
    }
}
