// The whole engine against the scripted server: encode, register, match,
// decode, retry.

extern crate alloc;
use alloc::vec::Vec;
use alloc::vec;
use alloc::boxed::Box;
use alloc::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::auth::{AuthSys, Cred};
use crate::clnt::RpcClient;
use crate::err::RpcError;
use crate::uapi::{accept_stat, auth_stat, program};
use crate::xdr::Enc;
use crate::xprt::{RpcTimeout, Transport, TransportRef};
use super::server::{reply_accept_err, reply_auth_err, reply_ok, Call, Handler, ScriptedServer};

/// A clock that never moves — every test that does not exercise the schedule
/// wants the reply to arrive before any deadline can.
fn frozen() -> u64 { 0 }

// Clocks that advance on every READ, so the retransmission schedule walks
// forward deterministically as the engine polls it. One per test rather than
// one shared: tests run concurrently, and a shared clock would make each
// test's schedule depend on which others happen to be running.
static DGRAM_TICK: AtomicU64 = AtomicU64::new(0);
fn dgram_now() -> u64 { DGRAM_TICK.fetch_add(6_000_000_000, Ordering::Relaxed) }
static STREAM_TICK: AtomicU64 = AtomicU64::new(0);
fn stream_now() -> u64 { STREAM_TICK.fetch_add(70_000_000_000, Ordering::Relaxed) }

fn client(srv: &Arc<ScriptedServer>, now: crate::clnt::NowNs) -> Arc<RpcClient> {
    let xprt: TransportRef = srv.clone();
    RpcClient::new(program::NFS, 3, xprt,
                   Cred::Sys(AuthSys::new("oxide", 0, 0)), RpcTimeout::TCP, 100, now)
}

fn echo_handler() -> Handler {
    Box::new(|c: &Call| Some(reply_ok(c.xid, &c.args)))
}

#[test]
fn a_call_reaches_the_server_and_its_results_come_back() {
    let srv = ScriptedServer::new(echo_handler());
    let c = client(&srv, frozen);
    let r = c.call(6, |e| e.u32(0xCAFE)).unwrap();
    assert_eq!(r.results(), &[0, 0, 0xCA, 0xFE]);
    assert_eq!(srv.call_count(), 1);
    assert_eq!(srv.call(0).proc_.proc_num, 6);
}

#[test]
fn the_credential_the_client_was_built_with_reaches_the_server() {
    let srv = ScriptedServer::new(echo_handler());
    let c = client(&srv, frozen);
    c.call(1, |_| Ok(())).unwrap();
    assert_eq!(srv.call(0).cred, Cred::Sys(AuthSys::new("oxide", 0, 0)));
}

#[test]
fn a_replaced_credential_is_used_by_the_next_call() {
    let srv = ScriptedServer::new(echo_handler());
    let c = client(&srv, frozen);
    c.call(1, |_| Ok(())).unwrap();
    c.set_cred(Cred::Sys(AuthSys::new("oxide", 1000, 100)));
    c.call(1, |_| Ok(())).unwrap();
    match srv.call(1).cred {
        Cred::Sys(s) => assert_eq!((s.uid, s.gid), (1000, 100)),
        other => panic!("expected AUTH_SYS, got {other:?}"),
    }
}

#[test]
fn every_call_takes_a_fresh_xid() {
    let srv = ScriptedServer::new(echo_handler());
    let c = client(&srv, frozen);
    for _ in 0..4 { c.call(1, |_| Ok(())).unwrap(); }
    let xids: Vec<u32> = (0..4).map(|i| srv.call(i).xid).collect();
    let mut sorted = xids.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), 4, "xids reused: {xids:?}");
}

#[test]
fn the_xid_slot_is_released_once_the_call_finishes() {
    let srv = ScriptedServer::new(echo_handler());
    let c = client(&srv, frozen);
    c.call(1, |_| Ok(())).unwrap();
    assert_eq!(c.in_flight(), 0);
}

#[test]
fn a_reply_carrying_someone_elses_xid_is_never_matched_to_this_call() {
    // The server answers with a DIFFERENT xid. If the matching layer routed by
    // arrival order instead of by xid, this call would take that record as its
    // own answer and return another operation's results.
    let srv = ScriptedServer::new(Box::new(|c: &Call| {
        Some(reply_ok(c.xid.wrapping_add(1), b"\xFF\xFF\xFF\xFF"))
    }));
    let c = client(&srv, frozen);
    assert_eq!(c.call(1, |_| Ok(())), Err(RpcError::Timeout));
}

#[test]
fn an_unsolicited_record_is_dropped_rather_than_delivered() {
    let srv = ScriptedServer::new(echo_handler());
    let c = client(&srv, frozen);
    srv.inject(&reply_ok(0xDEAD, b"\x00\x00\x00\x01"));
    let r = c.call(1, |e| e.u32(7)).unwrap();
    assert_eq!(r.results(), &[0, 0, 0, 7]);
}

#[test]
fn a_duplicate_reply_after_the_call_completed_is_harmless() {
    let srv = ScriptedServer::new(echo_handler());
    let c = client(&srv, frozen);
    let r = c.call(1, |e| e.u32(3)).unwrap();
    srv.inject(&reply_ok(r.xid, b"\xFF\xFF\xFF\xFF"));
    assert_eq!(r.results(), &[0, 0, 0, 3]);
    assert_eq!(c.in_flight(), 0);
}

#[test]
fn a_credential_the_server_aged_out_is_retried_then_reported() {
    // A stale session must not surface as a permission error the application
    // cannot act on — but a server that will never accept it must be reported
    // rather than hammered.
    let seen = Arc::new(AtomicU32::new(0));
    let s2 = seen.clone();
    let srv = ScriptedServer::new(Box::new(move |c: &Call| {
        s2.fetch_add(1, Ordering::Relaxed);
        Some(reply_auth_err(c.xid, auth_stat::REJECTEDCRED))
    }));
    let c = client(&srv, frozen);
    assert_eq!(c.call(1, |_| Ok(())), Err(RpcError::AuthError(auth_stat::REJECTEDCRED)));
    assert_eq!(seen.load(Ordering::Relaxed), 1 + crate::clnt::MAX_CRED_RETRY);
}

#[test]
fn a_credential_that_recovers_on_retry_succeeds_transparently() {
    let n = Arc::new(AtomicU32::new(0));
    let n2 = n.clone();
    let srv = ScriptedServer::new(Box::new(move |c: &Call| {
        if n2.fetch_add(1, Ordering::Relaxed) == 0 {
            Some(reply_auth_err(c.xid, auth_stat::REJECTEDCRED))
        } else {
            Some(reply_ok(c.xid, b"\x00\x00\x00\x2A"))
        }
    }));
    let c = client(&srv, frozen);
    assert_eq!(c.call(1, |_| Ok(())).unwrap().results(), &[0, 0, 0, 0x2A]);
    assert_eq!(n.load(Ordering::Relaxed), 2);
}

#[test]
fn garbled_arguments_are_retried_then_reported() {
    let n = Arc::new(AtomicU32::new(0));
    let n2 = n.clone();
    let srv = ScriptedServer::new(Box::new(move |c: &Call| {
        n2.fetch_add(1, Ordering::Relaxed);
        Some(reply_accept_err(c.xid, accept_stat::GARBAGE_ARGS, &[]))
    }));
    let c = client(&srv, frozen);
    assert_eq!(c.call(1, |_| Ok(())), Err(RpcError::GarbageArgs));
    assert_eq!(n.load(Ordering::Relaxed), 1 + crate::clnt::MAX_GARBAGE_RETRY);
}

#[test]
fn a_retry_is_sent_under_a_new_xid_not_the_old_one() {
    // Resending the same bytes would leave two live copies of one call at the
    // server, and a reply to the first would be matched to the second.
    let srv = ScriptedServer::new(Box::new(|c: &Call| {
        Some(reply_accept_err(c.xid, accept_stat::GARBAGE_ARGS, &[]))
    }));
    let c = client(&srv, frozen);
    let _ = c.call(1, |_| Ok(()));
    let xids: Vec<u32> = (0..srv.call_count()).map(|i| srv.call(i).xid).collect();
    let mut u = xids.clone();
    u.sort_unstable();
    u.dedup();
    assert_eq!(u.len(), xids.len(), "retry reused an xid: {xids:?}");
}

#[test]
fn a_permanent_refusal_is_reported_without_retrying() {
    let n = Arc::new(AtomicU32::new(0));
    let n2 = n.clone();
    let srv = ScriptedServer::new(Box::new(move |c: &Call| {
        n2.fetch_add(1, Ordering::Relaxed);
        Some(reply_auth_err(c.xid, auth_stat::TOOWEAK))
    }));
    let c = client(&srv, frozen);
    assert_eq!(c.call(1, |_| Ok(())), Err(RpcError::AuthError(auth_stat::TOOWEAK)));
    assert_eq!(n.load(Ordering::Relaxed), 1);
}

#[test]
fn a_program_the_server_does_not_export_is_reported_without_retrying() {
    let srv = ScriptedServer::new(Box::new(|c: &Call| {
        Some(reply_accept_err(c.xid, accept_stat::PROG_UNAVAIL, &[]))
    }));
    let c = client(&srv, frozen);
    assert_eq!(c.call(1, |_| Ok(())), Err(RpcError::ProgUnavail));
    assert_eq!(srv.call_count(), 1);
}

#[test]
fn a_dead_transport_fails_every_later_call() {
    let srv = ScriptedServer::new(echo_handler());
    let c = client(&srv, frozen);
    c.call(1, |_| Ok(())).unwrap();
    srv.kill();
    assert!(c.is_dead());
    assert_eq!(c.call(1, |_| Ok(())), Err(RpcError::Disconnected));
}

#[test]
fn a_disconnect_wakes_and_fails_the_outstanding_call() {
    let srv = ScriptedServer::new(Box::new(|_: &Call| None));
    let c = client(&srv, frozen);
    let sink: Arc<dyn crate::xprt::RecordSink> = c.clone();
    sink.disconnect();
    assert_eq!(c.call(1, |_| Ok(())), Err(RpcError::Disconnected));
}

#[test]
fn arguments_too_large_for_the_transport_never_reach_the_wire() {
    struct Tiny(Arc<ScriptedServer>);
    impl Transport for Tiny {
        fn attach_sink(&self, s: alloc::sync::Weak<dyn crate::xprt::RecordSink>) {
            self.0.attach_sink(s)
        }
        fn send(&self, m: &[u8]) -> crate::err::RpcResult<()> { self.0.send(m) }
        fn max_record(&self) -> usize { 64 }
        fn retransmits(&self) -> bool { false }
        fn is_connected(&self) -> bool { true }
    }
    let srv = ScriptedServer::new(echo_handler());
    let xprt: TransportRef = Arc::new(Tiny(srv.clone()));
    let c = RpcClient::new(program::NFS, 3, xprt, Cred::Null, RpcTimeout::TCP, 1, frozen);
    let big = vec![0u8; 256];
    assert_eq!(c.call(1, |e| e.opaque(&big)), Err(RpcError::MsgTooLarge));
    assert_eq!(srv.call_count(), 0);
}

#[test]
fn a_datagram_transport_resends_an_unanswered_call_until_the_budget_runs_out() {
    // Nothing beneath a datagram transport resends a lost call. A client that
    // waits without retransmitting hangs for the whole budget and then reports
    // a loss a resend would have recovered.
    let srv = ScriptedServer::datagram(Box::new(|_: &Call| None));
    let xprt: TransportRef = srv.clone();
    let c = RpcClient::new(program::NFS, 3, xprt, Cred::Null, RpcTimeout::UDP, 1, dgram_now);
    assert_eq!(c.call(1, |_| Ok(())), Err(RpcError::Timeout));
    assert!(srv.call_count() > 1, "no retransmission: {} sends", srv.call_count());
}

#[test]
fn a_stream_transport_never_resends_a_non_idempotent_call() {
    // TCP retransmits beneath us. A second copy of a rename or an exclusive
    // create on a connection that already holds the first is a duplicate
    // execution, not a recovery.
    let srv = ScriptedServer::new(Box::new(|_: &Call| None));
    let xprt: TransportRef = srv.clone();
    let c = RpcClient::new(program::NFS, 3, xprt, Cred::Null, RpcTimeout::TCP, 1, stream_now);
    assert_eq!(c.call(1, |_| Ok(())), Err(RpcError::Timeout));
    assert_eq!(srv.call_count(), 1);
}

#[test]
fn an_encode_failure_leaves_no_xid_behind() {
    let srv = ScriptedServer::new(echo_handler());
    let c = client(&srv, frozen);
    let _ = c.call_once(1, &|_: &mut Enc| Err(RpcError::NoMemory));
    assert_eq!(c.in_flight(), 0);
}
