// Tag occupancy — the contract that makes a reply belong to its request.

use alloc::vec::Vec;

use crate::client::req::{ReqStatus, Request};
use crate::client::tags::{TagTable, MAX_TAG};
use crate::err::NpError;
use crate::uapi::limits::NOTAG;

fn mk(tag: u16) -> Request { Request::new(tag, 0, alloc::vec![0u8; 7]) }

#[test]
fn a_tag_is_never_handed_out_while_its_request_is_outstanding() {
    let t = TagTable::new();
    let mut held = Vec::new();
    for _ in 0..1000 { held.push(t.alloc(mk).unwrap()); }
    let mut seen = alloc::collections::BTreeSet::new();
    for r in &held {
        assert!(seen.insert(r.tag), "tag {} issued twice while in flight", r.tag);
        assert!(t.is_live(r.tag));
    }
    assert_eq!(t.in_flight(), 1000);
}

#[test]
fn a_released_tag_becomes_available_again() {
    let t = TagTable::new();
    let a = t.alloc(mk).unwrap();
    let tag = a.tag;
    t.release(tag);
    assert!(!t.is_live(tag));
    assert_eq!(t.in_flight(), 0);
    // Exhausting the space forces the freed tag to come back around, proving
    // release actually returned it rather than retiring it.
    let mut held = Vec::new();
    for _ in 0..=MAX_TAG as u32 { held.push(t.alloc(mk).unwrap()); }
    assert!(held.iter().any(|r| r.tag == tag));
}

#[test]
fn the_search_skips_live_tags_rather_than_overwriting_one() {
    let t = TagTable::new();
    let a = t.alloc(mk).unwrap();
    let b = t.alloc(mk).unwrap();
    let c = t.alloc(mk).unwrap();
    // Free the middle one; the rotating cursor is past it, so allocating again
    // must wrap and find it without disturbing `a` or `c`.
    t.release(b.tag);
    let mut found = false;
    let mut held = Vec::new();
    for _ in 0..(MAX_TAG as u32 + 1) {
        match t.alloc(mk) {
            Ok(r) => { if r.tag == b.tag { found = true; } held.push(r); }
            Err(NpError::NoTags) => break,
            Err(e) => panic!("{e:?}"),
        }
    }
    assert!(found, "the freed tag was never reissued");
    assert!(t.is_live(a.tag));
    assert!(t.is_live(c.tag));
}

#[test]
fn exhausting_the_tag_space_fails_instead_of_reusing() {
    let t = TagTable::new();
    let mut held = Vec::new();
    for _ in 0..=MAX_TAG as u32 { held.push(t.alloc(mk).unwrap()); }
    assert_eq!(t.in_flight(), MAX_TAG as usize + 1);
    assert_eq!(t.alloc(mk).unwrap_err(), NpError::NoTags);
    // NOTAG is a separate slot and is unaffected by ordinary exhaustion.
    let v = t.alloc_notag(mk).unwrap();
    assert_eq!(v.tag, NOTAG);
}

#[test]
fn no_ordinary_tag_can_ever_be_the_reserved_one() {
    let t = TagTable::new();
    let mut held = Vec::new();
    for _ in 0..=MAX_TAG as u32 {
        let r = t.alloc(mk).unwrap();
        assert_ne!(r.tag, NOTAG);
        held.push(r);
    }
}

#[test]
fn only_one_version_handshake_may_be_outstanding() {
    let t = TagTable::new();
    let first = t.alloc_notag(mk).unwrap();
    assert_eq!(first.tag, NOTAG);
    assert_eq!(t.alloc_notag(mk).unwrap_err(), NpError::NoTags);
    t.release(NOTAG);
    assert!(t.alloc_notag(mk).is_ok());
}

#[test]
fn lookup_finds_a_live_tag_and_misses_a_freed_one() {
    let t = TagTable::new();
    let r = t.alloc(mk).unwrap();
    assert!(t.lookup(r.tag).is_some());
    t.release(r.tag);
    // A late or duplicate reply looks exactly like this and must be dropped.
    assert!(t.lookup(r.tag).is_none());
}

#[test]
fn draining_returns_every_outstanding_request_including_the_handshake() {
    let t = TagTable::new();
    let a = t.alloc(mk).unwrap();
    let b = t.alloc(mk).unwrap();
    let v = t.alloc_notag(mk).unwrap();
    let drained = t.drain();
    assert_eq!(drained.len(), 3);
    assert_eq!(t.in_flight(), 0);
    let tags: Vec<u16> = drained.iter().map(|r| r.tag).collect();
    for want in [a.tag, b.tag, v.tag] { assert!(tags.contains(&want)); }
}

#[test]
fn a_reply_is_published_before_the_status_that_advertises_it() {
    let r = Request::new(1, 0, alloc::vec![]);
    r.set_status(ReqStatus::Sent);
    assert!(r.complete(b"\x07\x00\x00\x00\x65\x01\x00"));
    assert_eq!(r.status(), ReqStatus::Received);
    assert_eq!(&*r.rc.lock(), b"\x07\x00\x00\x00\x65\x01\x00");
}

#[test]
fn a_reply_arriving_after_a_flush_is_discarded() {
    let r = Request::new(1, 0, alloc::vec![]);
    r.set_status(ReqStatus::Sent);
    r.set_status(ReqStatus::Flushed);
    // The tag has already been released and may belong to somebody else; this
    // frame must not become anyone's reply.
    assert!(!r.complete(b"late"));
    assert!(r.rc.lock().is_empty());
    assert_eq!(r.status(), ReqStatus::Flushed);
}

#[test]
fn a_second_reply_for_one_request_is_ignored() {
    let r = Request::new(1, 0, alloc::vec![]);
    r.set_status(ReqStatus::Sent);
    assert!(r.complete(b"first"));
    assert!(!r.complete(b"second"));
    assert_eq!(&*r.rc.lock(), b"first");
}

#[test]
fn every_terminal_status_orders_above_received() {
    assert!(ReqStatus::Received.is_terminal());
    assert!(ReqStatus::Flushed.is_terminal());
    assert!(ReqStatus::Errored.is_terminal());
    assert!(!ReqStatus::Allocated.is_terminal());
    assert!(!ReqStatus::Unsent.is_terminal());
    assert!(!ReqStatus::Sent.is_terminal());
}
