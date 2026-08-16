// Fid lifetime — clunk exactly once, never twice, never zero times.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use std::sync::Mutex;

use crate::client::fid::{Fid, FidOwner, FidTable, MAX_FID};
use crate::err::{NpError, NpResult};
use crate::uapi::limits::NOFID;

/// Records what a fid's drop actually did.
struct Recorder {
    clunked: Mutex<Vec<u32>>,
    forgotten: Mutex<Vec<u32>>,
    fail: bool,
}

impl FidOwner for Recorder {
    fn clunk(&self, fid: u32) -> NpResult<()> {
        self.clunked.lock().unwrap().push(fid);
        if self.fail { Err(NpError::Disconnected) } else { Ok(()) }
    }
    fn forget(&self, fid: u32) { self.forgotten.lock().unwrap().push(fid); }
}

fn recorder(fail: bool) -> Arc<Recorder> {
    Arc::new(Recorder { clunked: Mutex::new(Vec::new()), forgotten: Mutex::new(Vec::new()), fail })
}

fn weak(r: &Arc<Recorder>) -> Weak<dyn FidOwner + Send + Sync> {
    let o: Arc<dyn FidOwner + Send + Sync> = r.clone();
    Arc::downgrade(&o)
}

#[test]
fn dropping_a_handle_clunks_it_exactly_once() {
    let r = recorder(false);
    {
        let f = Arc::new(Fid::new(7, 0, weak(&r)));
        let f2 = f.clone();
        drop(f2);
        // A shared clone must NOT clunk: the handle is still in use, and a
        // clunk here frees a server handle another caller is about to address.
        assert!(r.clunked.lock().unwrap().is_empty());
    }
    assert_eq!(&*r.clunked.lock().unwrap(), &[7]);
}

#[test]
fn a_consumed_handle_is_forgotten_not_clunked() {
    let r = recorder(false);
    {
        let f = Fid::new(9, 0, weak(&r));
        // A successful remove destroys the server handle; clunking afterwards
        // addresses a fid the server no longer has, and a server that reissued
        // that number would clunk somebody else's handle.
        f.mark_consumed();
    }
    assert!(r.clunked.lock().unwrap().is_empty());
    assert_eq!(&*r.forgotten.lock().unwrap(), &[9]);
}

#[test]
fn a_failing_clunk_still_ends_the_handles_life() {
    let r = recorder(true);
    { let _f = Fid::new(3, 0, weak(&r)); }
    assert_eq!(&*r.clunked.lock().unwrap(), &[3]);
}

#[test]
fn a_handle_whose_owner_is_gone_drops_silently() {
    let r = recorder(false);
    let w = weak(&r);
    drop(r);
    let _f = Fid::new(1, 0, w);
    // No panic and no use-after-free: the session outlived nothing to tell.
}

#[test]
fn fid_numbers_are_not_reissued_while_live() {
    let t = FidTable::new();
    let mut held = Vec::new();
    for _ in 0..5000 { held.push(t.alloc().unwrap()); }
    let uniq: alloc::collections::BTreeSet<u32> = held.iter().copied().collect();
    assert_eq!(uniq.len(), held.len());
    assert_eq!(t.live_count(), held.len());
    for n in &held { assert!(t.is_live(*n)); }
}

#[test]
fn no_allocated_fid_is_ever_the_no_fid_sentinel() {
    let t = FidTable::new();
    for _ in 0..1000 {
        let n = t.alloc().unwrap();
        assert_ne!(n, NOFID);
        assert!(n <= MAX_FID);
    }
}

#[test]
fn releasing_returns_the_number_to_the_pool() {
    let t = FidTable::new();
    let a = t.alloc().unwrap();
    let b = t.alloc().unwrap();
    assert_ne!(a, b);
    t.release(a);
    assert!(!t.is_live(a));
    assert_eq!(t.live_count(), 1);
}

#[test]
fn handle_state_tracks_open_and_identity() {
    let r = recorder(false);
    let f = Fid::new(2, 1000, weak(&r));
    assert_eq!(f.open_mode(), None);
    assert_eq!(f.iounit(), 0);
    f.set_open(0o2, 8192);
    assert_eq!(f.open_mode(), Some(0o2));
    assert_eq!(f.iounit(), 8192);
    let q = crate::codec::Qid { ty: 0x80, version: 4, path: 5 };
    f.set_qid(q);
    assert_eq!(f.qid(), q);
    assert_eq!(f.uid, 1000);
}
