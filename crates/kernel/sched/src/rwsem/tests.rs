// Verified `rw_semaphore` contract. The blocking acquires need a live
// runqueue, so these drive the non-blocking forms — which consult the same
// `read_ok`/`write_ok` gate the blocking ones re-check after every wake — and
// then pin those predicates directly over their whole state space.

use super::*;

#[test]
fn readers_share_and_the_last_one_out_releases() {
    let s: RwSem<u32> = RwSem::new(5);
    let a = s.try_read().expect("an idle semaphore admits a reader");
    let b = s.try_read().expect("a second reader joins the batch");
    assert_eq!(*a, 5);
    assert_eq!(*b, 5);
    assert!(s.is_locked());
    assert!(s.try_write().is_none(), "a writer must not join a live read batch");
    drop(a);
    assert!(s.try_write().is_none(), "one reader remaining still excludes the writer");
    drop(b);
    assert!(!s.is_locked());
    assert!(s.try_write().is_some(), "the last reader out lets the writer in");
}

#[test]
fn a_write_guard_excludes_every_other_acquirer() {
    let s: RwSem<u32> = RwSem::new(0);
    let mut w = s.try_write().expect("an idle semaphore admits a writer");
    *w = 9;
    assert!(s.try_read().is_none(), "no reader may observe a half-written state");
    assert!(s.try_write().is_none(), "writers are exclusive of each other");
    drop(w);
    assert_eq!(*s.try_read().expect("a released semaphore admits a reader"), 9);
}

#[test]
fn a_queued_writer_closes_the_door_on_arriving_readers() {
    // The anti-starvation rung. Without it a stream of readers holds the
    // semaphore indefinitely and the exec-side writer never runs.
    let s: RwSem<()> = RwSem::new(());
    let r = s.try_read().unwrap();
    { let mut g = s.gate.lock(); g.pending += 1; }
    assert!(s.try_read().is_none(), "a queued writer must block an arriving reader");
    drop(r);
    assert!(s.try_read().is_none(), "still blocked while the writer is queued");
    { let mut g = s.gate.lock(); g.pending -= 1; }
    assert!(s.try_read().is_some(), "and admitted once no writer waits");
}

#[test]
fn release_restores_a_fully_idle_gate() {
    let s: RwSem<u8> = RwSem::new(1);
    for _ in 0..4 {
        drop(s.try_write().unwrap());
        drop(s.try_read().unwrap());
    }
    let g = s.gate.lock();
    assert_eq!(g.readers, 0);
    assert!(!g.writer);
    assert_eq!(g.pending, 0);
}

#[test]
fn the_admission_predicates_pin_their_own_rungs() {
    let mut g = Gate::new();
    assert!(g.read_ok() && g.write_ok(), "an idle gate admits either kind");
    g.readers = 1;
    assert!(g.read_ok(), "readers do not exclude readers");
    assert!(!g.write_ok(), "readers exclude writers");
    g.readers = 0;
    g.writer = true;
    assert!(!g.read_ok() && !g.write_ok(), "a writer excludes everyone");
    g.writer = false;
    g.pending = 1;
    assert!(!g.read_ok(), "a queued writer excludes arriving readers");
    assert!(g.write_ok(), "but the semaphore is idle for that writer to take");
}
