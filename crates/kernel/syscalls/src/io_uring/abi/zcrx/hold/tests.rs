use super::*;

#[test]
fn a_registered_instance_has_exactly_one_user() {
    let h = UserHold::new();
    assert_eq!(h.count(), 1);
}

/// The close happens once, on the transition to zero, and the ring that
/// registered the instance is the one that reaches it when nobody adopted it.
#[test]
fn the_last_user_is_the_only_one_told_to_close() {
    let h = UserHold::new();
    assert!(h.put());
    assert_eq!(h.count(), 0);
}

/// An adopted instance survives its exporter going away: the adopter is still
/// a user, so the queue stays bound.
#[test]
fn an_adopted_instance_outlives_its_exporter() {
    let h = UserHold::new();
    assert!(h.get());
    assert_eq!(h.count(), 2);
    assert!(!h.put(), "the exporter leaving must not close a queue the adopter still uses");
    assert_eq!(h.count(), 1);
    assert!(h.put(), "the adopter leaving closes it");
}

/// A doubled release must not close the queue twice: the second one would run
/// against a binding that was already torn down.
#[test]
fn a_doubled_release_never_closes_twice() {
    let h = UserHold::new();
    assert!(h.put());
    assert!(!h.put());
    assert!(!h.put());
    assert_eq!(h.count(), 0);
}

/// Adopting an instance whose last user already left must fail rather than
/// resurrect it: its queue is closed and its buffers reclaimed, so the adopter
/// would be handed something that can never deliver a packet.
#[test]
fn a_closed_instance_cannot_be_adopted() {
    let h = UserHold::new();
    assert!(h.put());
    assert!(!h.get());
    assert_eq!(h.count(), 0);
}
