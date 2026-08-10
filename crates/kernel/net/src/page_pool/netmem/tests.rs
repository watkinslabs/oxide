use super::*;

fn area(n: usize) -> Arc<NetIovArea> { Arc::new(NetIovArea::new(n)) }

#[test]
fn fresh_area_has_unreferenced_unbound_buffers() {
    let a = area(4);
    assert_eq!(a.len(), 4);
    for i in 0..4 {
        assert_eq!(a.niovs[i].refs(), 0);
        assert!(!a.niovs[i].is_bound());
    }
}

#[test]
fn last_unref_reports_the_transition_and_only_once() {
    let a = area(1);
    let nm = Netmem { area: Arc::clone(&a), idx: 0 };
    nm.niov().fragment(2);
    assert!(!nm.niov().unref_and_test());
    assert_eq!(nm.niov().refs(), 1);
    assert!(nm.niov().unref_and_test());
    assert_eq!(nm.niov().refs(), 0);
}

/// A release that arrives when the count is already zero must NOT report the
/// transition again: reporting it twice hands one buffer back to the provider
/// twice, which puts the same buffer on the freelist twice and lets two owners
/// receive into it.
#[test]
fn release_below_zero_is_refused_and_cannot_wrap() {
    let a = area(1);
    let nm = Netmem { area: Arc::clone(&a), idx: 0 };
    nm.niov().fragment(1);
    assert!(nm.niov().unref_and_test());
    assert!(!nm.niov().unref_and_test());
    assert!(!nm.niov().unref_and_test());
    assert_eq!(nm.niov().refs(), 0);
}

#[test]
fn get_adds_a_reference() {
    let a = area(1);
    let nm = Netmem { area: Arc::clone(&a), idx: 0 };
    nm.niov().fragment(1);
    nm.niov().get();
    assert_eq!(nm.niov().refs(), 2);
    assert!(!nm.niov().unref_and_test());
    assert!(nm.niov().unref_and_test());
}

#[test]
fn binding_state_is_recorded_per_buffer() {
    let a = area(2);
    a.niovs[0].set_bound();
    assert!(a.niovs[0].is_bound());
    assert!(!a.niovs[1].is_bound());
    a.niovs[0].clear_bound();
    assert!(!a.niovs[0].is_bound());
}
