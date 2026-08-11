use super::*;

#[test]
fn mapping_lifecycle_waits_for_invalidation() {
    let b = Bdf { segment: 2, bus: 3, device: 4, function: 0 };
    let mut d = Domain::new(b, 0x1000, 0x4000).unwrap();
    let m = d.reserve(0x2000, 0x1000, 0x1000).unwrap();
    assert_eq!(d.requester(), b); assert_eq!(d.mapping(m.iova.start), Some(m));
    assert!(d.release_after_invalidate(m)); assert!(!d.release_after_invalidate(m));
}
