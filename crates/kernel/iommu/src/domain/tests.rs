use super::*;

#[test]
fn mapping_lifecycle_waits_for_invalidation() {
    let b = Bdf { segment: 2, bus: 3, device: 4, function: 0 };
    let mut d = Domain::new(b, 0x1000, 0x4000).unwrap();
    let m = d.reserve(0x2000, 0x1000, 0x1000).unwrap();
    assert_eq!(d.requester(), b); assert_eq!(d.mapping(m.iova.start), Some(m));
    assert!(d.release_after_invalidate(m)); assert!(!d.release_after_invalidate(m));
}

#[test]
fn retired_pte_stays_owned_until_its_iotlb_sync_succeeds() {
    let mapping = Mapping { iova: pci::IovaRange { start: 0x1000, len: 0x1000 }, pa: 0x8000 };
    let mut record = MappingRecord::live(mapping);
    assert!(!record.iotlb_pending());
    assert!(record.begin_iotlb_invalidate());
    assert!(record.iotlb_pending());
    assert!(!record.begin_iotlb_invalidate());
}
