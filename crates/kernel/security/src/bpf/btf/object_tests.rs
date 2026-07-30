use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use super::*;

const RETAINED_INPUT: &[u8] = b"retained-btf-input";

fn index() -> BtfIndex { BtfIndex::empty_for_test() }

#[test]
fn object_id_domain_is_nonzero_bounded_and_cyclic() {
    assert!(valid_object_id(FIRST_OBJECT_ID));
    assert!(valid_object_id(LAST_OBJECT_ID));
    assert!(!valid_object_id(0));
    assert!(!valid_object_id(OBJECT_ID_EXCLUSIVE_MAX));
    assert_eq!(successor_id(LAST_OBJECT_ID), FIRST_OBJECT_ID);
    assert_eq!(successor_id(FIRST_OBJECT_ID), FIRST_OBJECT_ID + 1);
    assert!(matches!(next_id(OBJECT_ID_EXCLUSIVE_MAX), Err(Errno::Einval)));
}

#[test]
fn registry_enumerates_live_ids_in_order() {
    let first = BtfObject::register(Vec::new(), index()).expect("register first object");
    let second = BtfObject::register(Vec::new(), index()).expect("register second object");
    let low = first.id().min(second.id());
    let high = first.id().max(second.id());

    let earliest = next_id(0).expect("enumerate first live object");
    assert_ne!(earliest, 0);
    assert!(earliest <= low);
    let mut cursor = low;
    loop {
        let found = next_id(cursor).expect("enumerate toward pinned object");
        assert!(found > cursor);
        if found == high { break; }
        assert!(found < high);
        cursor = found;
    }
    assert_eq!(get_by_id(first.id()).map(|object| object.id()), Ok(first.id()));
    assert_eq!(get_by_id(second.id()).map(|object| object.id()), Ok(second.id()));
}

#[test]
fn registry_does_not_retain_or_publish_dead_object() {
    let object = BtfObject::register(Vec::new(), index()).expect("register object");
    let id = object.id();
    let weak: Weak<BtfObject> = Arc::downgrade(&object);
    drop(object);

    assert!(weak.upgrade().is_none());
    assert!(matches!(get_by_id(id), Err(Errno::Enoent)));
}

#[test]
fn object_retains_exact_input_until_final_close() {
    let object = BtfObject::register(RETAINED_INPUT.to_vec(), index())
        .expect("register retained object");
    let id = object.id();
    let duplicate = Arc::clone(&object);

    drop(object);
    assert_eq!(duplicate.raw(), RETAINED_INPUT);
    assert_eq!(duplicate.index().type_count(), 0);
    assert!(get_by_id(id).is_ok());
    drop(duplicate);
    assert!(matches!(get_by_id(id), Err(Errno::Enoent)));
}
