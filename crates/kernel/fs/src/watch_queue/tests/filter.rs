// What a filter accepts, and which filters are refused.

use super::*;
use crate::watch_queue::filter::{Filter, TypeFilter};
use crate::watch_queue::queue::WatchQueue;
use syscall::errno::Errno;

/// Encode a `struct watch_notification_filter` header. # C: O(1)
fn header_bytes(nr: u32, reserved: u32) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec![0u8; WATCH_FILTER_HEADER_SIZE];
    v[WATCH_FILTER_NR_OFFSET..][..4].copy_from_slice(&nr.to_ne_bytes());
    v[WATCH_FILTER_RESERVED_OFFSET..][..4].copy_from_slice(&reserved.to_ne_bytes());
    v
}

/// Encode one `struct watch_notification_type_filter`. # C: O(1)
fn rule_bytes(ty: u32, subtypes: u32, info_filter: u32, info_mask: u32) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec![0u8; WATCH_TYPE_FILTER_SIZE];
    v[WATCH_TYPE_FILTER_TYPE_OFFSET..][..4].copy_from_slice(&ty.to_ne_bytes());
    v[WATCH_TYPE_FILTER_INFO_FILTER_OFFSET..][..4].copy_from_slice(&info_filter.to_ne_bytes());
    v[WATCH_TYPE_FILTER_INFO_MASK_OFFSET..][..4].copy_from_slice(&info_mask.to_ne_bytes());
    v[WATCH_TYPE_FILTER_SUBTYPE_OFFSET..][..4].copy_from_slice(&subtypes.to_ne_bytes());
    v
}

// The counts and reserved word a filter must respect.
#[test]
fn filter_admission() {
    let rule = rule_bytes(WATCH_TYPE_KEY_NOTIFY, 1 << NOTIFY_KEY_UPDATED, 0, 0);
    assert!(Filter::parse(&header_bytes(1, 0), &rule, 1).is_ok());
    assert_eq!(Filter::parse(&header_bytes(0, 0), &rule, 0), Err(Errno::Einval), "no rules at all");
    assert_eq!(Filter::parse(&header_bytes(1, 1), &rule, 1), Err(Errno::Einval),
        "a reserved word set asks for something this kernel has no definition of");
    assert_eq!(Filter::parse(&header_bytes(WATCH_FILTER_MAX + 1, 0), &rule, WATCH_FILTER_MAX + 1),
        Err(Errno::Einval), "past the rule ceiling");

    // A filter whose match bits fall outside its own mask could never match.
    let bad = rule_bytes(WATCH_TYPE_KEY_NOTIFY, 1, 0x0001_0000, 0);
    assert_eq!(Filter::parse(&header_bytes(1, 0), &bad, 1), Err(Errno::Einval));
    // Filtering on the record LENGTH filters on what the sender wrote, not on
    // anything about the event.
    let bad = rule_bytes(WATCH_TYPE_KEY_NOTIFY, 1, 0, WATCH_INFO_LENGTH);
    assert_eq!(Filter::parse(&header_bytes(1, 0), &bad, 1), Err(Errno::Einval));
}

// A rule naming a type this kernel does not define is DROPPED, not rejected,
// so a program built against a later kernel still installs the rest.
#[test]
fn unknown_types_are_dropped_not_refused() {
    let mut rules = rule_bytes(WATCH_TYPE_NR + 5, 0xffff_ffff, 0, 0);
    rules.extend_from_slice(&rule_bytes(WATCH_TYPE_KEY_NOTIFY, 1 << NOTIFY_KEY_REVOKED, 0, 0));
    let f = Filter::parse(&header_bytes(2, 0), &rules, 2).expect("the known rule survives");
    assert_eq!(f.filters.len(), 1);
    assert_eq!(f.filters[0].ty, WATCH_TYPE_KEY_NOTIFY);
}

// A filter selects by type, subtype and masked info; anything it does not name
// is rejected, because the default flips to reject the moment a filter exists.
#[test]
fn filtering_is_reject_by_default() {
    let f = Filter { filters: alloc::vec![TypeFilter {
        ty: WATCH_TYPE_KEY_NOTIFY,
        info_filter: 0x0200,
        info_mask: WATCH_INFO_ID,
        subtype_filter: (1 << NOTIFY_KEY_UPDATED) | (1 << NOTIFY_KEY_REVOKED),
    }] };
    assert!(f.accepts(WATCH_TYPE_KEY_NOTIFY, NOTIFY_KEY_UPDATED, 0x0210));
    assert!(f.accepts(WATCH_TYPE_KEY_NOTIFY, NOTIFY_KEY_REVOKED, 0x0210));
    assert!(!f.accepts(WATCH_TYPE_KEY_NOTIFY, NOTIFY_KEY_LINKED, 0x0210), "an unnamed subtype");
    assert!(!f.accepts(WATCH_TYPE_KEY_NOTIFY, NOTIFY_KEY_UPDATED, 0x0310), "a different watchpoint");
    assert!(!f.accepts(WATCH_TYPE_META, WATCH_META_REMOVAL_NOTIFICATION, 0x0210), "an unnamed type");
}

// A filtered-out record is withheld WITHOUT a loss: the reader asked not to be
// told, so reporting a gap would defeat the filter it installed.
#[test]
fn a_filtered_record_is_not_a_loss() {
    let q = WatchQueue::new();
    q.set_size(8).expect("a valid depth");
    q.set_filter(Some(Filter { filters: alloc::vec![TypeFilter {
        ty: WATCH_TYPE_KEY_NOTIFY, info_filter: 0, info_mask: 0,
        subtype_filter: 1 << NOTIFY_KEY_REVOKED,
    }] }));
    assert!(!q.post(&key_notification(NOTIFY_KEY_UPDATED, 1, 0, 0)));
    assert!(!q.readable(), "nothing was delivered and nothing was lost");
    assert!(q.post(&key_notification(NOTIFY_KEY_REVOKED, 1, 0, 0)));
    assert_eq!(records(&q.read(64).expect("room")).len(), 1);

    // Removing the filter restores delivery of everything.
    q.set_filter(None);
    assert!(q.post(&key_notification(NOTIFY_KEY_UPDATED, 1, 0, 0)));
    assert_eq!(records(&q.read(64).expect("room")).len(), 1);
}
