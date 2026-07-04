use super::common::registry_test_lock;
use crate::task::{SchedClass, Task};
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

#[test]
fn cmdline_empty_argv_is_empty_string() {
    assert_eq!(crate::argv_to_cmdline(&[]).as_bytes(), b"");
}

#[test]
fn cmdline_single_arg_has_trailing_nul() {
    let argv: &[&[u8]] = &[b"/init"];
    assert_eq!(crate::argv_to_cmdline(argv).as_bytes(), b"/init\0");
}

#[test]
fn cmdline_multiple_args_nul_separated() {
    let argv: &[&[u8]] = &[b"sh", b"-c", b"echo hi"];
    assert_eq!(crate::argv_to_cmdline(argv).as_bytes(), b"sh\0-c\0echo hi\0");
}

#[test]
fn cmdline_drops_non_ascii_bytes() {
    let argv: &[&[u8]] = &[b"a\xC3\xA9b"];
    assert_eq!(crate::argv_to_cmdline(argv).as_bytes(), b"ab\0");
}

#[test]
fn cmdline_preserves_internal_spaces() {
    let argv: &[&[u8]] = &[b"hello world"];
    assert_eq!(crate::argv_to_cmdline(argv).as_bytes(), b"hello world\0");
}

#[test]
fn registry_insert_and_lookup() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let t = Arc::new(Task::new(123, "t", SchedClass::Normal { weight: 1024 }));
    crate::registry::insert(&t);
    let got = crate::registry::lookup(123).expect("tid 123 should be live");
    assert!(Arc::ptr_eq(&t, &got));
}

#[test]
fn registry_lookup_unknown_returns_none() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    assert!(crate::registry::lookup(9999).is_none());
}

#[test]
fn registry_decays_when_arc_dropped() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    {
        let t = Arc::new(Task::new(7, "t", SchedClass::Normal { weight: 1024 }));
        crate::registry::insert(&t);
        assert!(crate::registry::lookup(7).is_some());
    }
    assert!(crate::registry::lookup(7).is_none(),
            "Weak<Task> upgrade must fail after the last Arc is dropped");
}

#[test]
fn registry_live_tids_prunes_decayed() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let live = Arc::new(Task::new(1, "live", SchedClass::Normal { weight: 1024 }));
    crate::registry::insert(&live);
    {
        let dead = Arc::new(Task::new(2, "dead", SchedClass::Normal { weight: 1024 }));
        crate::registry::insert(&dead);
    }
    let tids = crate::registry::live_tids();
    assert_eq!(tids, alloc::vec![1u32]);
}

#[test]
fn registry_insert_idempotent_overwrites_stale_slot() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let a = Arc::new(Task::new(42, "a", SchedClass::Normal { weight: 1024 }));
    crate::registry::insert(&a);
    let b = Arc::new(Task::new(42, "b", SchedClass::Normal { weight: 1024 }));
    crate::registry::insert(&b);
    let got = crate::registry::lookup(42).unwrap();
    assert!(Arc::ptr_eq(&b, &got));
    assert_eq!(crate::registry::live_tids().len(), 1);
}

#[test]
fn registry_tasks_in_pgrp_filters_by_pgid() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let a = Arc::new(Task::new(10, "a", SchedClass::Normal { weight: 1024 }));
    let b = Arc::new(Task::new(11, "b", SchedClass::Normal { weight: 1024 }));
    let c = Arc::new(Task::new(12, "c", SchedClass::Normal { weight: 1024 }));
    a.pgid.store(99, Ordering::Release);
    b.pgid.store(99, Ordering::Release);
    c.pgid.store(50, Ordering::Release);
    crate::registry::insert(&a);
    crate::registry::insert(&b);
    crate::registry::insert(&c);
    let in_99 = crate::registry::tasks_in_pgrp(99);
    assert_eq!(in_99.len(), 2);
    let tids: alloc::vec::Vec<u32> = in_99.iter().map(|t| t.tid).collect();
    assert!(tids.contains(&10) && tids.contains(&11) && !tids.contains(&12));
    let in_50 = crate::registry::tasks_in_pgrp(50);
    assert_eq!(in_50.len(), 1);
    assert_eq!(in_50[0].tid, 12);
    let in_none = crate::registry::tasks_in_pgrp(7777);
    assert!(in_none.is_empty());
}

#[test]
fn display_vpid_resolves_vtgid_not_internal_tid() {
    crate::registry::clear_for_tests();
    let init = Arc::new(Task::new(0xC0DE_0002, "systemd", SchedClass::Normal { weight: 1024 }));
    init.vtgid.store(1, Ordering::Release);
    crate::registry::insert(&init);
    assert_eq!(crate::registry::display_vpid(0xC0DE_0002), 1);
    let kth = Arc::new(Task::new(42, "kworker", SchedClass::Normal { weight: 1024 }));
    crate::registry::insert(&kth);
    assert_eq!(crate::registry::display_vpid(42), 42);
    assert_eq!(crate::registry::display_vpid(9999), 9999);
}

#[test]
fn parent_vpid_resolves_parent_vtgid() {
    crate::registry::clear_for_tests();
    let init = Arc::new(Task::new(0xC0DE_0002, "systemd", SchedClass::Normal { weight: 1024 }));
    init.vtgid.store(1, Ordering::Release);
    crate::registry::insert(&init);
    let child = Arc::new(Task::new(0xC0DE_0050, "sh", SchedClass::Normal { weight: 1024 }));
    child.vtgid.store(7, Ordering::Release);
    child.parent_tid.store(0xC0DE_0002, Ordering::Release);
    crate::registry::insert(&child);
    assert_eq!(crate::registry::parent_vpid(0xC0DE_0050), 1);
    assert_eq!(crate::registry::parent_vpid(0xC0DE_0002), 0);
}
