use super::*;

#[test]
fn getppid_reports_the_parents_process_id() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let parent = published(100);
    let child = child_of(&parent, 101);
    assert_eq!(session::getppid(&child), 100);
    assert_eq!(session::getppid(&parent), 0, "no parent → 0, as Linux does for pid 1");
}

#[test]
fn getppid_of_a_thread_reports_the_parent_process_not_the_parent_thread() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let parent_leader = published(100);
    let parent_worker = thread_in(&parent_leader, 101);
    // The worker thread forked the child, so parent_tid names the WORKER.
    let child = proc(200);
    child.parent_tid.store(parent_worker.tid, Ordering::Release);
    crate::registry::insert(&child);
    assert_eq!(session::getppid(&child), 100,
        "Linux reports task_tgid_vnr(real_parent), i.e. the parent PROCESS");
}

#[test]
fn personality_query_form_does_not_set() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let p = published(100);
    assert_eq!(personality::get_set(&p, personality::PER_LINUX), 0);
    let want = personality::READ_IMPLIES_EXEC | personality::UNAME26;
    assert_eq!(personality::get_set(&p, want), personality::PER_LINUX);
    // 0xffffffff reads without writing, and keeps returning the same value.
    assert_eq!(personality::get_set(&p, personality::PERSONALITY_QUERY), want);
    assert_eq!(personality::get_set(&p, personality::PERSONALITY_QUERY), want);
    assert_eq!(personality::get(&p), want);
    assert!(personality::read_implies_exec(&p));
    assert!(personality::uname26(&p));
}

#[test]
fn personality_returns_previous_on_every_set() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let p = published(100);
    assert_eq!(personality::get_set(&p, personality::ADDR_NO_RANDOMIZE), 0);
    assert_eq!(personality::get_set(&p, personality::MMAP_PAGE_ZERO),
        personality::ADDR_NO_RANDOMIZE);
    assert_eq!(personality::get_set(&p, personality::PER_LINUX),
        personality::MMAP_PAGE_ZERO);
    assert_eq!(personality::get(&p), personality::PER_LINUX);
    assert!(!personality::read_implies_exec(&p));
}

/// `set_personality(pers)` is a plain assignment: no masking, no validation,
/// no EINVAL on the generic path. A kernel that masked the argument would
/// break `setarch` round-trips through `/proc/<pid>/personality`, which
/// renders whatever was stored.
#[test]
fn personality_stores_the_argument_verbatim_including_dead_bits() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let p = published(100);
    // Every bit with no consumer, plus an execution-domain byte that no longer
    // dispatches anything: all of it must survive a store/read round trip.
    let odd = personality::audit::PER_NO_CONSUMER | personality::domains::PER_HPUX;
    assert_eq!(personality::get_set(&p, odd), personality::PER_LINUX);
    assert_eq!(personality::get(&p), odd, "the persona was masked on store");
    assert_eq!(personality::get_set(&p, personality::PERSONALITY_QUERY), odd);
    assert_eq!(personality::get(&p), odd, "the query form stored the sentinel");
    // The dead bits are stored but drive nothing.
    assert!(!personality::mmap_page_zero(personality::get(&p)));
    assert!(!personality::addr_compat_layout(personality::get(&p)));
    assert!(!personality::sticky_timeouts(personality::get(&p)));
}

