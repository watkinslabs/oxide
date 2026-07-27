use crate::exit::reaper::*;

const LEVEL: u32 = 0;

fn ancestor(tid: u32, subreaper: bool, alive: Option<u32>) -> Ancestor {
    Ancestor { tid, ns_level: LEVEL, is_child_subreaper: subreaper, alive_thread: alive, is_init_task: false }
}

#[test]
fn a_live_sibling_thread_adopts_before_anything_else() {
    let subreaper = ancestor(50, true, Some(50));
    assert_eq!(
        find_new_reaper(Some(42), true, LEVEL, &[subreaper]),
        NewReaper::AliveSibling(42),
        "a thread exiting must not hand its children to init while its process lives",
    );
}

#[test]
fn without_a_subreaper_flag_children_go_to_the_namespace_init() {
    let chain = [ancestor(50, true, Some(50))];
    assert_eq!(find_new_reaper(None, false, LEVEL, &chain), NewReaper::NsInit);
}

#[test]
fn the_nearest_subreaper_ancestor_adopts() {
    let chain = [
        ancestor(30, false, Some(30)),
        ancestor(20, true, Some(21)),
        ancestor(10, true, Some(10)),
    ];
    assert_eq!(find_new_reaper(None, true, LEVEL, &chain), NewReaper::Subreaper(21));
}

#[test]
fn a_subreaper_with_no_live_thread_is_skipped() {
    let chain = [ancestor(30, true, None), ancestor(20, true, Some(20))];
    assert_eq!(find_new_reaper(None, true, LEVEL, &chain), NewReaper::Subreaper(20));
}

#[test]
fn the_walk_stops_at_the_pid_namespace_boundary() {
    let mut outer = ancestor(9, true, Some(9));
    outer.ns_level = LEVEL + 1;
    assert_eq!(find_new_reaper(None, true, LEVEL + 1, &[outer]), NewReaper::Subreaper(9));
    assert_eq!(
        find_new_reaper(None, true, LEVEL, &[outer]),
        NewReaper::NsInit,
        "a setns-injected outer parent must not pull children out of the namespace",
    );
}

#[test]
fn the_walk_stops_at_the_init_task() {
    let mut init = ancestor(1, true, Some(1));
    init.is_init_task = true;
    let chain = [init, ancestor(0, true, Some(0))];
    assert_eq!(find_new_reaper(None, true, LEVEL, &chain), NewReaper::NsInit);
}

#[test]
fn a_dying_namespace_reaper_hands_off_to_a_live_thread() {
    assert_eq!(child_reaper_succession(true, Some(7)), ChildReaperSuccession::Promote(7));
}

#[test]
fn a_dying_namespace_reaper_with_no_threads_tears_the_namespace_down() {
    assert_eq!(child_reaper_succession(true, None), ChildReaperSuccession::ZapNamespace);
}

#[test]
fn an_ordinary_task_does_not_touch_namespace_leadership() {
    assert_eq!(child_reaper_succession(false, None), ChildReaperSuccession::Unchanged);
}
