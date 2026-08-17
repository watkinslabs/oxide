use super::*;
use crate::module::{LsmInfo, Order, LSM_FLAG_EXCLUSIVE, LSM_FLAG_LEGACY_MAJOR};
use crate::uapi;

fn m(name: &'static str, id: u64) -> LsmInfo { LsmInfo::new(name, id) }

fn names(modules: &[LsmInfo], ordered: &Ordered) -> alloc::vec::Vec<&'static str> {
    ordered.active.iter().map(|at| modules[*at].id.name).collect()
}

fn set(list: &str) -> Selection<'static> {
    // Leaked so the borrow outlives the call in a test body; the strings are
    // static in every real caller.
    Selection { builtin: alloc::boxed::Box::leak(list.into()), cmdline: None, legacy: None }
}

#[test] fn the_builtin_list_decides_the_order() {
    let mods = alloc::vec![m("a", 1), m("b", 2), m("c", 3)];
    let o = resolve(&mods, set("c,a,b"));
    assert_eq!(names(&mods, &o), ["c", "a", "b"]);
}

#[test] fn a_module_left_off_the_list_does_not_run() {
    let mods = alloc::vec![m("a", 1), m("b", 2)];
    let o = resolve(&mods, set("a"));
    assert_eq!(names(&mods, &o), ["a"]);
    assert!(!o.is_active(1));
    assert_eq!(o.skipped[1], Some(Skipped::NotSelected));
}

#[test] fn the_first_position_runs_ahead_of_the_list_and_is_never_named() {
    // Capability-shaped: ordered first, and reached even though the list
    // does not mention it. Every other module refines a decision it took.
    let mods = alloc::vec![m("b", 2), m("cap", 1).order(Order::First)];
    let o = resolve(&mods, set("b"));
    assert_eq!(names(&mods, &o), ["cap", "b"]);
}

#[test] fn the_last_position_runs_behind_the_list_and_is_never_named() {
    let mods = alloc::vec![m("integrity", 9).order(Order::Last), m("b", 2)];
    let o = resolve(&mods, set("b"));
    assert_eq!(names(&mods, &o), ["b", "integrity"]);
}

#[test] fn first_and_last_bracket_the_mutable_middle() {
    let mods = alloc::vec![
        m("mid1", 1), m("last", 2).order(Order::Last),
        m("first", 3).order(Order::First), m("mid2", 4)];
    let o = resolve(&mods, set("mid2,mid1"));
    assert_eq!(names(&mods, &o), ["first", "mid2", "mid1", "last"]);
}

#[test] fn naming_a_module_twice_runs_it_once() {
    let mods = alloc::vec![m("a", 1), m("b", 2)];
    let o = resolve(&mods, set("a,b,a"));
    assert_eq!(names(&mods, &o), ["a", "b"]);
}

#[test] fn a_module_that_disabled_itself_stays_off_even_when_the_list_names_it() {
    let mods = alloc::vec![m("a", 1).enabled(false), m("b", 2)];
    let o = resolve(&mods, set("a,b"));
    assert_eq!(names(&mods, &o), ["b"]);
    assert_eq!(o.skipped[0], Some(Skipped::Disabled));
}

#[test] fn a_module_with_no_enable_control_is_not_treated_as_disabled() {
    let mods = alloc::vec![m("a", 1)];
    assert_eq!(mods[0].enabled, None);
    let o = resolve(&mods, set("a"));
    assert_eq!(names(&mods, &o), ["a"]);
}

#[test] fn only_the_first_exclusive_module_runs() {
    let mods = alloc::vec![
        m("x", 1).flags(LSM_FLAG_EXCLUSIVE), m("y", 2).flags(LSM_FLAG_EXCLUSIVE), m("z", 3)];
    let o = resolve(&mods, set("x,y,z"));
    assert_eq!(names(&mods, &o), ["x", "z"]);
    assert_eq!(o.skipped[1], Some(Skipped::ExclusiveConflict));
    assert!(!o.is_active(1));
}

#[test] fn the_list_order_decides_which_exclusive_module_wins() {
    let mods = alloc::vec![
        m("x", 1).flags(LSM_FLAG_EXCLUSIVE), m("y", 2).flags(LSM_FLAG_EXCLUSIVE)];
    let o = resolve(&mods, set("y,x"));
    assert_eq!(names(&mods, &o), ["y"]);
}

#[test] fn a_non_exclusive_module_runs_beside_an_exclusive_one() {
    let mods = alloc::vec![m("path", 1), m("label", 2).flags(LSM_FLAG_EXCLUSIVE)];
    let o = resolve(&mods, set("path,label"));
    assert_eq!(names(&mods, &o), ["path", "label"]);
}

#[test] fn the_boot_list_replaces_the_builtin_one() {
    let mods = alloc::vec![m("a", 1), m("b", 2)];
    let o = resolve(&mods, Selection { builtin: "a", cmdline: Some("b"), legacy: None });
    assert_eq!(names(&mods, &o), ["b"]);
}

#[test] fn the_modern_list_discards_the_legacy_selector_entirely() {
    // Both given. The modern list wins and the legacy one has no effect at
    // all — not even its exclusion of the other legacy modules.
    let mods = alloc::vec![
        m("l1", 1).flags(LSM_FLAG_LEGACY_MAJOR), m("l2", 2).flags(LSM_FLAG_LEGACY_MAJOR)];
    let o = resolve(&mods, Selection { builtin: "", cmdline: Some("l1,l2"), legacy: Some("l2") });
    assert_eq!(names(&mods, &o), ["l1", "l2"]);
}

#[test] fn the_legacy_selector_excludes_its_peers() {
    let mods = alloc::vec![
        m("l1", 1).flags(LSM_FLAG_LEGACY_MAJOR), m("l2", 2).flags(LSM_FLAG_LEGACY_MAJOR),
        m("other", 3)];
    let o = resolve(&mods, Selection { builtin: "other", cmdline: None, legacy: Some("l2") });
    assert_eq!(names(&mods, &o), ["other", "l2"]);
    assert_eq!(o.skipped[0], Some(Skipped::LegacyConflict));
}

#[test] fn the_legacy_selector_runs_its_module_after_the_builtin_list() {
    let mods = alloc::vec![m("a", 1), m("l", 2).flags(LSM_FLAG_LEGACY_MAJOR)];
    let o = resolve(&mods, Selection { builtin: "a", cmdline: None, legacy: Some("l") });
    assert_eq!(names(&mods, &o), ["a", "l"]);
}

#[test] fn a_legacy_module_the_builtin_list_already_named_is_not_run_twice() {
    let mods = alloc::vec![m("l", 1).flags(LSM_FLAG_LEGACY_MAJOR)];
    let o = resolve(&mods, Selection { builtin: "l", cmdline: None, legacy: Some("l") });
    assert_eq!(names(&mods, &o), ["l"]);
}

#[test] fn a_legacy_selection_of_a_self_disabled_module_falls_back_to_nothing() {
    // The operator asked for that module or none: the peer it excluded does
    // NOT take over when the chosen one turns out to be off.
    let mods = alloc::vec![
        m("l1", 1).flags(LSM_FLAG_LEGACY_MAJOR),
        m("l2", 2).flags(LSM_FLAG_LEGACY_MAJOR).enabled(false)];
    let o = resolve(&mods, Selection { builtin: "l1,l2", cmdline: None, legacy: Some("l2") });
    assert!(names(&mods, &o).is_empty());
}

#[test] fn an_unknown_name_in_the_list_is_ignored() {
    let mods = alloc::vec![m("a", 1)];
    let o = resolve(&mods, set("nosuch,a,alsonone"));
    assert_eq!(names(&mods, &o), ["a"]);
}

#[test] fn an_empty_list_still_runs_the_fixed_positions() {
    let mods = alloc::vec![
        m("mid", 1), m("first", 2).order(Order::First), m("last", 3).order(Order::Last)];
    let o = resolve(&mods, set(""));
    assert_eq!(names(&mods, &o), ["first", "last"]);
}

#[test] fn empty_names_and_surrounding_space_are_tolerated() {
    let mods = alloc::vec![m("a", 1), m("b", 2)];
    let o = resolve(&mods, set(" a ,, b ,"));
    assert_eq!(names(&mods, &o), ["a", "b"]);
}

#[test] fn a_fixed_position_module_is_not_selected_by_being_named() {
    // Naming it in the list must not append it a second time, and the list
    // must not be able to move it out of its fixed position.
    let mods = alloc::vec![m("mid", 1), m("first", 2).order(Order::First)];
    let o = resolve(&mods, set("mid,first"));
    assert_eq!(names(&mods, &o), ["first", "mid"]);
}

#[test] fn the_order_stops_at_the_module_cap() {
    let names_pool: [&'static str; 14] = ["a0", "a1", "a2", "a3", "a4", "a5", "a6",
        "a7", "a8", "a9", "a10", "a11", "a12", "a13"];
    let mods: alloc::vec::Vec<LsmInfo> =
        names_pool.iter().enumerate().map(|(i, n)| m(n, i as u64)).collect();
    let list = names_pool.join(",");
    let o = resolve(&mods, Selection { builtin: &list, cmdline: None, legacy: None });
    assert_eq!(o.active.len(), crate::limits::MAX_LSM_COUNT);
    assert_eq!(o.skipped[crate::limits::MAX_LSM_COUNT], Some(Skipped::Full));
    assert!(!o.is_active(crate::limits::MAX_LSM_COUNT));
}

#[test] fn positions_match_the_resolved_order() {
    let mods = alloc::vec![m("a", 1), m("b", 2), m("c", 3)];
    let o = resolve(&mods, set("c,b,a"));
    assert_eq!(o.position(2), Some(0));
    assert_eq!(o.position(1), Some(1));
    assert_eq!(o.position(0), Some(2));
}

#[test] fn this_kernels_builtin_order_runs_both_modules_path_first() {
    let mods = crate::modules::builtin(true);
    let o = resolve(&mods, Selection {
        builtin: crate::modules::BUILTIN_ORDER, cmdline: None, legacy: None });
    assert_eq!(names(&mods, &o), ["landlock", "selinux"]);
    assert!(o.is_active(0) && o.is_active(1));
}

#[test] fn disabling_the_label_module_leaves_the_path_module_running() {
    let mods = crate::modules::builtin(false);
    let o = resolve(&mods, Selection {
        builtin: crate::modules::BUILTIN_ORDER, cmdline: None, legacy: None });
    assert_eq!(names(&mods, &o), ["landlock"]);
    assert_eq!(mods[1].id.id, uapi::LSM_ID_SELINUX);
}
