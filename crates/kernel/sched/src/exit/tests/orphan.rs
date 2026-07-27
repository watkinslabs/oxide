use crate::exit::orphan::*;

const SESSION: u32 = 100;
const PGRP: u32 = 200;
const OUTSIDE_PGRP: u32 = 201;

fn member(tid: u32, stopped: bool, parent_pgid: u32, parent_sid: u32) -> PgrpMember {
    PgrpMember {
        tid, sid: SESSION, exiting: false, thread_group_empty: true, stopped,
        parent_is_init: false, parent_pgid, parent_sid,
    }
}

#[test]
fn a_group_with_an_outside_parent_in_the_same_session_is_not_orphaned() {
    let members = [member(10, false, OUTSIDE_PGRP, SESSION)];
    assert!(!will_become_orphaned_pgrp(&members, PGRP, None));
}

#[test]
fn a_group_whose_only_outside_link_is_exiting_becomes_orphaned() {
    let members = [member(10, false, OUTSIDE_PGRP, SESSION)];
    assert!(will_become_orphaned_pgrp(&members, PGRP, Some(10)));
}

#[test]
fn a_parent_inside_the_group_does_not_keep_it_connected() {
    let members = [member(10, false, PGRP, SESSION)];
    assert!(will_become_orphaned_pgrp(&members, PGRP, None));
}

#[test]
fn a_parent_in_another_session_does_not_keep_it_connected() {
    let members = [member(10, false, OUTSIDE_PGRP, SESSION + 1)];
    assert!(will_become_orphaned_pgrp(&members, PGRP, None));
}

#[test]
fn an_init_parented_member_is_skipped() {
    let mut m = member(10, false, OUTSIDE_PGRP, SESSION);
    m.parent_is_init = true;
    assert!(will_become_orphaned_pgrp(&[m], PGRP, None));
}

#[test]
fn a_single_threaded_zombie_member_is_skipped() {
    let mut m = member(10, false, OUTSIDE_PGRP, SESSION);
    m.exiting = true;
    assert!(will_become_orphaned_pgrp(&[m], PGRP, None));
    // but a zombie leader with live threads still counts
    let mut m = member(10, false, OUTSIDE_PGRP, SESSION);
    m.exiting = true;
    m.thread_group_empty = false;
    assert!(!will_become_orphaned_pgrp(&[m], PGRP, None));
}

#[test]
fn orphaning_a_group_with_a_stopped_job_sends_sighup_and_sigcont() {
    let members = [member(10, false, OUTSIDE_PGRP, SESSION), member(11, true, PGRP, SESSION)];
    assert!(has_stopped_jobs(&members));
    assert!(should_kill_orphaned_pgrp(PGRP, SESSION, OUTSIDE_PGRP, SESSION, &members, Some(10)));
}

#[test]
fn orphaning_a_group_with_no_stopped_job_is_silent() {
    let members = [member(10, false, OUTSIDE_PGRP, SESSION), member(11, false, PGRP, SESSION)];
    assert!(!has_stopped_jobs(&members));
    assert!(!should_kill_orphaned_pgrp(PGRP, SESSION, OUTSIDE_PGRP, SESSION, &members, Some(10)));
}

#[test]
fn a_parent_inside_the_same_group_never_orphans_it() {
    let members = [member(10, true, PGRP, SESSION)];
    assert!(!should_kill_orphaned_pgrp(PGRP, SESSION, PGRP, SESSION, &members, Some(10)));
}

#[test]
fn a_parent_in_a_different_session_never_orphans_it() {
    let members = [member(10, true, OUTSIDE_PGRP, SESSION)];
    assert!(!should_kill_orphaned_pgrp(PGRP, SESSION, OUTSIDE_PGRP, SESSION + 1, &members, Some(10)));
}

#[test]
fn a_still_connected_group_is_left_alone_even_with_stopped_jobs() {
    let members = [member(10, true, OUTSIDE_PGRP, SESSION), member(11, false, OUTSIDE_PGRP, SESSION)];
    assert!(!should_kill_orphaned_pgrp(PGRP, SESSION, OUTSIDE_PGRP, SESSION, &members, Some(10)));
}
