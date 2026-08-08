// The notification state machine. Every rule here decides what a supervisor
// and a notified task are allowed to do to each other, so each one is driven
// directly rather than through a descriptor.

use super::*;

fn data(nr: i32) -> SeccompData {
    SeccompData { nr, arch: 0xC000_003E, ip: 0x1000, args: [0; 6] }
}

fn listener() -> Inner { Inner::new(100, false) }

fn queued(inner: &mut Inner) -> u64 { inner.queue(7, data(1)).expect("listener is open") }

#[test]
fn a_notification_is_picked_up_once_and_answered_once() {
    let mut l = listener();
    let id = queued(&mut l);
    assert!(l.has_pending());
    let (got, tid, d) = l.recv().expect("one notification is waiting");
    assert_eq!((got, tid, d.nr), (id, 7, 1));
    assert!(!l.has_pending(), "a picked-up notification is not offered again");
    assert_eq!(l.recv().is_none(), true);

    assert_eq!(l.reply(NotifResp { id, val: 5, error: 0, flags: 0 }), Ok(()));
    // Exactly one reply: the second is refused, not silently applied.
    assert_eq!(l.reply(NotifResp { id, val: 6, error: 0, flags: 0 }),
               Err(Errno::Einprogress));
    assert_eq!(l.take_reply(id), Some((5, 0, 0)));
    assert_eq!(l.take_reply(id), None, "a collected reply leaves the queue");
}

#[test]
fn a_reply_to_a_notification_no_supervisor_holds_is_refused() {
    let mut l = listener();
    let id = queued(&mut l);
    // Never picked up: answering it would answer a call the supervisor has
    // not been shown.
    assert_eq!(l.reply(NotifResp { id, val: 0, error: -1, flags: 0 }),
               Err(Errno::Einprogress));
    assert_eq!(l.reply(NotifResp { id: id + 999, val: 0, error: 0, flags: 0 }),
               Err(Errno::Enoent));
}

#[test]
fn only_a_notification_a_supervisor_holds_has_a_valid_id() {
    let mut l = listener();
    let id = queued(&mut l);
    assert_eq!(l.id_valid(id), Err(Errno::Enoent), "not picked up yet");
    l.recv();
    assert_eq!(l.id_valid(id), Ok(()));
    assert_eq!(l.id_valid(id + 1), Err(Errno::Enoent));
    l.reply(NotifResp { id, val: 0, error: 0, flags: 0 }).unwrap();
    l.take_reply(id);
    assert_eq!(l.id_valid(id), Err(Errno::Enoent), "gone once collected");
}

#[test]
fn a_faulted_handover_puts_the_notification_back_for_another_supervisor() {
    let mut l = listener();
    let id = queued(&mut l);
    l.recv().unwrap();
    l.recv_undo(id);
    assert!(l.has_pending());
    assert_eq!(l.recv().map(|(i, _, _)| i), Some(id));
}

#[test]
fn a_closed_listener_releases_every_waiter_with_the_no_supervisor_answer() {
    let mut l = listener();
    let a = queued(&mut l);
    let b = queued(&mut l);
    l.recv();
    l.detach();
    let enosys = -(Errno::Enosys.as_i32() as i32);
    assert_eq!(l.take_reply(a), Some((0, enosys, 0)));
    assert_eq!(l.take_reply(b), Some((0, enosys, 0)));
    assert_eq!(l.queue(7, data(2)), None, "nothing new is accepted");
}

#[test]
fn a_reply_already_given_survives_the_listener_going_away() {
    let mut l = listener();
    let id = queued(&mut l);
    l.recv();
    l.reply(NotifResp { id, val: 99, error: 0, flags: 0 }).unwrap();
    l.detach();
    assert_eq!(l.take_reply(id), Some((99, 0, 0)),
               "an answered notification keeps its answer");
}

#[test]
fn the_response_decides_the_syscall_outcome() {
    assert_eq!(outcome(0, 0, USER_NOTIF_FLAG_CONTINUE), Outcome::Continue);
    // The error member wins when set; the value carries the result otherwise.
    assert_eq!(outcome(7, -13, 0), Outcome::Skip(-13));
    assert_eq!(outcome(7, 0, 0), Outcome::Skip(7));
    assert_eq!(outcome(0, 0, 0), Outcome::Skip(0));
}

#[test]
fn a_response_may_not_both_continue_the_call_and_answer_it() {
    let cont = |val, error| NotifResp { id: 1, val, error, flags: USER_NOTIF_FLAG_CONTINUE };
    assert_eq!(validate_resp(&cont(0, 0)), Ok(()));
    assert_eq!(validate_resp(&cont(1, 0)), Err(Errno::Einval));
    assert_eq!(validate_resp(&cont(0, -1)), Err(Errno::Einval));
    assert_eq!(validate_resp(&NotifResp { id: 1, val: 1, error: -1, flags: 0 }), Ok(()));
    assert_eq!(validate_resp(&NotifResp { id: 1, val: 0, error: 0, flags: 2 }),
               Err(Errno::Einval));
}

#[test]
fn an_injection_request_is_admitted_before_the_descriptor_is_resolved() {
    let ok = AddfdReq { id: 1, flags: 0, srcfd: 3, newfd: 0, newfd_flags: 0 };
    assert_eq!(validate_addfd(&ok), Ok(()));
    assert_eq!(validate_addfd(&AddfdReq { newfd_flags: O_CLOEXEC, ..ok }), Ok(()));
    // Only O_CLOEXEC may travel with an injected descriptor.
    assert_eq!(validate_addfd(&AddfdReq { newfd_flags: 1, ..ok }), Err(Errno::Einval));
    assert_eq!(validate_addfd(&AddfdReq { flags: 4, ..ok }), Err(Errno::Einval));
    // Naming a target number without asking to choose it is a contradiction.
    assert_eq!(validate_addfd(&AddfdReq { newfd: 9, ..ok }), Err(Errno::Einval));
    assert_eq!(validate_addfd(&AddfdReq { newfd: 9, flags: ADDFD_FLAG_SETFD, ..ok }), Ok(()));
    assert_eq!(validate_addfd(&AddfdReq { newfd: u32::MAX, flags: ADDFD_FLAG_SETFD, ..ok }),
               Err(Errno::Einval));
}

#[test]
fn an_injection_payload_smaller_than_the_first_version_is_refused() {
    assert_eq!(validate_addfd_size(ADDFD_SIZE_VER0 - 1), Err(Errno::Einval));
    assert_eq!(validate_addfd_size(ADDFD_SIZE_VER0), Ok(()));
    assert_eq!(validate_addfd_size(ADDFD_SIZE_VER0 + 8), Ok(()));
    assert_eq!(validate_addfd_size(ADDFD_SIZE_MAX), Err(Errno::Einval));
}

#[test]
fn set_flags_takes_only_the_defined_listener_flag() {
    let mut l = listener();
    assert_eq!(l.set_flags(USER_NOTIF_FD_SYNC_WAKE_UP), Ok(()));
    assert_eq!(l.flags, USER_NOTIF_FD_SYNC_WAKE_UP);
    assert_eq!(l.set_flags(2), Err(Errno::Einval));
    assert_eq!(l.flags, USER_NOTIF_FD_SYNC_WAKE_UP, "a refused set changes nothing");
    assert_eq!(l.set_flags(0), Ok(()));
}

#[test]
fn readiness_follows_what_each_side_is_waiting_for() {
    let mut l = listener();
    assert_eq!(l.poll_mask(true), 0);
    let id = queued(&mut l);
    assert_eq!(l.poll_mask(true), vfs::POLL_IN, "a notification is waiting to be read");
    l.recv();
    assert_eq!(l.poll_mask(true), vfs::POLL_OUT, "it is now waiting for its reply");
    l.reply(NotifResp { id, val: 0, error: 0, flags: 0 }).unwrap();
    assert_eq!(l.poll_mask(true), 0);
    // With no task left running the filter, the listener is hung up.
    assert_eq!(l.poll_mask(false), vfs::POLL_HUP);
}

#[test]
fn a_killable_wait_starts_only_once_a_supervisor_holds_the_notification() {
    let mut l = Inner::new(1, true);
    let id = queued(&mut l);
    assert!(!l.sleep_killable(id), "not picked up: an ordinary signal still ends the wait");
    l.recv();
    assert!(l.sleep_killable(id));
    // A filter that did not ask for it never gets the narrower wait.
    let mut plain = listener();
    let pid = queued(&mut plain);
    plain.recv();
    assert!(!plain.sleep_killable(pid));
}

#[test]
fn a_task_wakes_for_a_reply_a_descriptor_or_a_vanished_notification() {
    let mut l = listener();
    let id = queued(&mut l);
    assert!(!l.actionable(id), "queued and untouched: nothing to do");
    l.recv();
    assert!(!l.actionable(id), "picked up but unanswered: still waiting");
    l.reply(NotifResp { id, val: 0, error: 0, flags: 0 }).unwrap();
    assert!(l.actionable(id));
    l.take_reply(id);
    assert!(l.actionable(id), "a notification that is gone must not be waited on");
}

fn a_file() -> alloc::sync::Arc<vfs::File> {
    let inode = vfs::InodeBuilder::new(1, vfs::mk_mode(vfs::FileType::Regular, 0o600),
        vfs::default_inode_ops(), vfs::default_file_ops()).build();
    let dentry = vfs::Dentry::new(None, alloc::string::String::from("f"), inode.clone());
    vfs::File::new(inode, dentry, vfs::OpenFlags::empty())
}

fn req(id: u64, flags: u32) -> AddfdReq {
    AddfdReq { id, flags, srcfd: 3, newfd: 0, newfd_flags: 0 }
}

// A descriptor may only be injected into a task a supervisor is actually
// holding: before the notification is picked up the target has not been
// examined, and after it is answered the target is already leaving.
#[test]
fn an_injection_is_refused_outside_the_window_the_supervisor_holds() {
    let mut l = listener();
    let id = queued(&mut l);
    assert_eq!(l.addfd_queue(id, a_file(), &req(id, 0)), Err(Errno::Einprogress));
    assert_eq!(l.addfd_queue(id + 99, a_file(), &req(id + 99, 0)), Err(Errno::Enoent));
    l.recv();
    assert_eq!(l.addfd_queue(id, a_file(), &req(id, 0)), Ok(1));
    l.reply(NotifResp { id, val: 0, error: 0, flags: 0 }).unwrap();
    assert_eq!(l.addfd_queue(id, a_file(), &req(id, 0)), Err(Errno::Einprogress));
}

#[test]
fn the_notified_task_performs_each_injection_and_publishes_its_result() {
    let mut l = listener();
    let id = queued(&mut l);
    l.recv();
    let seq = l.addfd_queue(id, a_file(), &req(id, 0)).unwrap();
    assert!(l.actionable(id), "the target must wake to perform it");
    let a = l.addfd_take(id).expect("one injection is queued");
    assert_eq!(a.seq, seq);
    assert!(l.addfd_take(id).is_none());
    assert!(!l.addfd_settled(seq));
    l.addfd_complete(id, &a, 4);
    assert!(l.addfd_settled(seq));
    assert_eq!(l.addfd_collect(seq), Some(4));
    assert_eq!(l.addfd_collect(seq), None, "a collected result leaves the queue");
}

// Injection-and-reply in one step: the installed descriptor BECOMES the
// syscall's return value, and a failed install hands the notification back to
// the supervisor instead of completing the call with a descriptor that is not
// there.
#[test]
fn an_atomic_inject_and_reply_answers_with_the_descriptor_it_installed() {
    let mut l = listener();
    let id = queued(&mut l);
    l.recv();
    let seq = l.addfd_queue(id, a_file(), &req(id, ADDFD_FLAG_SEND)).unwrap();
    let a = l.addfd_take(id).unwrap();
    l.addfd_complete(id, &a, 6);
    assert_eq!(l.addfd_collect(seq), Some(6));
    assert_eq!(l.take_reply(id), Some((6, 0, 0)));

    let mut l = listener();
    let id = queued(&mut l);
    l.recv();
    let seq = l.addfd_queue(id, a_file(), &req(id, ADDFD_FLAG_SEND)).unwrap();
    let a = l.addfd_take(id).unwrap();
    let emfile = -(Errno::Emfile.as_i32() as i64);
    l.addfd_complete(id, &a, emfile);
    assert_eq!(l.addfd_collect(seq), Some(emfile));
    assert_eq!(l.take_reply(id), None, "the call is not answered");
    assert_eq!(l.id_valid(id), Ok(()), "the supervisor holds it again");
}

#[test]
fn an_atomic_inject_and_reply_is_refused_while_other_injections_are_queued() {
    let mut l = listener();
    let id = queued(&mut l);
    l.recv();
    l.addfd_queue(id, a_file(), &req(id, 0)).unwrap();
    assert_eq!(l.addfd_queue(id, a_file(), &req(id, ADDFD_FLAG_SEND)), Err(Errno::Ebusy));
}

#[test]
fn an_abandoned_or_withdrawn_injection_is_answered_rather_than_left_hanging() {
    let mut l = listener();
    let id = queued(&mut l);
    l.recv();
    let seq = l.addfd_queue(id, a_file(), &req(id, 0)).unwrap();
    assert!(l.addfd_cancel(id, seq), "still queued, so it can be withdrawn");
    assert!(!l.addfd_cancel(id, seq));

    let seq = l.addfd_queue(id, a_file(), &req(id, 0)).unwrap();
    l.addfd_abandon(id);
    assert_eq!(l.addfd_collect(seq), Some(-(Errno::Esrch.as_i32() as i64)),
               "the target is leaving, so nothing will ever perform it");
    // One the target already took is past withdrawing: its result is coming.
    let seq = l.addfd_queue(id, a_file(), &req(id, 0)).unwrap();
    let a = l.addfd_take(id).unwrap();
    assert!(!l.addfd_cancel(id, seq));
    l.addfd_complete(id, &a, 3);
    assert_eq!(l.addfd_collect(seq), Some(3));
}
