// The fork / exec / exit transitions. Each test uses a unique tid+uid because
// the STORE is a process-global static shared across the whole suite.

use super::*;
use super::super::ops::*;
use super::super::store::{TaskIds, STORE};
use super::super::uapi::*;

fn ctx(tid: u32, uid: u32) -> super::super::ops::Ctx {
    super::super::ops::Ctx::new(
        TaskIds { tid, tgid: tid, fsuid: uid, fsgid: uid, groups: alloc::vec::Vec::new() }, 0, false)
}

fn thread_ctx(tid: u32, tgid: u32, uid: u32) -> super::super::ops::Ctx {
    super::super::ops::Ctx::new(
        TaskIds { tid, tgid, fsuid: uid, fsgid: uid, groups: alloc::vec::Vec::new() }, 0, false)
}

// A forked child shares the parent's session keyring — the reason a login
// session's keys are visible to every process pam_keyinit's shell spawns.
#[test]
fn fork_inherits_the_session_keyring() {
    let parent = ctx(4101, 4101);
    let child  = ctx(4102, 4101);
    let ps = join_session(&parent, None);
    fork(parent.t.tid, child.t.tid);
    assert_eq!(get_keyring_id(&child, KEY_SPEC_SESSION_KEYRING, true), ps);
}

// ... and the `jit_keyring` default, which is a cred field too. A child that
// lost it would upcall into a different keyring than its parent configured.
#[test]
fn fork_inherits_the_reqkey_default() {
    let parent = ctx(4103, 4103);
    let child  = ctx(4104, 4103);
    assert_eq!(set_reqkey_keyring(&parent, KEY_REQKEY_DEFL_SESSION_KEYRING),
        KEY_REQKEY_DEFL_THREAD_KEYRING as i64);
    fork(parent.t.tid, child.t.tid);
    assert_eq!(set_reqkey_keyring(&child, KEY_REQKEY_DEFL_NO_CHANGE),
        KEY_REQKEY_DEFL_SESSION_KEYRING as i64,
        "the child reads back the parent's setting, not the boot default");
}

// The thread keyring is NOT inherited: `copy_creds` drops it, so a child never
// sees a key its parent put in `@t`.
#[test]
fn fork_does_not_inherit_the_thread_keyring() {
    let parent = ctx(4105, 4105);
    let child  = ctx(4106, 4105);
    let pt = get_keyring_id(&parent, KEY_SPEC_THREAD_KEYRING, true);
    fork(parent.t.tid, child.t.tid);
    let ct = get_keyring_id(&child, KEY_SPEC_THREAD_KEYRING, true);
    assert_ne!(pt, ct, "@t is per-thread, never inherited");
}

// A CLONE_THREAD child shares its parent's tgid and therefore its process
// keyring; a fork gets a new tgid and a distinct one.
#[test]
fn the_process_keyring_is_shared_within_a_thread_group_only() {
    let leader = ctx(4107, 4107);
    let sibling = thread_ctx(4108, 4107, 4107);
    let forked = ctx(4109, 4107);
    let p = get_keyring_id(&leader, KEY_SPEC_PROCESS_KEYRING, true);
    assert_eq!(get_keyring_id(&sibling, KEY_SPEC_PROCESS_KEYRING, true), p,
        "threads of one process share @p");
    assert_ne!(get_keyring_id(&forked, KEY_SPEC_PROCESS_KEYRING, true), p,
        "a separate process does not");
}

// exec drops the thread and process keyrings and keeps the session keyring —
// a key the pre-exec image left in @t must not be readable by the new program.
#[test]
fn exec_drops_thread_and_process_keyrings_but_keeps_the_session() {
    let t = ctx(4110, 4110);
    let ses = join_session(&t, None);
    let th = get_keyring_id(&t, KEY_SPEC_THREAD_KEYRING, true);
    let pr = get_keyring_id(&t, KEY_SPEC_PROCESS_KEYRING, true);
    exec(t.t.tid, t.t.tgid);
    assert_eq!(get_keyring_id(&t, KEY_SPEC_SESSION_KEYRING, true), ses);
    assert_ne!(get_keyring_id(&t, KEY_SPEC_THREAD_KEYRING, true), th);
    assert_ne!(get_keyring_id(&t, KEY_SPEC_PROCESS_KEYRING, true), pr);
}

// exec does NOT divest assumed instantiation authority. `/sbin/request-key`
// assumes authority over the key it was asked to build and then execs the
// handler its configuration names, so a kernel that divested here would give
// that handler no authority and no construction could ever complete.
#[test]
fn exec_keeps_assumed_authority() {
    let t = ctx(4111, 4111);
    STORE.lock().authkey.insert(t.t.tid, 0x7fff_0000);
    exec(t.t.tid, t.t.tgid);
    assert_eq!(STORE.lock().authkey.get(&t.t.tid).copied(), Some(0x7fff_0000),
        "the token survives the exec into the handler");
}

// ... and a fork carries it to the child, because `prepare_creds` takes a
// reference to the same token. The handler answers the key from a FORKED
// `keyctl instantiate`, so a child without the token is EPERM.
#[test]
fn fork_inherits_assumed_authority() {
    let parent = ctx(4119, 4119);
    let child = ctx(4120, 4119);
    STORE.lock().authkey.insert(parent.t.tid, 0x7fff_0001);
    fork(parent.t.tid, child.t.tid);
    assert_eq!(STORE.lock().authkey.get(&child.t.tid).copied(), Some(0x7fff_0001));
}

// A child of a task holding no token gets none — the inheritance is a copy of
// what the parent had, never a lazily created authority.
#[test]
fn fork_grants_no_authority_the_parent_did_not_hold() {
    let parent = ctx(4121, 4121);
    let child = ctx(4122, 4121);
    STORE.lock().authkey.remove(&parent.t.tid);
    fork(parent.t.tid, child.t.tid);
    assert!(STORE.lock().authkey.get(&child.t.tid).is_none());
}

// Exit purges the dying tid's entries, so a RECYCLED tid does not inherit a
// dead task's session keyring. Without this the maps grow without bound and a
// new task can read the previous occupant's keys.
#[test]
fn exit_purges_the_tid_and_frees_the_keyring() {
    let t = ctx(4112, 4112);
    let ses = join_session(&t, None);
    let _th = get_keyring_id(&t, KEY_SPEC_THREAD_KEYRING, true);
    let charged = STORE.lock().key_user(4112).nkeys;
    assert!(charged > 0);
    exit(t.t.tid, t.t.tgid, true);
    {
        let g = STORE.lock();
        assert!(g.session.get(&t.t.tid).is_none());
        assert!(g.thread.get(&t.t.tid).is_none());
        assert!(g.process.get(&t.t.tgid).is_none());
        assert!(g.keys.get(&(ses as i32)).is_none(), "the unreferenced session keyring is collected");
    }
    // A recycled tid starts clean rather than inheriting the dead task's ring.
    let reused = ctx(4112, 4112);
    assert_ne!(get_keyring_id(&reused, KEY_SPEC_SESSION_KEYRING, true), ses);
}

// The quota charge comes back on exit — otherwise a task-churning system
// eventually EDQUOTs its own users out of keys they no longer hold.
#[test]
fn exit_refunds_the_quota_charge() {
    let t = ctx(4113, 4113);
    join_session(&t, None);
    get_keyring_id(&t, KEY_SPEC_THREAD_KEYRING, true);
    assert!(STORE.lock().key_user(4113).nkeys > 0);
    exit(t.t.tid, t.t.tgid, true);
    assert_eq!(STORE.lock().key_user(4113).nkeys, 0, "every charge is refunded");
    assert_eq!(STORE.lock().key_user(4113).nbytes, 0);
}

// A thread exiting does NOT take the thread group's process keyring with it;
// only the last one does.
#[test]
fn a_non_final_thread_exit_keeps_the_process_keyring() {
    let leader = ctx(4114, 4114);
    let sibling = thread_ctx(4115, 4114, 4114);
    let p = get_keyring_id(&leader, KEY_SPEC_PROCESS_KEYRING, true);
    exit(sibling.t.tid, sibling.t.tgid, false);
    assert_eq!(get_keyring_id(&leader, KEY_SPEC_PROCESS_KEYRING, true), p);
    exit(leader.t.tid, leader.t.tgid, true);
    assert!(STORE.lock().process.get(&leader.t.tgid).is_none());
}

// The per-uid keyrings belong to the uid, not the task, and survive its death.
#[test]
fn exit_leaves_the_user_keyrings_alone() {
    let t = ctx(4116, 4116);
    let u = get_keyring_id(&t, KEY_SPEC_USER_KEYRING, true);
    exit(t.t.tid, t.t.tgid, true);
    assert_eq!(STORE.lock().user.get(&4116).copied(), Some(u as i32));
}

// Changing the filesystem ids moves the thread keyring's ownership with them,
// so the task still reaches its own `@t` through the user perm byte.
#[test]
fn fsid_change_moves_thread_keyring_ownership() {
    let t = ctx(4117, 4117);
    let th = get_keyring_id(&t, KEY_SPEC_THREAD_KEYRING, true) as i32;
    assert_eq!(STORE.lock().keys[&th].uid, 4117);
    fsids_changed(t.t.tid, 4118, 4119);
    let g = STORE.lock();
    assert_eq!(g.keys[&th].uid, 4118);
    assert_eq!(g.keys[&th].gid, 4119);
}
