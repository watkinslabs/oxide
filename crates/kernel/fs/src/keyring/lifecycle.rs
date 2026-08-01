// Task-lifecycle keyring hooks — the points where Linux's keyring state lives
// in `cred` and therefore moves with `copy_creds`, `prepare_exec_creds` and the
// final `put_cred`. This store keys that state by tid/tgid instead of by cred
// pointer, so the same three transitions have to be applied explicitly.
//
// Getting these wrong is not cosmetic. Without the exit hook a tid's session
// keyring outlives it and a RECYCLED tid inherits a dead task's keys; without
// the fork hook a child cannot see the session keyring `pam_keyinit` installed
// for the login session it belongs to, which is the whole point of a session
// keyring.

use super::store::STORE;

/// `copy_creds`: the child's cred is a copy of the parent's, so it starts out
/// pointing at the SAME session keyring and carries the same
/// `jit_keyring` default. That holds for a new thread and a new process alike.
///
/// What is NOT copied:
///   * the thread keyring — `copy_creds` drops it (`new->thread_keyring =
///     NULL`), so a child never inherits its parent's `@t`. Keyed by tid here,
///     a fresh tid has none, which is the same state.
///   * the process keyring — inherited only within a thread group
///     (`if (!(clone_flags & CLONE_THREAD)) new->process_keyring = NULL`).
///     Keyed by tgid here, a `CLONE_THREAD` child shares its parent's tgid and
///     therefore its `@p`, while a fork gets a new tgid and none — again the
///     same state, without a flag to consult.
/// # C: O(log N)
pub fn fork(parent_tid: u32, child_tid: u32) {
    let mut g = STORE.lock();
    if let Some(&s) = g.session.get(&parent_tid) { g.session.insert(child_tid, s); }
    if let Some(&j) = g.jit.get(&parent_tid) { g.jit.insert(child_tid, j); }
}

/// `prepare_exec_creds`: a newly exec'd program gets no thread keyring and a
/// fresh (absent) process keyring, and INHERITS the session keyring. Dropping
/// the first two is what stops a key left behind by the pre-exec program from
/// being visible to the new image, which matters most across a setuid exec.
///
/// Any authority the task had assumed is dropped with the cred too — a helper
/// that execs something else must not hand that program the right to
/// instantiate the key it was asked to build.
/// # C: O(N)
pub fn exec(tid: u32, tgid: u32) {
    let mut g = STORE.lock();
    g.thread.remove(&tid);
    g.process.remove(&tgid);
    g.authkey.remove(&tid);
    g.collect();
}

/// The final `put_cred`: the task's thread keyring, its assumed authority and
/// its `jit_keyring` setting die with it, and its session-keyring reference is
/// dropped. `last_thread` also releases the thread group's process keyring.
///
/// The per-uid user and user-session keyrings deliberately survive: they belong
/// to the uid, not to any task, and Linux keeps them until the `key_user`
/// itself goes away.
///
/// `collect` then destroys whatever that left unreferenced and refunds its
/// quota charge — without this a long-running system leaks a keyring per task
/// forever, and the owner's key quota with it.
/// # C: O(N)
pub fn exit(tid: u32, tgid: u32, last_thread: bool) {
    let mut g = STORE.lock();
    g.thread.remove(&tid);
    g.session.remove(&tid);
    g.jit.remove(&tid);
    g.authkey.remove(&tid);
    if last_thread { g.process.remove(&tgid); }
    g.collect();
}

/// `key_fsuid_changed` / `key_fsgid_changed`: the thread keyring is owned by
/// whoever the task's filesystem ids say it is, so a task that changes them
/// takes its `@t` with it. Skipping this strands the keyring under the old
/// owner, where the task can no longer reach it through the user perm byte.
/// # C: O(log N)
pub fn fsids_changed(tid: u32, fsuid: u32, fsgid: u32) {
    let mut g = STORE.lock();
    let s = match g.thread.get(&tid) { Some(&s) => s, None => return };
    if let Some(k) = g.keys.get_mut(&s) { k.uid = fsuid; k.gid = fsgid; }
}

#[cfg(test)] mod tests;
