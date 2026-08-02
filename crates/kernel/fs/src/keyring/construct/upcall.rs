// The upcall itself: `call_sbin_request_key`.
//
// `/sbin/request-key <op> <key> <uid> <gid> <thread_ring> <process_ring>
//  <session_ring>` with a minimal environment, run through the usermode-helper
// machinery and waited for. The helper is given a session keyring of its own
// holding the authorisation token, which is how it obtains the authority to
// answer the key — it finds the token by searching its own keyrings.
//
// The actor is indirected because Linux indirects it (`key_type->request_key`
// overrides `call_sbin_request_key`): a key type can service its own requests
// in-kernel. Here the indirection is also what lets the hosted tests drive a
// helper that actually answers the key, which a real `/sbin/request-key` binary
// is needed for otherwise.

use alloc::string::String;
use alloc::vec::Vec;
use sync::{Spinlock, TaskList as TaskListClass};
use syscall::errno::Errno;

use super::super::ops::Ctx;
use super::super::store::Store;
use super::super::uapi::*;

/// Everything the helper needs, captured under the store lock so the upcall
/// itself can run without holding it.
pub struct HelperArgs {
    /// The key being built — what the helper answers.
    ///
    /// Part of the [`Upcall`] contract rather than of this module: an in-kernel
    /// actor is handed the request and must know which key it answers under
    /// which token. The `/sbin/request-key` actor reads both out of the
    /// prebuilt `argv` instead, so nothing in this crate reads the fields
    /// directly.
    #[allow(dead_code)]
    pub key: i32,
    /// The authorisation token granting the right to answer it.
    #[allow(dead_code)]
    pub authkey: i32,
    /// The helper's own session keyring, holding the token.
    pub helper_keyring: i32,
    /// `argv[1..]` — op, key serial, uid, gid, and the requester's three
    /// default keyrings, so the helper can cache intermediate results where the
    /// requester would.
    argv: Vec<String>,
}

impl HelperArgs {
    /// Build the argument vector and the helper's session keyring, and link the
    /// token into it. # C: O(N)
    pub fn build(g: &mut Store, c: &Ctx, key: i32, authkey: i32) -> Result<Self, Errno> {
        let helper_keyring = super::new_helper_keyring(g, key, &c.t)?;
        g.link(helper_keyring, authkey)?;
        let op = g.keys.get(&authkey).and_then(|k| k.auth.as_ref()).map(|a| a.op.clone())
            .unwrap_or_else(|| String::from(REQKEY_OP_CREATE));
        let thread = g.thread.get(&c.t.tid).copied().unwrap_or(0);
        let process = g.process.get(&c.t.tgid).copied().unwrap_or(0);
        // The session slot is never 0: absent a session keyring the requester's
        // user-session keyring stands in, so the helper always has somewhere to
        // look for the requester's keys.
        let session = match g.session.get(&c.t.tid).copied() {
            Some(s) => s,
            None => g.resolve(KEY_SPEC_USER_SESSION_KEYRING, &c.t)?,
        };
        Ok(Self { key, authkey, helper_keyring, argv: alloc::vec![
            op,
            alloc::format!("{key}"),
            alloc::format!("{}", c.t.fsuid),
            alloc::format!("{}", c.t.fsgid),
            alloc::format!("{thread}"),
            alloc::format!("{process}"),
            alloc::format!("{session}"),
        ]})
    }

    /// The argument list as the helper sees it, `argv[0]` included. # C: O(1)
    pub fn argv(&self) -> Vec<&[u8]> {
        let mut v: Vec<&[u8]> = alloc::vec![SBIN_REQUEST_KEY];
        for a in &self.argv { v.push(a.as_bytes()); }
        v
    }
}

/// A key-construction actor: given the request, answer the key (or fail).
/// Returns a wait-status-shaped value, negative for "the helper could not be
/// run at all".
pub type Upcall = fn(&HelperArgs) -> i64;

/// The installed actor. Empty means [`sbin_request_key`], exactly as Linux
/// falls back to `call_sbin_request_key` when a type provides none.
static ACTOR: Spinlock<Option<Upcall>, TaskListClass> = Spinlock::new(None);

/// Install a construction actor. The hosted tests use this to run a helper that
/// really answers the key; there is no `/sbin/request-key` binary to exec in a
/// test process. Test-only: the production path always reaches
/// [`sbin_request_key`]. # C: O(1)
#[cfg(test)]
pub fn set_actor_for_test(a: Option<Upcall>) { *ACTOR.lock() = a; }

/// Run the construction actor. # C: depends on the helper
pub fn run(args: &HelperArgs) -> i64 {
    let actor = *ACTOR.lock();
    match actor { Some(a) => a(args), None => sbin_request_key(args) }
}

/// `call_usermodehelper_keys(request_key, argv, envp, keyring, UMH_WAIT_PROC)`.
///
/// `UMH_WAIT_PROC` because the requester is blocked on the answer: returning
/// before the helper has run would hand back a key nobody has filled in yet.
/// The helper's session keyring is installed by the init callback, before it
/// execs, so the token is already reachable when it starts.
/// # C: depends on the helper
fn sbin_request_key(args: &HelperArgs) -> i64 {
    let mut info = umh::call_usermodehelper_setup(SBIN_REQUEST_KEY, &args.argv(),
        &umh::env::UPCALL_ENV, Some(install_helper_keyring), None,
        args.helper_keyring as usize);
    info.wait = umh::UMH_WAIT_PROC;
    umh::call_usermodehelper_exec(info, umh::UMH_WAIT_PROC) as i64
}

/// The helper's `umh_keys_init`: give the freshly forked helper the session
/// keyring holding its authorisation token. Without this the helper starts with
/// no token in reach and every `KEYCTL_ASSUME_AUTHORITY` it makes is ENOKEY.
/// # C: O(log N)
fn install_helper_keyring(info: &mut umh::SubprocessInfo, ctx: &umh::HelperCtx) -> i32 {
    let ring = info.data as i32;
    super::super::store::STORE.lock().session.insert(ctx.task.tid, ring);
    0
}

/// Drop the helper's session keyring once it has exited. The token is already
/// burned by this point; collecting the keyring releases the last reference to
/// it. # C: O(N)
pub fn teardown(g: &mut Store, args: &HelperArgs) {
    if let Some(k) = g.keys.get_mut(&args.helper_keyring) { k.members.clear(); }
    let tids: Vec<u32> = g.session.iter()
        .filter(|(_, &v)| v == args.helper_keyring).map(|(&k, _)| k).collect();
    for tid in tids { g.session.remove(&tid); }
    g.destroy(args.helper_keyring);
}
