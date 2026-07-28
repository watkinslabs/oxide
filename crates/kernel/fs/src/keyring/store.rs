// The live key/keyring store: `struct key` state, the serial space, the
// per-task/per-uid special-keyring maps, and the raw mint/resolve/link
// primitives. No permission decisions here — those are `perm.rs`; no op
// policy — that is `ops/`.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use sync::{Spinlock, TaskList as TaskListClass};
use syscall::errno::Errno;

use super::types::{self, KeyType};
use super::uapi::*;

/// Caller identity every op resolves special keyrings against and that
/// `perm::key_task_permission` checks ownership against. Linux keys are
/// owned by and checked against the FILESYSTEM ids (`cred->fsuid` /
/// `cred->fsgid` in `key_alloc` and `key_task_permission`), not the effective
/// ids — a process under `setfsuid()` sees a different key world.
#[derive(Clone, Debug, Default)]
pub struct TaskIds {
    pub tid: u32,
    pub tgid: u32,
    pub fsuid: u32,
    pub fsgid: u32,
    /// `cred->group_info`, walked by `groups_search` when the key's gid is
    /// not the caller's fsgid.
    pub groups: Vec<u32>,
}

impl TaskIds {
    /// Does the caller subscribe to `gid` — `gid_eq(gid, cred->fsgid) ||
    /// groups_search(cred->group_info, gid)` (Linux `in_group_p`). # C: O(groups)
    pub fn in_group(&self, gid: u32) -> bool {
        gid != GID_INVALID && (gid == self.fsgid || self.groups.contains(&gid))
    }
}

/// One `struct key`. A keyring is a key of type `keyring` whose `members`
/// holds the linked child serials.
pub struct Key {
    pub serial: i32,
    pub key_type: &'static KeyType,
    pub description: String,
    pub payload: Vec<u8>,
    pub perm: u32,
    pub uid: u32,
    pub gid: u32,
    /// `key->expiry` in monotonic ns; 0 = never (Linux `TIME64_MAX`/0 sentinel).
    pub expiry_ns: u64,
    /// `KEY_FLAG_REVOKED` — `key_validate` turns this into EKEYREVOKED.
    pub revoked: bool,
    /// `KEY_FLAG_INVALIDATED` — `key_validate` turns this into ENOKEY, and
    /// the gc unlinks it from every keyring.
    pub invalidated: bool,
    /// Keyring only: linked member serials.
    pub members: Vec<i32>,
    /// Keyring only: `key->restrict_link == restrict_link_reject`, installed
    /// by `KEYCTL_RESTRICT_KEYRING` with a NULL type. Every subsequent link
    /// into this ring is EPERM.
    pub restrict_reject: bool,
}

impl Key {
    /// # C: O(1)
    pub fn is_keyring(&self) -> bool { self.key_type.is_keyring }
}

pub struct Store {
    pub next_serial: i32,
    pub keys: BTreeMap<i32, Key>,
    pub session:  BTreeMap<u32, i32>, // tid  -> session keyring serial
    pub thread:   BTreeMap<u32, i32>, // tid  -> thread keyring
    pub process:  BTreeMap<u32, i32>, // tgid -> process keyring
    pub user:     BTreeMap<u32, i32>, // uid  -> user keyring
    pub usersess: BTreeMap<u32, i32>, // uid  -> user-session keyring
    /// `cred->jit_keyring` (`KEYCTL_SET_REQKEY_KEYRING`), per tid. Absent
    /// means `KEY_REQKEY_DEFL_THREAD_KEYRING`, Linux's boot default.
    pub jit:      BTreeMap<u32, i32>,
}

pub static STORE: Spinlock<Store, TaskListClass> = Spinlock::new(Store {
    next_serial: FIRST_SERIAL,
    keys: BTreeMap::new(),
    session:  BTreeMap::new(),
    thread:   BTreeMap::new(),
    process:  BTreeMap::new(),
    user:     BTreeMap::new(),
    usersess: BTreeMap::new(),
    jit:      BTreeMap::new(),
});

impl Store {
    /// Mint a key of `ty` with an explicit perm mask. # C: O(log N)
    pub fn mint_with_perm(&mut self, ty: &'static KeyType, desc: &str, payload: Vec<u8>,
        uid: u32, gid: u32, perm: u32) -> i32
    {
        let serial = self.next_serial;
        // Linux serials are positive; `key_alloc_serial` skips 0 and negatives
        // because negative values are the special-keyring namespace.
        self.next_serial = match self.next_serial.checked_add(1) { Some(n) => n, None => FIRST_SERIAL };
        self.keys.insert(serial, Key {
            serial, key_type: ty, description: String::from(desc), payload, perm, uid, gid,
            expiry_ns: 0, revoked: false, invalidated: false,
            members: Vec::new(), restrict_reject: false,
        });
        serial
    }

    /// Mint a key with the type's `KEY_PERM_UNDEF` default perm. # C: O(log N)
    pub fn mint(&mut self, ty: &'static KeyType, desc: &str, payload: Vec<u8>, uid: u32, gid: u32) -> i32 {
        let perm = types::default_perm(ty);
        self.mint_with_perm(ty, desc, payload, uid, gid, perm)
    }

    /// Mint a fresh anonymous keyring with an explicit perm. # C: O(log N)
    pub fn new_keyring(&mut self, desc: &str, uid: u32, gid: u32, perm: u32) -> i32 {
        self.mint_with_perm(types::keyring_type(), desc, Vec::new(), uid, gid, perm)
    }

    /// Resolve a special (negative) keyring id to a real serial, lazily
    /// creating the caller's keyring with the perm mask Linux gives it. A
    /// positive serial passes through; 0 → None. # C: O(log N)
    pub fn resolve(&mut self, id: i32, t: &TaskIds) -> Option<i32> {
        if id >= 0 { return if id == 0 { None } else { Some(id) }; }
        let s = match id {
            KEY_SPEC_THREAD_KEYRING => {
                if let Some(&v) = self.thread.get(&t.tid) { v }
                else { let v = self.new_keyring("_tid", t.fsuid, t.fsgid, THREAD_KEYRING_PERM);
                       self.thread.insert(t.tid, v); v }
            }
            KEY_SPEC_PROCESS_KEYRING => {
                if let Some(&v) = self.process.get(&t.tgid) { v }
                else { let v = self.new_keyring("_pid", t.fsuid, t.fsgid, THREAD_KEYRING_PERM);
                       self.process.insert(t.tgid, v); v }
            }
            KEY_SPEC_SESSION_KEYRING => {
                if let Some(&v) = self.session.get(&t.tid) { v }
                else { let v = self.new_keyring("_ses", t.fsuid, t.fsgid, SESSION_KEYRING_PERM);
                       self.session.insert(t.tid, v); v }
            }
            KEY_SPEC_USER_KEYRING => {
                if let Some(&v) = self.user.get(&t.fsuid) { v }
                else { let v = self.new_keyring("_uid", t.fsuid, GID_INVALID, USER_KEYRING_PERM);
                       self.user.insert(t.fsuid, v); v }
            }
            KEY_SPEC_USER_SESSION_KEYRING => {
                if let Some(&v) = self.usersess.get(&t.fsuid) { v }
                else { let v = self.new_keyring("_uid_ses", t.fsuid, GID_INVALID, USER_KEYRING_PERM);
                       self.usersess.insert(t.fsuid, v); v }
            }
            _ => return None,
        };
        Some(s)
    }

    /// Link `child` into `ring`, idempotently. Enforces the ring's
    /// `restrict_link` (Linux `restrict_link_reject` → EPERM) and rejects a
    /// self-link or a cycle (`keyring_detect_cycle` → EDEADLK). # C: O(members)
    pub fn link(&mut self, ring: i32, child: i32) -> Result<(), Errno> {
        if !self.keys.contains_key(&child) { return Err(Errno::Enokey); }
        if self.keys.get(&ring).map(|k| !k.is_keyring()).unwrap_or(true) {
            return if self.keys.contains_key(&ring) { Err(Errno::Enotdir) } else { Err(Errno::Enokey) };
        }
        if self.keys[&ring].restrict_reject { return Err(Errno::Eperm); }
        if ring == child || self.reaches(child, ring) { return Err(Errno::Edeadlk); }
        let k = self.keys.get_mut(&ring).expect("ring presence checked above");
        if !k.members.contains(&child) { k.members.push(child); }
        Ok(())
    }

    /// Is `to` reachable from keyring `from` through nested keyrings? Linux
    /// `keyring_detect_cycle`. # C: O(members)
    pub fn reaches(&self, from: i32, to: i32) -> bool {
        let mut visited: Vec<i32> = Vec::new();
        let mut stack: Vec<i32> = alloc::vec![from];
        while let Some(cur) = stack.pop() {
            if cur == to { return true; }
            if visited.contains(&cur) { continue; }
            visited.push(cur);
            if let Some(k) = self.keys.get(&cur) {
                if !k.is_keyring() { continue; }
                for &m in &k.members { stack.push(m); }
            }
        }
        false
    }

    /// The caller's own keyring roots, in Linux's `search_cred_keyrings_rcu`
    /// order: thread, process, then session — or, when no session keyring
    /// exists, the user-session keyring. Peeks only; never lazily creates.
    /// # C: O(log N)
    pub fn cred_roots(&self, t: &TaskIds) -> Vec<i32> {
        let mut roots: Vec<i32> = Vec::new();
        if let Some(&v) = self.thread.get(&t.tid) { roots.push(v); }
        if let Some(&v) = self.process.get(&t.tgid) { roots.push(v); }
        match self.session.get(&t.tid) {
            Some(&v) => roots.push(v),
            None => if let Some(&v) = self.usersess.get(&t.fsuid) { roots.push(v); },
        }
        roots
    }

    /// Every keyring the caller possesses through, for `is_key_possessed`.
    /// Linux computes possession from the same cred keyrings the search walks,
    /// plus the user keyring reached by linkage. # C: O(log N)
    pub fn possession_roots(&self, t: &TaskIds) -> Vec<i32> {
        let mut roots = self.cred_roots(t);
        if let Some(&v) = self.user.get(&t.fsuid) { if !roots.contains(&v) { roots.push(v); } }
        if let Some(&v) = self.usersess.get(&t.fsuid) { if !roots.contains(&v) { roots.push(v); } }
        roots
    }
}
