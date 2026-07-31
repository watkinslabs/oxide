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

/// How a mint interacts with the owner's `key_user` quota.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Quota {
    /// `KEY_ALLOC_IN_QUOTA`: charge, and refuse with EDQUOT when the charge
    /// would exceed the owner's key-count or byte limit.
    InQuota,
    /// `KEY_ALLOC_QUOTA_OVERRUN`: charge, but never refuse. The implicit
    /// thread / process / anonymous-session keyrings use this — a task that has
    /// exhausted its quota must still be able to have keyrings installed for
    /// it, or it could not be given any credentials at all.
    Overrun,
}

/// Per-uid `struct key_user` quota accounting.
#[derive(Clone, Copy, Default, Debug)]
pub struct KeyUser {
    /// `qnkeys` — keys currently charged to this uid.
    pub nkeys: u64,
    /// `qnbytes` — bytes currently charged to this uid.
    pub nbytes: u64,
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
    /// `key->quotalen` — the byte charge this key currently holds against
    /// `key->user`. `key_payload_reserve` moves it by the payload delta on
    /// every update, and the whole charge is refunded when the key dies.
    pub quotalen: u64,
    /// `KEY_FLAG_IN_QUOTA` — false only for a key allocated outside the quota
    /// system, whose death refunds nothing.
    pub in_quota: bool,
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
    /// The `key_user` tree: per-uid key/byte quota accounting.
    pub quota:    BTreeMap<u32, KeyUser>,
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
    quota:    BTreeMap::new(),
});

/// A uid's key-count ceiling — `key_quota_root_maxkeys` for root, else
/// `key_quota_maxkeys`. # C: O(1)
pub fn max_keys(uid: u32) -> u64 {
    if uid == ROOT_UID { KEY_QUOTA_ROOT_MAXKEYS } else { KEY_QUOTA_MAXKEYS }
}

/// A uid's key-byte ceiling — `key_quota_root_maxbytes` / `key_quota_maxbytes`.
/// # C: O(1)
pub fn max_bytes(uid: u32) -> u64 {
    if uid == ROOT_UID { KEY_QUOTA_ROOT_MAXBYTES } else { KEY_QUOTA_MAXBYTES }
}

impl Store {
    /// The uid's current charge, zero when it has never held a key. The
    /// production paths mutate the entry in place through `charge` /
    /// `payload_reserve` / `destroy`; this read-only view is what the hosted
    /// tests assert the charge and the refund against. # C: O(log N)
    #[cfg(test)]
    pub fn key_user(&self, uid: u32) -> KeyUser {
        self.quota.get(&uid).copied().unwrap_or_default()
    }

    /// `key_alloc`'s quota arm: charge `nbytes` and one key to `uid`, refusing
    /// with EDQUOT when either ceiling would be crossed. `Quota::Overrun`
    /// charges unconditionally. # C: O(log N)
    fn charge(&mut self, uid: u32, nbytes: u64, mode: Quota) -> Result<(), Errno> {
        let u = self.quota.entry(uid).or_default();
        if mode == Quota::InQuota
            && (u.nkeys + 1 > max_keys(uid) || u.nbytes + nbytes > max_bytes(uid))
        {
            return Err(Errno::Edquot);
        }
        u.nkeys += 1;
        u.nbytes += nbytes;
        Ok(())
    }

    /// `key_payload_reserve`: move an existing key's byte charge by the delta
    /// between its current and its new payload quota, refusing an INCREASE
    /// that would cross the owner's byte ceiling. A decrease always succeeds.
    /// Only the byte charge moves; the key count is unchanged. # C: O(log N)
    pub fn payload_reserve(&mut self, serial: i32, new_quota: u64) -> Result<(), Errno> {
        let (uid, old, in_quota) = match self.keys.get(&serial) {
            Some(k) => (k.uid, k.quotalen, k.in_quota),
            None => return Err(Errno::Enokey),
        };
        // `key->quotalen` covers the description too; only the payload part moves.
        let base = self.keys[&serial].description.len() as u64 + 1;
        let new_total = base + new_quota;
        if !in_quota { self.keys.get_mut(&serial).expect("presence proved above").quotalen = new_total; return Ok(()); }
        let u = self.quota.entry(uid).or_default();
        if new_total > old {
            let delta = new_total - old;
            if u.nbytes + delta > max_bytes(uid) { return Err(Errno::Edquot); }
            u.nbytes += delta;
        } else {
            u.nbytes -= old - new_total;
        }
        self.keys.get_mut(&serial).expect("presence proved above").quotalen = new_total;
        Ok(())
    }

    /// `key_put`'s last-reference arm: hand the key's whole charge back to its
    /// owner and drop it from the serial space. # C: O(log N)
    pub fn destroy(&mut self, serial: i32) {
        let k = match self.keys.remove(&serial) { Some(k) => k, None => return };
        if !k.in_quota { return; }
        if let Some(u) = self.quota.get_mut(&k.uid) {
            u.nkeys = u.nkeys.saturating_sub(1);
            u.nbytes = u.nbytes.saturating_sub(k.quotalen);
        }
    }

    /// The key gc: destroy every key no keyring links to and that is not
    /// itself one of the special per-task/per-uid keyrings, refunding its
    /// quota. Linux reaches the same state by refcounting — a key whose last
    /// link goes away has no references left and the gc collects it — and this
    /// is what makes a quota charge releasable at all. Iterates to a fixed
    /// point so a collected keyring releases its own members. # C: O(N * links)
    pub fn collect(&mut self) {
        loop {
            let mut linked: Vec<i32> = Vec::new();
            for k in self.keys.values() { if k.is_keyring() { linked.extend_from_slice(&k.members); } }
            for m in [&self.session, &self.thread, &self.process, &self.user, &self.usersess] {
                for &v in m.values() { linked.push(v); }
            }
            let dead: Vec<i32> = self.keys.keys().copied().filter(|s| !linked.contains(s)).collect();
            if dead.is_empty() { return; }
            for s in dead { self.destroy(s); }
        }
    }

    /// Mint a key of `ty` with an explicit perm mask, charging `quota_bytes`
    /// of payload plus the description (`desclen + 1`, Linux's `quotalen`) to
    /// `uid`. # C: O(log N)
    pub fn mint_with_perm(&mut self, ty: &'static KeyType, desc: &str, payload: Vec<u8>,
        uid: u32, gid: u32, perm: u32, quota_bytes: u64, mode: Quota) -> Result<i32, Errno>
    {
        let quotalen = desc.len() as u64 + 1 + quota_bytes;
        self.charge(uid, quotalen, mode)?;
        let serial = self.next_serial;
        // Serials are positive; the allocator skips 0 and negatives because
        // negative values are the special-keyring namespace.
        self.next_serial = match self.next_serial.checked_add(1) { Some(n) => n, None => FIRST_SERIAL };
        self.keys.insert(serial, Key {
            serial, key_type: ty, description: String::from(desc), payload, perm, uid, gid,
            quotalen, in_quota: true,
            expiry_ns: 0, revoked: false, invalidated: false,
            members: Vec::new(), restrict_reject: false,
        });
        Ok(serial)
    }

    /// Mint a key with the type's `KEY_PERM_UNDEF` default perm. # C: O(log N)
    pub fn mint(&mut self, ty: &'static KeyType, desc: &str, payload: Vec<u8>, uid: u32, gid: u32,
        quota_bytes: u64) -> Result<i32, Errno>
    {
        let perm = types::default_perm(ty);
        self.mint_with_perm(ty, desc, payload, uid, gid, perm, quota_bytes, Quota::InQuota)
    }

    /// Mint a fresh anonymous keyring with an explicit perm. # C: O(log N)
    pub fn new_keyring(&mut self, desc: &str, uid: u32, gid: u32, perm: u32, mode: Quota)
        -> Result<i32, Errno>
    {
        self.mint_with_perm(types::keyring_type(), desc, Vec::new(), uid, gid, perm, 0, mode)
    }

    /// Resolve a keyring id to a real serial, lazily creating the caller's
    /// special keyring with the perm mask it is given.
    ///
    /// A positive serial passes through. Everything else is a special id, and
    /// the errnos are NOT interchangeable:
    ///   * `@t/@p/@s/@u/@us` (-1..-5) resolve, creating on demand;
    ///   * `@g` (-6) is EINVAL — group keyrings have never been implemented,
    ///     and reporting ENOKEY instead would tell a caller the facility exists
    ///     but is empty;
    ///   * `@a` (-7) and `@` (-8) name the instantiation authorisation key and
    ///     the requestor's keyring, which exist only inside a `request_key`
    ///     upcall; with no upcall in flight they are ENOKEY;
    ///   * **0, and any id below -8, are EINVAL** — an id of 0 is not a
    ///     shorthand for the session keyring, and silently treating it as one
    ///     turns a caller's uninitialised keyring argument into a successful
    ///     key insertion.
    /// # C: O(log N)
    pub fn resolve(&mut self, id: i32, t: &TaskIds) -> Result<i32, Errno> {
        if id >= 1 { return Ok(id); }
        // The implicit thread / process / anonymous-session keyrings are
        // allocated with the quota OVERRUN flag: they are charged but never
        // refused, because a task that has hit its quota must still be able to
        // hold credentials. The per-uid keyrings are IN_QUOTA and can EDQUOT.
        let s = match id {
            KEY_SPEC_THREAD_KEYRING => {
                if let Some(&v) = self.thread.get(&t.tid) { v }
                else { let v = self.new_keyring("_tid", t.fsuid, t.fsgid, THREAD_KEYRING_PERM, Quota::Overrun)?;
                       self.thread.insert(t.tid, v); v }
            }
            KEY_SPEC_PROCESS_KEYRING => {
                if let Some(&v) = self.process.get(&t.tgid) { v }
                else { let v = self.new_keyring("_pid", t.fsuid, t.fsgid, THREAD_KEYRING_PERM, Quota::Overrun)?;
                       self.process.insert(t.tgid, v); v }
            }
            KEY_SPEC_SESSION_KEYRING => {
                if let Some(&v) = self.session.get(&t.tid) { v }
                else { let v = self.new_keyring("_ses", t.fsuid, t.fsgid, SESSION_KEYRING_PERM, Quota::Overrun)?;
                       self.session.insert(t.tid, v); v }
            }
            KEY_SPEC_USER_KEYRING => {
                if let Some(&v) = self.user.get(&t.fsuid) { v }
                else { let v = self.new_keyring("_uid", t.fsuid, GID_INVALID, USER_KEYRING_PERM, Quota::InQuota)?;
                       self.user.insert(t.fsuid, v); v }
            }
            KEY_SPEC_USER_SESSION_KEYRING => {
                if let Some(&v) = self.usersess.get(&t.fsuid) { v }
                else { let v = self.new_keyring("_uid_ses", t.fsuid, GID_INVALID, USER_KEYRING_PERM, Quota::InQuota)?;
                       self.usersess.insert(t.fsuid, v); v }
            }
            // The authorisation-key ids name objects that exist only during a
            // `request_key` upcall.
            KEY_SPEC_REQKEY_AUTH_KEY | KEY_SPEC_REQUESTOR_KEYRING => return Err(Errno::Enokey),
            // `@g` plus 0 and every id below the defined range.
            _ => return Err(Errno::Einval),
        };
        Ok(s)
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
