// Id resolution, linking and the keyring roots a search or a possession test
// starts from — the graph primitives, with no permission decision in them.

use alloc::vec::Vec;
use syscall::errno::Errno;

use super::super::uapi::*;
use super::{LinkRestriction, Quota, Store, TaskIds};

impl Store {
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
            // `@a` is the authorisation token the caller has assumed; `@` is
            // the destination keyring recorded IN that token, so a helper
            // running under it caches the key it builds in the requester's
            // keyring rather than its own. Both exist only while an upcall is
            // being serviced.
            KEY_SPEC_REQKEY_AUTH_KEY => match self.authkey.get(&t.tid) {
                Some(&s) => s, None => return Err(Errno::Enokey),
            },
            KEY_SPEC_REQUESTOR_KEYRING => {
                let a = match self.authkey.get(&t.tid) { Some(&s) => s, None => return Err(Errno::Enokey) };
                let k = match self.keys.get(&a) { Some(k) => k, None => return Err(Errno::Enokey) };
                if k.revoked { return Err(Errno::Ekeyrevoked); }
                match k.auth.as_ref().map(|d| d.dest_keyring) {
                    Some(d) if d != 0 => d,
                    _ => return Err(Errno::Enokey),
                }
            }
            // `@g` plus 0 and every id below the defined range.
            _ => return Err(Errno::Einval),
        };
        Ok(s)
    }

    /// Link `child` into `ring`, idempotently. Enforces the ring's
    /// link restriction and rejects a self-link or a cycle
    /// (`keyring_detect_cycle` → EDEADLK). # C: O(members)
    pub fn link(&mut self, ring: i32, child: i32) -> Result<(), Errno> {
        if !self.keys.contains_key(&child) { return Err(Errno::Enokey); }
        if self.keys.get(&ring).map(|k| !k.is_keyring()).unwrap_or(true) {
            return if self.keys.contains_key(&ring) { Err(Errno::Enotdir) } else { Err(Errno::Enokey) };
        }
        if let Some(restriction) = self.keys[&ring].restriction {
            self.check_restriction(ring, child, restriction)?;
        }
        if ring == child || self.reaches(child, ring) { return Err(Errno::Edeadlk); }
        let k = self.keys.get_mut(&ring).expect("ring presence checked above");
        if !k.members.contains(&child) { k.members.push(child); }
        Ok(())
    }

    fn check_restriction(&self, ring: i32, child: i32, restriction: LinkRestriction) -> Result<(), Errno> {
        match restriction {
            LinkRestriction::Reject => Err(Errno::Eperm),
            LinkRestriction::Asymmetric { trusted, chain } => {
                let candidate = self.keys.get(&child).ok_or(Errno::Enokey)?;
                if candidate.key_type.name != ASYMMETRIC_KEY_TYPE { return Err(Errno::Eopnotsupp); }
                let cert = ::pkey::x509::parse(&candidate.payload).map_err(crate::keyring::ops::pkey::errno_for)?;
                let mut roots = alloc::vec::Vec::new();
                if let Some(trusted) = trusted { roots.push(trusted); }
                if chain { roots.push(ring); }
                let mut visited = alloc::vec::Vec::new();
                let mut parents = alloc::vec::Vec::new();
                while let Some(id) = roots.pop() {
                    if visited.contains(&id) { continue; }
                    visited.push(id);
                    let Some(key) = self.keys.get(&id) else { continue; };
                    if key.is_keyring() { roots.extend(key.members.iter().copied()); continue; }
                    if key.key_type.name != ASYMMETRIC_KEY_TYPE || key.asymmetric_name_id.as_deref() != Some(&cert.issuer) { continue; }
                    parents.push(id);
                }
                if parents.is_empty() { return Err(Errno::Enokey); }
                let mut first = Errno::Ekeyrejected;
                for parent in parents {
                    let key = ::pkey::AsymmetricKey::parse(&self.keys[&parent].payload)
                        .map_err(crate::keyring::ops::pkey::errno_for)?;
                    match key.verify_certificate(&cert) {
                        Ok(()) => return Ok(()),
                        Err(error) => first = crate::keyring::ops::pkey::errno_for(error),
                    }
                }
                Err(first)
            }
        }
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
