// The per-uid `key_user` quota: the charge/refund arithmetic `key_alloc` and `key_payload_reserve` perform, and
// the gc that makes a charge releasable.

use alloc::vec::Vec;
use syscall::errno::Errno;

use super::{max_bytes, max_keys, KeyUser, Quota, Store};

/// `key_alloc`'s ceiling test: one more key, and `add_bytes` more bytes, must
/// both still fit. Taking the two ceilings as arguments is what lets the
/// `/proc/sys/kernel/keys/` knobs be proved to GATE an allocation rather than
/// merely to store a number — the alternative, lowering a global ceiling inside
/// a test, would make every concurrently running test see it. # C: O(1)
pub fn over_quota(u: &KeyUser, add_bytes: u64, maxkeys: u64, maxbytes: u64) -> bool {
    u.nkeys + 1 > maxkeys || u.nbytes + add_bytes > maxbytes
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
    pub(super) fn charge(&mut self, uid: u32, nbytes: u64, mode: Quota) -> Result<(), Errno> {
        let (maxkeys, maxbytes) = (max_keys(uid), max_bytes(uid));
        let u = self.quota.entry(uid).or_default();
        if mode == Quota::InQuota && over_quota(u, nbytes, maxkeys, maxbytes) {
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
        let mut k = match self.keys.remove(&serial) { Some(k) => k, None => return };
        // A watcher is told the object it watched has gone, so a queue never
        // just stops producing with no explanation.
        k.watchers.remove_all();
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
            for m in [&self.session, &self.thread, &self.process, &self.user, &self.usersess,
                      &self.authkey] {
                for &v in m.values() { linked.push(v); }
            }
            if let Some(r) = self.persistent_register { linked.push(r); }
            // A key still under construction is referenced by the requester
            // waiting on it and by the authorisation token naming it, neither
            // of which is a keyring link.
            let held: Vec<i32> = self.keys.values()
                .filter(|k| k.under_construction).map(|k| k.serial)
                .chain(self.keys.values().filter_map(|k| k.auth.as_ref().map(|a| a.target)))
                .collect();
            linked.extend_from_slice(&held);
            // A request in flight holds its authorisation token, and the
            // keyring the helper will reach that token through. Between the
            // token being minted and the helper task being handed that keyring
            // as its session, NEITHER is reachable from any gc root — a
            // collection in that window (any other task unlinking a key is
            // enough to trigger one) destroys the token and strands the
            // requester on a key no helper can now answer.
            let tokens: Vec<i32> = self.keys.values()
                .filter(|k| k.auth.is_some()).map(|k| k.serial).collect();
            for k in self.keys.values() {
                if k.is_keyring() && k.members.iter().any(|m| tokens.contains(m)) {
                    linked.push(k.serial);
                }
            }
            linked.extend_from_slice(&tokens);
            let dead: Vec<i32> = self.keys.keys().copied().filter(|s| !linked.contains(s)).collect();
            if dead.is_empty() { return; }
            for s in dead { self.destroy(s); }
        }
    }
}
