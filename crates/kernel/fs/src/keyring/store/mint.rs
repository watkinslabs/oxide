// `key_alloc` and its callers: the one place a serial is handed out and a
// `struct key` enters the store, in each of the states Linux allocates one in.

use alloc::string::String;
use alloc::vec::Vec;
use syscall::errno::Errno;

use super::super::types::{self, KeyType};
use super::super::uapi::*;
use super::{Key, Quota, Store, TaskIds};

/// The index-key namespace fields a mint stamps onto the new key: the domain
/// tag its type is indexed under, and the user namespace it is published in.
/// Derived once from the minting caller so no mint site can compute a
/// different answer for the same type.
#[derive(Copy, Clone, Debug)]
pub struct KeyNs { pub domain: u64, pub user_ns: u64 }

impl KeyNs {
    /// The namespace stamp `key_alloc` applies for `t` creating a key of `ty`.
    /// # C: O(1)
    pub fn of(t: &TaskIds, ty: &KeyType) -> Self {
        Self { domain: t.domain_for(ty), user_ns: t.user_ns }
    }
    /// The boot namespaces with the default domain. Every production mint
    /// derives its stamp from a real caller through [`KeyNs::of`], so this
    /// exists for the tests that mint a key directly against the store rather
    /// than through an op core. # C: O(1)
    #[cfg(test)]
    pub const fn initial() -> Self { Self { domain: DEFAULT_KEY_DOMAIN, user_ns: INITIAL_USER_NS } }
}

impl Store {
    /// Mint a key of `ty` with an explicit perm mask, charging `quota_bytes`
    /// of payload plus the description (`desclen + 1`, Linux's `quotalen`) to
    /// `uid`. # C: O(log N)
    pub fn mint_with_perm(&mut self, ty: &'static KeyType, desc: &str, payload: Vec<u8>,
        uid: u32, gid: u32, perm: u32, quota_bytes: u64, mode: Quota, ns: KeyNs) -> Result<i32, Errno>
    {
        self.alloc(ty, desc, payload, uid, gid, perm, quota_bytes, mode, KEY_IS_POSITIVE, ns)
    }

    /// `key_alloc` with `KEY_ALLOC_NOT_IN_QUOTA`: the key is charged nothing and
    /// its death refunds nothing. The authorisation token and the persistent
    /// keyrings are allocated this way, so servicing a request cannot itself
    /// push the servicing uid over its quota. # C: O(log N)
    pub fn mint_not_in_quota(&mut self, ty: &'static KeyType, desc: &str, uid: u32, gid: u32,
        perm: u32, ns: KeyNs) -> Result<i32, Errno>
    {
        let serial = self.alloc(ty, desc, Vec::new(), uid, gid, perm, 0, Quota::Overrun, KEY_IS_POSITIVE, ns)?;
        let k = self.keys.get_mut(&serial).expect("just inserted under the held lock");
        k.in_quota = false;
        k.quotalen = 0;
        if let Some(u) = self.quota.get_mut(&uid) {
            u.nkeys = u.nkeys.saturating_sub(1);
            u.nbytes = u.nbytes.saturating_sub(desc.len() as u64 + 1);
        }
        Ok(serial)
    }

    /// `construct_alloc_key`: mint a key in [`KEY_IS_UNINSTANTIATED`] state with
    /// `KEY_FLAG_USER_CONSTRUCT` set. Until something instantiates or negates
    /// it, a full lookup of it is EIO and a requester waiting on it blocks.
    /// # C: O(log N)
    pub fn mint_uninstantiated(&mut self, ty: &'static KeyType, desc: &str, uid: u32, gid: u32,
        perm: u32, quota_bytes: u64, ns: KeyNs) -> Result<i32, Errno>
    {
        let serial = self.alloc(ty, desc, Vec::new(), uid, gid, perm, quota_bytes,
            Quota::InQuota, KEY_IS_UNINSTANTIATED, ns)?;
        self.keys.get_mut(&serial).expect("just inserted under the held lock").under_construction = true;
        Ok(serial)
    }

    /// The one `key_alloc`. # C: O(log N)
    fn alloc(&mut self, ty: &'static KeyType, desc: &str, payload: Vec<u8>, uid: u32, gid: u32,
        perm: u32, quota_bytes: u64, mode: Quota, state: i32, ns: KeyNs) -> Result<i32, Errno>
    {
        let quotalen = desc.len() as u64 + 1 + quota_bytes;
        self.charge(uid, quotalen, mode)?;
        let serial = self.next_serial;
        // Serials are positive; the allocator skips 0 and negatives because
        // negative values are the special-keyring namespace.
        self.next_serial = match self.next_serial.checked_add(1) { Some(n) => n, None => FIRST_SERIAL };
        self.keys.insert(serial, Key {
            serial, key_type: ty, description: String::from(desc),
            domain: ns.domain, user_ns: ns.user_ns, payload,
            asymmetric_ids: Vec::new(), asymmetric_name_id: None, perm, uid, gid,
            quotalen, in_quota: true,
            expiry_ns: 0, revoked: false, invalidated: false,
            members: Vec::new(), restriction: None,
            state, under_construction: false, auth: None,
            watchers: crate::watch_queue::WatchList::new(),
        });
        Ok(serial)
    }

    /// Mint a key with the type's `KEY_PERM_UNDEF` default perm. # C: O(log N)
    pub fn mint(&mut self, ty: &'static KeyType, desc: &str, payload: Vec<u8>, uid: u32, gid: u32,
        quota_bytes: u64, ns: KeyNs) -> Result<i32, Errno>
    {
        let perm = types::default_perm(ty);
        self.mint_with_perm(ty, desc, payload, uid, gid, perm, quota_bytes, Quota::InQuota, ns)
    }

    /// Mint a fresh anonymous keyring with an explicit perm. # C: O(log N)
    pub fn new_keyring(&mut self, desc: &str, uid: u32, gid: u32, perm: u32, mode: Quota, ns: KeyNs)
        -> Result<i32, Errno>
    {
        self.mint_with_perm(types::keyring_type(), desc, Vec::new(), uid, gid, perm, 0, mode, ns)
    }
}
