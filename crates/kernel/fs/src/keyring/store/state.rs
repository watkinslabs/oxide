// The global store and its lock. Every map here is a `cred` field or a kernel-
// wide register in Linux, keyed by the id that owns it.

use alloc::collections::BTreeMap;
use sync::{Spinlock, TaskList as TaskListClass};

use super::{Key, KeyUser};
use super::super::uapi::FIRST_SERIAL;

pub struct Store {
    pub next_serial: i32,
    pub keys: BTreeMap<i32, Key>,
    pub session:  BTreeMap<u32, i32>, // tid  -> session keyring serial
    pub thread:   BTreeMap<u32, i32>, // tid  -> thread keyring
    pub process:  BTreeMap<u32, i32>, // tgid -> process keyring
    /// `_uid.<uid>` inside the user namespace's `.user_reg` register: the
    /// register is per user namespace, so the pair — not the uid alone — is
    /// what names a user keyring.
    pub user:     BTreeMap<(u64, u32), i32>, // (user_ns, uid) -> user keyring
    /// `_uid_ses.<uid>` in the same per-namespace register.
    pub usersess: BTreeMap<(u64, u32), i32>, // (user_ns, uid) -> user-session keyring
    /// `cred->jit_keyring` (`KEYCTL_SET_REQKEY_KEYRING`), per tid. Absent
    /// means `KEY_REQKEY_DEFL_THREAD_KEYRING`, Linux's boot default.
    pub jit:      BTreeMap<u32, i32>,
    /// The `key_user` tree: per-uid key/byte quota accounting.
    pub quota:    BTreeMap<u32, KeyUser>,
    /// `cred->request_key_auth`, per tid: the authorisation token this task has
    /// assumed with `KEYCTL_ASSUME_AUTHORITY`. Absent means the task holds no
    /// authority, which is what makes the whole instantiation family EPERM for
    /// an ordinary caller.
    pub authkey:  BTreeMap<u32, i32>,
    /// `ns->persistent_keyring_register` — the `.persistent_register` keyring
    /// holding every `_persistent.<uid>`, ONE PER USER NAMESPACE as the field
    /// name says. Absent for a namespace until its first
    /// `KEYCTL_GET_PERSISTENT` creates it.
    pub persistent_register: BTreeMap<u64, i32>,
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
    authkey:  BTreeMap::new(),
    persistent_register: BTreeMap::new(),
});
