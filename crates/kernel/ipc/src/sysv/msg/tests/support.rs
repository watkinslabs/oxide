//! Fixtures shared by the `sysv::msg` hosted tests.
//!
//! Every test runs in its own freshly allocated IPC namespace so the shared
//! registry cannot leak state between tests running on different threads, and
//! builds its credentials explicitly: `current_ipc_cred()` reports the
//! all-capable root identity when no task is installed, and `CAP_IPC_OWNER`
//! would make every `ipcperms` check pass.

use alloc::vec;
use alloc::vec::Vec;
use namespace_identity::{NamespaceId, NamespaceKind, NamespaceRef};

use crate::sysv::msg::model::MTYPE_BYTES;
use crate::sysv::perm::IpcCred;

/// An IPC namespace held for the duration of one test; dropping it runs the
/// finalizer, which reaps the namespace's queues.
pub struct Ns {
    owner: NamespaceRef,
}

impl Ns {
    pub fn new() -> Self {
        let user = namespace_identity::initial(NamespaceKind::User);
        Self { owner: namespace_identity::allocate(NamespaceKind::Ipc, user, None).unwrap() }
    }

    pub fn id(&self) -> NamespaceId { self.owner.id() }
}

impl Drop for Ns {
    /// The fixture never routes through `IpcOwner`, so no finalizer is
    /// registered; reap explicitly to keep the shared registry clean.
    fn drop(&mut self) { crate::sysv::msg::model::reap_namespace(self.owner.id()); }
}

/// Credentials with no IPC-relevant capability, so `ipcperms` actually bites.
pub fn cred(euid: u32, egid: u32) -> IpcCred {
    IpcCred {
        euid,
        egid,
        groups: vfs::GroupList::empty(),
        cap_ipc_owner: false,
        cap_ipc_lock: false,
        cap_sys_admin: false,
        cap_sys_resource: false,
    }
}

/// The creator identity used by most tests: uncapped, uid/gid 0.
pub fn owner_cred() -> IpcCred { cred(0, 0) }

/// Uncapped identity that matches neither the owner nor the creator.
pub fn other_cred() -> IpcCred { cred(4242, 4242) }

/// Uncapped identity that still holds `CAP_SYS_RESOURCE`, for the `IPC_SET`
/// queue-size raise.
pub fn resource_cred() -> IpcCred {
    let mut c = owner_cred();
    c.cap_sys_resource = true;
    c
}

/// A `struct msgbuf` living in host memory. `user::validate` only NULL-checks
/// off the kernel target, so its address serves as the "user" pointer.
pub struct Buf {
    raw: Vec<u8>,
}

impl Buf {
    /// Outgoing `{mtype, mtext}`.
    pub fn out(mtype: i64, text: &[u8]) -> Self {
        let mut raw = Vec::with_capacity(MTYPE_BYTES + text.len());
        raw.extend_from_slice(&mtype.to_le_bytes());
        raw.extend_from_slice(text);
        Self { raw }
    }

    /// Incoming buffer with room for `cap` payload bytes.
    pub fn recv(cap: usize) -> Self { Self { raw: vec![0u8; MTYPE_BYTES + cap] } }

    /// Raw byte buffer of `len` bytes, for the `msgctl` structs.
    pub fn bytes(len: usize) -> Self { Self { raw: vec![0u8; len] } }

    pub fn ptr(&mut self) -> u64 { self.raw.as_mut_ptr() as u64 }

    pub fn mtype(&self) -> i64 {
        let mut v = [0u8; MTYPE_BYTES];
        v.copy_from_slice(&self.raw[..MTYPE_BYTES]);
        i64::from_le_bytes(v)
    }

    pub fn text(&self, n: usize) -> &[u8] { &self.raw[MTYPE_BYTES..MTYPE_BYTES + n] }

    pub fn raw(&self) -> &[u8] { &self.raw }

    pub fn raw_mut(&mut self) -> &mut [u8] { &mut self.raw }
}
