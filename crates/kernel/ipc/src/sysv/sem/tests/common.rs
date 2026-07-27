//! Shared fixtures for the semaphore tests.

use namespace_identity::{allocate, NamespaceId, NamespaceKind};

use super::super::super::perm::IpcCred;
use super::super::{model, undo};

/// The registry is a process-wide static; every test serialises on this and
/// resets it first.
pub static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn reset() {
    model::reset_for_test();
    undo::reset_for_test();
}

/// A fresh, private IPC namespace so ids from one test cannot leak into another.
pub fn ns() -> NamespaceId {
    let user = namespace_identity::initial(NamespaceKind::User);
    allocate(NamespaceKind::Ipc, user, None).unwrap().id()
}

pub fn cred(euid: u32, egid: u32) -> IpcCred {
    IpcCred {
        euid, egid,
        groups: vfs::GroupList::empty(),
        cap_ipc_owner: false,
        cap_ipc_lock: false,
        cap_sys_admin: false,
        cap_sys_resource: false,
    }
}

/// Root with every IPC capability, matching what `current_ipc_cred` reports
/// when no task is installed.
pub fn root() -> IpcCred {
    IpcCred {
        euid: 0, egid: 0,
        groups: vfs::GroupList::empty(),
        cap_ipc_owner: true,
        cap_ipc_lock: true,
        cap_sys_admin: true,
        cap_sys_resource: true,
    }
}

/// `user::read_bytes`/`write_bytes` only NULL-check off the kernel target, so a
/// host buffer's address is a valid stand-in for a user pointer.
pub fn uptr<T>(buf: &[T]) -> u64 { buf.as_ptr() as u64 }

pub fn uptr_mut<T>(buf: &mut [T]) -> u64 { buf.as_mut_ptr() as u64 }
