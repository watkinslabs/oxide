// Minimal BPF LSM link registry.
//
// This is deliberately not listed as an active LSM module: links are accepted
// only for hook targets that this crate can call, and policy execution is still
// a later verifier/interpreter step.

extern crate alloc;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};

use sync::{Spinlock, TaskList as TaskListClass};
use syscall::errno::Errno;
use vfs::InodeRef;

/// Temporary Oxide-local hook id for `file_open` until a real BTF hook-id
/// table exists. Other target ids are rejected at BPF_LINK_CREATE time.
pub const FILE_OPEN_TARGET_BTF_ID: u32 = 1;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Hook {
    FileOpen,
}

pub struct LinkRecord {
    pub hook: Hook,
}

static NEXT_LINK_ID: AtomicU64 = AtomicU64::new(1);
static LINKS: Spinlock<BTreeMap<u64, LinkRecord>, TaskListClass> =
    Spinlock::new(BTreeMap::new());

pub fn hook_from_target_btf_id(target_btf_id: u32) -> Option<Hook> {
    match target_btf_id {
        FILE_OPEN_TARGET_BTF_ID => Some(Hook::FileOpen),
        _ => None,
    }
}

pub fn register(hook: Hook) -> u64 {
    let id = NEXT_LINK_ID.fetch_add(1, Ordering::Relaxed);
    LINKS.lock().insert(id, LinkRecord { hook });
    id
}

pub fn unregister(id: u64) {
    LINKS.lock().remove(&id);
}

/// Callable BPF LSM `file_open` hook.
///
/// Current foundation behavior is intentionally narrow: every live registered
/// BPF LSM link must target the recognized `file_open` hook. Program execution
/// and MAC decisions land with the eBPF verifier/interpreter layer.
/// # C: O(N_links)
pub fn file_open(_inode: &InodeRef) -> Result<(), i64> {
    let links = LINKS.lock();
    for link in links.values() {
        if link.hook != Hook::FileOpen {
            return Err(-(Errno::Eopnotsupp.as_i32() as i64));
        }
    }
    Ok(())
}
