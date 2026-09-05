//! Inode-owned NT open/share claims.
extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use sync::{Inode as InodeLockClass, Spinlock};

use super::InodeRef;

pub const FILE_READ_DATA: u32 = 0x0001;
pub const FILE_WRITE_DATA: u32 = 0x0002;
pub const FILE_APPEND_DATA: u32 = 0x0004;
pub const FILE_EXECUTE: u32 = 0x0020;
pub const DELETE: u32 = 0x0001_0000;
pub const GENERIC_READ: u32 = 0x8000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const GENERIC_ALL: u32 = 0x1000_0000;
pub const SHARE_READ: u32 = 0x1;
pub const SHARE_WRITE: u32 = 0x2;
pub const SHARE_DELETE: u32 = 0x4;

const READ_ACCESS: u32 = FILE_READ_DATA | FILE_EXECUTE;
const WRITE_ACCESS: u32 = FILE_WRITE_DATA | FILE_APPEND_DATA;
const ALL_ACCESS: u32 = READ_ACCESS | WRITE_ACCESS | DELETE;
const VALID_SHARING: u32 = SHARE_READ | SHARE_WRITE | SHARE_DELETE;
const MAPPING_IMAGE: u32 = 0x8000_0000;
const MAPPING_WRITE: u32 = 0x4000_0000;
const MAPPING_ACCESS: u32 = 0x2000_0000;
const VALID_MAPPING: u32 = MAPPING_IMAGE | MAPPING_WRITE | MAPPING_ACCESS;

#[derive(Copy, Clone)]
struct Claim {
    access: u32,
    sharing: u32,
    mapping: u32,
    token: u64,
}

struct State { claims: Vec<Claim> }

/// One canonical share-state owner for every live open of an inode. # C: O(1)
pub struct WindowsShareContext {
    state: Spinlock<State, InodeLockClass>,
    next: AtomicU64,
}

/// Lifetime token retained by the NT file or section object. # C: O(1)
pub struct WindowsFileShare {
    inode: InodeRef,
    token: u64,
}

impl WindowsShareContext {
    /// Construct empty inode-owned state. # C: O(1)
    pub fn new() -> Self {
        Self { state: Spinlock::new(State { claims: Vec::new() }), next: AtomicU64::new(1) }
    }

    /// Admit an ordinary open after checking both sides of the share contract. # C: O(N_claims)
    pub fn claim(&self, inode: InodeRef, access: u32, sharing: u32) -> Option<Arc<WindowsFileShare>> {
        self.insert(inode, access, sharing, 0)
    }

    /// Admit a file mapping using its distinct mapping access contract. # C: O(N_claims)
    pub fn claim_mapping(&self, inode: InodeRef, mapping: u32) -> Option<Arc<WindowsFileShare>> {
        if mapping & !VALID_MAPPING != 0 || mapping & MAPPING_ACCESS == 0 { return None; }
        self.insert(inode, 0, VALID_SHARING, mapping)
    }

    fn insert(&self, inode: InodeRef, access: u32, sharing: u32, mapping: u32) -> Option<Arc<WindowsFileShare>> {
        if sharing & !VALID_SHARING != 0 { return None; }
        let mut state = self.state.lock();
        if state.claims.iter().any(|old| conflicts(access, sharing, mapping, *old)) { return None; }
        let token = self.next.fetch_add(1, Ordering::Relaxed);
        state.claims.push(Claim { access, sharing, mapping, token });
        Some(Arc::new(WindowsFileShare { inode, token }))
    }

    fn release(&self, token: u64) {
        let mut state = self.state.lock();
        if let Some(index) = state.claims.iter().position(|claim| claim.token == token) {
            state.claims.swap_remove(index);
        }
    }

    #[cfg(test)]
    fn count(&self) -> usize { self.state.lock().claims.len() }
}

impl Default for WindowsShareContext { fn default() -> Self { Self::new() } }

impl Drop for WindowsFileShare {
    fn drop(&mut self) { self.inode.windows_share_context().release(self.token); }
}

fn ordinary_access(access: u32) -> u32 {
    (access & (READ_ACCESS | WRITE_ACCESS | DELETE))
        | if access & GENERIC_READ != 0 { READ_ACCESS } else { 0 }
        | if access & GENERIC_WRITE != 0 { WRITE_ACCESS } else { 0 }
        | if access & GENERIC_ALL != 0 { ALL_ACCESS } else { 0 }
}

fn conflicts(access: u32, sharing: u32, mapping: u32, old: Claim) -> bool {
    let requested = ordinary_access(access);
    let existing = ordinary_access(old.access);
    let existing_sharing = if existing != 0 { old.sharing } else { VALID_SHARING };
    if requested & READ_ACCESS != 0 && existing_sharing & SHARE_READ == 0 { return true; }
    if requested & WRITE_ACCESS != 0 && existing_sharing & SHARE_WRITE == 0 { return true; }
    if requested & DELETE != 0 && existing_sharing & SHARE_DELETE == 0 { return true; }
    if old.mapping & MAPPING_WRITE != 0 && sharing & SHARE_WRITE == 0 { return true; }
    if old.mapping & MAPPING_IMAGE != 0 && requested & (WRITE_ACCESS | DELETE) != 0 { return true; }
    if requested == 0 && mapping == 0 { return false; }
    if existing & READ_ACCESS != 0 && sharing & SHARE_READ == 0 { return true; }
    if existing & WRITE_ACCESS != 0 && sharing & SHARE_WRITE == 0 { return true; }
    if existing & DELETE != 0 && sharing & SHARE_DELETE == 0 { return true; }
    false
}

/// Claim mapping access against the inode that owns the file. # C: O(N_claims)
pub fn mapping_claim(file: &crate::File, access: u32) -> Option<Arc<WindowsFileShare>> {
    file.inode().windows_share_context().claim_mapping(file.inode().clone(), access)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inode() -> InodeRef { crate::make_static_file_inode(b"windows-share") }

    #[test]
    fn contention_and_final_release_are_inode_scoped() {
        let i = inode();
        let c = i.windows_share_context();
        let first = c.claim(i.clone(), FILE_READ_DATA, SHARE_READ).unwrap();
        assert!(c.claim(i.clone(), FILE_WRITE_DATA, SHARE_WRITE).is_none());
        drop(first);
        assert!(c.claim(i.clone(), FILE_WRITE_DATA, SHARE_WRITE).is_some());
    }

    #[test]
    fn invalid_masks_are_rejected_without_state_mutation() {
        let i = inode();
        let c = i.windows_share_context();
        assert!(c.claim(i.clone(), FILE_READ_DATA, 8).is_none());
        assert!(c.claim_mapping(i.clone(), MAPPING_IMAGE).is_none());
        assert_eq!(c.count(), 0);
    }

    #[test]
    fn metadata_only_open_ignores_requested_share_mode() {
        let i = inode();
        let c = i.windows_share_context();
        let first = c.claim(i.clone(), FILE_READ_DATA, SHARE_READ).unwrap();
        assert!(c.claim(i.clone(), 0, 0).is_some());
        drop(first);
    }

    #[test]
    fn execute_and_append_are_access_classes() {
        let i = inode();
        let c = i.windows_share_context();
        let execute = c.claim(i.clone(), FILE_EXECUTE, SHARE_READ).unwrap();
        assert!(c.claim(i.clone(), FILE_READ_DATA, SHARE_WRITE).is_none());
        drop(execute);
        let append = c.claim(i.clone(), FILE_APPEND_DATA, SHARE_WRITE).unwrap();
        assert!(c.claim(i.clone(), FILE_WRITE_DATA, SHARE_READ).is_none());
        drop(append);
    }

    #[test]
    fn mappings_use_the_same_inode_owner_and_rules() {
        let i = inode();
        let c = i.windows_share_context();
        let open = c.claim(i.clone(), FILE_WRITE_DATA, SHARE_READ).unwrap();
        assert!(c.claim_mapping(i.clone(), MAPPING_ACCESS | MAPPING_WRITE).is_some());
        drop(open);
        let image = c.claim_mapping(i.clone(), MAPPING_ACCESS | MAPPING_IMAGE).unwrap();
        assert!(c.claim(i.clone(), FILE_WRITE_DATA, VALID_SHARING).is_none());
        drop(image);
    }

    #[test]
    fn distinct_inodes_cannot_contend_by_inode_number() {
        let a = inode();
        let b = inode();
        let _ = a.windows_share_context().claim(a.clone(), FILE_READ_DATA, 0).unwrap();
        assert!(b.windows_share_context().claim(b.clone(), FILE_WRITE_DATA, 0).is_some());
    }
}
