// Canonical inode-owned Windows open/share claims.
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
const SHARE_MASK: u32 = SHARE_READ | SHARE_WRITE | SHARE_DELETE;
const ACCESS_MASK: u32 = FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_EXECUTE | DELETE;
const MAPPING_ACCESS: u32 = 1 << 26;
const MAPPING_WRITE: u32 = 1 << 27;
const MAPPING_IMAGE: u32 = 1 << 28;

#[derive(Copy, Clone)] struct Claim { desired: u32, sharing: u32, token: u64 }
struct State { claims: Vec<Claim> }

/// Share claims for all Windows opens of this canonical inode. # C: O(1)
pub struct WindowsShareContext { state: Spinlock<State, InodeLockClass>, next: AtomicU64 }
/// Guard retained by the NT object until its final duplicated handle closes. # C: O(1)
pub struct WindowsFileShare { inode: InodeRef, token: u64 }

impl WindowsShareContext {
    pub fn new() -> Self { Self { state: Spinlock::new(State { claims: Vec::new() }), next: AtomicU64::new(1) } }
    /// Atomically admit an open when the inode's existing claims allow it. # C: O(N_claims)
    pub fn claim(&self, inode: InodeRef, desired: u32, sharing: u32) -> Option<Arc<WindowsFileShare>> {
        if sharing & !SHARE_MASK != 0 { return None; }
        let mut state = self.state.lock();
        if state.claims.iter().any(|old| conflicts(desired, sharing, *old)) { return None; }
        let token = self.next.fetch_add(1, Ordering::Relaxed);
        state.claims.push(Claim { desired, sharing, token });
        Some(Arc::new(WindowsFileShare { inode, token }))
    }
    fn release(&self, token: u64) { let mut state = self.state.lock(); if let Some(i) = state.claims.iter().position(|c| c.token == token) { state.claims.swap_remove(i); } }
    #[cfg(test)] fn count(&self) -> usize { self.state.lock().claims.len() }
}
impl Default for WindowsShareContext { fn default() -> Self { Self::new() } }
impl Drop for WindowsFileShare { fn drop(&mut self) { self.inode.windows_share_context().release(self.token); } }

/// Claim Wine's file-backed mapping access against the inode owner. # C: O(N_claims)
pub fn mapping_claim(file: &crate::File, access: u32) -> Option<Arc<WindowsFileShare>> {
    const IMAGE: u32 = 0x8000_0000; const WRITE: u32 = 0x4000_0000; const ACCESS: u32 = 0x2000_0000;
    if access & !(IMAGE | WRITE | ACCESS) != 0 || access & ACCESS == 0 { return None; }
    let desired = MAPPING_ACCESS | if access & IMAGE != 0 { MAPPING_IMAGE } else { 0 }
        | if access & WRITE != 0 { MAPPING_WRITE } else { 0 };
    file.inode().windows_share_context().claim(file.inode().clone(), desired, SHARE_MASK)
}

fn conflicts(desired: u32, sharing: u32, old: Claim) -> bool {
    let read = desired & (FILE_READ_DATA | FILE_EXECUTE | GENERIC_READ | GENERIC_ALL) != 0;
    let write = desired & (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE | GENERIC_ALL) != 0;
    let delete = desired & (DELETE | GENERIC_ALL) != 0;
    let old_read = old.desired & (FILE_READ_DATA | FILE_EXECUTE | GENERIC_READ | GENERIC_ALL) != 0;
    let old_write = old.desired & (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE | GENERIC_ALL) != 0;
    let old_delete = old.desired & (DELETE | GENERIC_ALL) != 0;
    let mut existing_sharing = SHARE_MASK;
    if old.desired & ACCESS_MASK != 0 { existing_sharing &= old.sharing; }
    if (read && existing_sharing & SHARE_READ == 0)
        || (write && existing_sharing & SHARE_WRITE == 0)
        || (delete && existing_sharing & SHARE_DELETE == 0) { return true; }
    if (old.desired & MAPPING_WRITE != 0) && sharing & SHARE_WRITE == 0 { return true; }
    if (old.desired & MAPPING_IMAGE != 0) && desired & FILE_WRITE_DATA != 0 { return true; }
    if desired & ACCESS_MASK == 0 { return false; }
    (old_read && sharing & SHARE_READ == 0) || (old_write && sharing & SHARE_WRITE == 0)
        || (old_delete && sharing & SHARE_DELETE == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn inode() -> InodeRef { crate::make_static_file_inode(b"share") }
    #[test]
    fn contention_and_final_release() {
        let i = inode(); let c = i.windows_share_context();
        let first = c.claim(i.clone(), FILE_READ_DATA, SHARE_READ).unwrap();
        assert!(c.claim(i.clone(), FILE_WRITE_DATA, SHARE_WRITE).is_none());
        drop(first); assert!(c.claim(i.clone(), FILE_WRITE_DATA, SHARE_WRITE).is_some());
    }
    #[test]
    fn invalid_masks_and_metadata_only_open() {
        let i = inode(); let c = i.windows_share_context();
        assert!(c.claim(i.clone(), FILE_READ_DATA, 8).is_none());
        assert!(c.claim(i.clone(), FILE_READ_DATA | (1 << 24), SHARE_MASK).is_some());
        let first = c.claim(i.clone(), FILE_READ_DATA, 0).unwrap();
        let metadata = c.claim(i.clone(), 0, 0).unwrap();
        assert_eq!(c.count(), 2); drop(first); assert_eq!(c.count(), 1);
        drop(metadata);
    }
    #[test]
    fn claims_are_isolated_by_inode_identity() {
        let a = inode(); let b = inode();
        let _first = a.windows_share_context().claim(a.clone(), FILE_READ_DATA, 0).unwrap();
        assert!(b.windows_share_context().claim(b.clone(), FILE_WRITE_DATA, 0).is_some());
    }
    #[test]
    fn mapping_markers_are_validated_and_writable_mapping_is_tracked() {
        let i = inode(); let c = i.windows_share_context();
        assert!(c.claim(i.clone(), MAPPING_ACCESS | (1 << 24), SHARE_MASK).is_some());
        let mapping = c.claim(i.clone(), MAPPING_ACCESS | MAPPING_WRITE, SHARE_MASK).unwrap();
        assert!(c.claim(i.clone(), FILE_READ_DATA, 0).is_none());
        assert!(c.claim(i.clone(), FILE_READ_DATA, SHARE_WRITE).is_some());
        drop(mapping);
    }
}
