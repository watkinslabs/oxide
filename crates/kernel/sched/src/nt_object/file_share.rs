//! Native file-share claims, separate from Linux open-file flags.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use sync::{Spinlock, TaskList as TaskListClass};

const READ_DATA: u32 = 0x0001;
const WRITE_DATA: u32 = 0x0002;
const DELETE: u32 = 0x0001_0000;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const SHARE_RELEVANT_ACCESS: u32 = READ_DATA | WRITE_DATA | DELETE
    | GENERIC_READ | GENERIC_WRITE | GENERIC_ALL;
const SHARE_READ: u32 = 0x1;
const SHARE_WRITE: u32 = 0x2;
const SHARE_DELETE: u32 = 0x4;
const WINE_MAPPING_IMAGE: u32 = 0x8000_0000;
const WINE_MAPPING_WRITE: u32 = 0x4000_0000;
const WINE_MAPPING_ACCESS: u32 = 0x2000_0000;
// Keep Wine's mapping markers out of the Windows access-mask namespace. The
// native claim record is shared with ordinary opens, whose GENERIC_* bits use
// the same high bits as Wine's private mapping markers.
const MAPPING_IMAGE: u32 = 1 << 28;
const MAPPING_WRITE: u32 = 1 << 27;
const MAPPING_ACCESS: u32 = 1 << 26;
const MAPPING_RELEVANT_ACCESS: u32 = MAPPING_IMAGE | MAPPING_WRITE | MAPPING_ACCESS;

#[derive(Copy, Clone, Eq, PartialEq)]
struct ActiveClaim { key: (u64, u64), desired: u32, sharing: u32, token: u64 }

static CLAIMS: Spinlock<Vec<ActiveClaim>, TaskListClass> = Spinlock::new(Vec::new());
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);

/// One live NT open's share claim. Cloned handles retain one claim until the
/// final NT object reference is dropped.
pub struct NtFileShare { token: u64, key: (u64, u64) }

impl NtFileShare {
    /// Claim Windows sharing rights for one canonical VFS file. # C: O(N_claims)
    pub fn claim(file: &vfs::File, desired: u32, sharing: u32) -> Option<Arc<Self>> {
        claim(file, desired, sharing)
    }

    /// Claim a file-backed section's mapping access for its object lifetime.
    /// # C: O(N_claims)
    pub fn claim_mapping(file: &vfs::File, access: u32) -> Option<Arc<Self>> {
        if access & !(WINE_MAPPING_IMAGE | WINE_MAPPING_WRITE | WINE_MAPPING_ACCESS) != 0
            || access & WINE_MAPPING_ACCESS == 0 { return None; }
        let desired = MAPPING_ACCESS
            | if access & WINE_MAPPING_IMAGE != 0 { MAPPING_IMAGE } else { 0 }
            | if access & WINE_MAPPING_WRITE != 0 { MAPPING_WRITE } else { 0 };
        let key = (file.mnt_id(), file.inode().ino());
        claim_key(key, desired, SHARE_READ | SHARE_WRITE | SHARE_DELETE)
    }
}

impl Drop for NtFileShare {
    fn drop(&mut self) {
        let mut claims = CLAIMS.lock();
        if let Some(index) = claims.iter().position(|claim| claim.token == self.token && claim.key == self.key) { claims.swap_remove(index); }
    }
}

fn conflicts(desired: u32, sharing: u32, active: ActiveClaim) -> bool {
    // Wine's server ignores a new open's share mask when that open requests
    // no read, write, or delete access. Metadata-only handles therefore do
    // not turn an existing deny mode into a sharing violation.
    if desired & (SHARE_RELEVANT_ACCESS | MAPPING_RELEVANT_ACCESS) == 0 { return false; }
    let read = desired & (READ_DATA | GENERIC_READ | GENERIC_ALL) != 0;
    let write = desired & (WRITE_DATA | GENERIC_WRITE | GENERIC_ALL) != 0;
    let delete = desired & (DELETE | GENERIC_ALL) != 0;
    let old_read = active.desired & (READ_DATA | GENERIC_READ | GENERIC_ALL) != 0;
    let old_write = active.desired & (WRITE_DATA | GENERIC_WRITE | GENERIC_ALL) != 0;
    let old_delete = active.desired & (DELETE | GENERIC_ALL) != 0;
    let mapping_write = desired & MAPPING_WRITE != 0;
    let old_mapping_write = active.desired & MAPPING_WRITE != 0;
    let old_mapping_image = active.desired & MAPPING_IMAGE != 0;
    (read && active.sharing & SHARE_READ == 0) || (old_read && sharing & SHARE_READ == 0)
        || (write && active.sharing & SHARE_WRITE == 0) || (old_write && sharing & SHARE_WRITE == 0)
        || (delete && active.sharing & SHARE_DELETE == 0) || (old_delete && sharing & SHARE_DELETE == 0)
        || (mapping_write && active.sharing & SHARE_WRITE == 0)
        || (old_mapping_write && sharing & SHARE_WRITE == 0)
        || (old_mapping_image && (write || delete))
}

fn claim(file: &vfs::File, desired: u32, sharing: u32) -> Option<Arc<NtFileShare>> {
    if sharing & !(SHARE_READ | SHARE_WRITE | SHARE_DELETE) != 0 { return None; }
    let key = (file.mnt_id(), file.inode().ino());
    claim_key(key, desired, sharing)
}

fn claim_key(key: (u64, u64), desired: u32, sharing: u32) -> Option<Arc<NtFileShare>> {
    let mut claims = CLAIMS.lock();
    if claims.iter().any(|active| active.key == key && conflicts(desired, sharing, *active)) { return None; }
    let token = NEXT_TOKEN.fetch_add(1, Ordering::Relaxed);
    claims.push(ActiveClaim { key, desired, sharing, token });
    Some(Arc::new(NtFileShare { token, key }))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pair(a: u32, as_: u32, b: u32, bs: u32) -> bool {
        conflicts(b, bs, ActiveClaim { key: (1, 1), desired: a, sharing: as_, token: 1 })
    }
    #[test]
    fn each_access_class_requires_matching_share_both_ways() {
        assert!(pair(READ_DATA, 0, READ_DATA, SHARE_READ));
        assert!(pair(READ_DATA, SHARE_READ, READ_DATA, 0));
        assert!(pair(WRITE_DATA, 0, WRITE_DATA, SHARE_WRITE));
        assert!(pair(DELETE, 0, DELETE, SHARE_DELETE));
        assert!(!pair(READ_DATA, SHARE_READ, READ_DATA, SHARE_READ));
        assert!(!pair(WRITE_DATA, SHARE_READ | SHARE_WRITE, READ_DATA, SHARE_READ | SHARE_WRITE));
    }
    #[test]
    fn generic_access_masks_participate_in_conflicts() {
        assert!(pair(GENERIC_READ, 0, READ_DATA, SHARE_READ));
        assert!(pair(READ_DATA, 0, GENERIC_READ, SHARE_READ));
        assert!(pair(GENERIC_WRITE, 0, WRITE_DATA, SHARE_WRITE));
        assert!(pair(GENERIC_ALL, SHARE_READ | SHARE_WRITE | SHARE_DELETE, DELETE, SHARE_DELETE));
    }
    #[test]
    fn metadata_only_open_ignores_its_requested_deny_mode() {
        assert!(!pair(READ_DATA, 0, 0, 0));
        assert!(!pair(WRITE_DATA, 0, 0, SHARE_READ));
        assert!(!pair(DELETE, 0, 0, SHARE_WRITE));
    }
    #[test]
    fn a_released_claim_allows_the_next_open() {
        let first = claim_key((9, 9), READ_DATA, SHARE_READ).unwrap();
        assert!(claim_key((9, 9), WRITE_DATA, SHARE_WRITE).is_none());
        drop(first);
        let second = claim_key((9, 9), WRITE_DATA, SHARE_WRITE).unwrap();
        drop(second);
    }

    #[test]
    fn writable_mapping_obeys_existing_write_share_claim() {
        let first = claim_key((10, 10), READ_DATA | WRITE_DATA, SHARE_READ).unwrap();
        assert!(claim_key((10, 10), MAPPING_ACCESS | MAPPING_WRITE, SHARE_READ | SHARE_WRITE | SHARE_DELETE).is_none());
        drop(first);
        let mapping = claim_key((10, 10), MAPPING_ACCESS | MAPPING_WRITE, SHARE_READ | SHARE_WRITE | SHARE_DELETE).unwrap();
        drop(mapping);
    }

    #[test]
    fn existing_writable_mapping_obeys_new_open_share_write() {
        let mapping = claim_key((11, 11), MAPPING_ACCESS | MAPPING_WRITE, SHARE_READ | SHARE_WRITE | SHARE_DELETE).unwrap();
        assert!(claim_key((11, 11), READ_DATA, SHARE_READ).is_none());
        assert!(claim_key((11, 11), READ_DATA, SHARE_READ | SHARE_WRITE).is_some());
        drop(mapping);
    }
}
