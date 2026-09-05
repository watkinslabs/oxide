//! NT-object wrapper for inode-owned Windows share claims.
extern crate alloc;
use alloc::sync::Arc;

/// One live NT open's share claim. Cloned handles retain one claim until the
/// final NT object reference is dropped.
pub struct NtFileShare { _inner: Arc<vfs::WindowsFileShare> }

impl NtFileShare {
    /// Claim Windows sharing rights for one canonical VFS inode. # C: O(N_claims)
    pub fn claim(file: &vfs::File, access: u32, sharing: u32) -> Option<Arc<Self>> {
        file.inode().windows_share_context().claim(file.inode().clone(), access, sharing)
            .map(|inner| Arc::new(Self { _inner: inner }))
    }

    /// Claim file-backed mapping access against the same inode owner. # C: O(N_claims)
    pub fn claim_mapping(file: &vfs::File, access: u32) -> Option<Arc<Self>> {
        file.inode().windows_share_context().claim_mapping(file.inode().clone(), access)
            .map(|inner| Arc::new(Self { _inner: inner }))
    }
}
