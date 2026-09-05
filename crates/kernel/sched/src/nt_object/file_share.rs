//! NT-object compatibility wrapper; share state is owned by the VFS inode.
extern crate alloc;
use alloc::sync::Arc;

pub struct NtFileShare { inner: Arc<vfs::WindowsFileShare> }

impl NtFileShare {
    /// Claim Windows sharing rights for one canonical VFS inode. # C: O(N_claims)
    pub fn claim(file: &vfs::File, desired: u32, sharing: u32) -> Option<Arc<Self>> {
        file.inode().windows_share_context().claim(file.inode().clone(), desired, sharing)
            .map(|inner| Arc::new(Self { inner }))
    }
    /// Claim mapping access against the same inode-owned share state. # C: O(N_claims)
    pub fn claim_mapping(file: &vfs::File, access: u32) -> Option<Arc<Self>> {
        vfs::mapping_claim(file, access).map(|inner| Arc::new(Self { inner }))
    }
}
