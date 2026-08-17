//! Which identities an allocation is charged to, and how the kinds are numbered.

use crate::uapi::MAX_QUOTAS;

/// The project a new inode belongs to until something sets one.
pub const DEFAULT_PROJID: u32 = 0;

/// The three kinds, in the order the superblock lists their inodes.
pub const USRQUOTA: usize = 0;
pub const GRPQUOTA: usize = 1;
pub const PRJQUOTA: usize = 2;

/// The identity an allocation is charged to, one id per kind.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Owners([u32; MAX_QUOTAS]);

impl Owners {
    /// # C: O(1)
    pub fn new(uid: u32, gid: u32, projid: u32) -> Self { Owners([uid, gid, projid]) }

    /// # C: O(1)
    pub fn id(&self, kind: usize) -> u32 { self.0[kind] }
}
