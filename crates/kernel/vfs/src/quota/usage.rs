/// Charged usage carried by one inode for dquot accounting. Space units are
/// bytes, matching Linux `dquot_transfer`'s `cur_space`/`rsv_space` inputs.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DquotUsage {
    pub space:          u64,
    pub reserved_space: u64,
    pub inodes:         u64,
}

impl DquotUsage {
    /// Empty usage delta. # C: O(1)
    pub const fn zero() -> Self { Self { space: 0, reserved_space: 0, inodes: 0 } }
    /// Usage for an allocated inode with known charged byte counts. # C: O(1)
    pub const fn inode(space: u64, reserved_space: u64) -> Self {
        Self { space, reserved_space, inodes: 1 }
    }
    /// True when no quota counter changes. # C: O(1)
    pub const fn is_zero(self) -> bool {
        self.space == 0 && self.reserved_space == 0 && self.inodes == 0
    }
    /// Checked counter addition. # C: O(1)
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        Some(Self {
            space:          self.space.checked_add(rhs.space)?,
            reserved_space: self.reserved_space.checked_add(rhs.reserved_space)?,
            inodes:         self.inodes.checked_add(rhs.inodes)?,
        })
    }
    /// Checked counter subtraction. # C: O(1)
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        Some(Self {
            space:          self.space.checked_sub(rhs.space)?,
            reserved_space: self.reserved_space.checked_sub(rhs.reserved_space)?,
            inodes:         self.inodes.checked_sub(rhs.inodes)?,
        })
    }
}
