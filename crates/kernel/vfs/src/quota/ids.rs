/// Linux quota class (`USRQUOTA`, `GRPQUOTA`, `PRJQUOTA`). # C: O(1)
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum QuotaType {
    User,
    Group,
    Project,
}

impl QuotaType {
    /// Inode dquot slot index matching Linux's MAXQUOTAS order. # C: O(1)
    pub const fn slot(self) -> usize {
        match self {
            QuotaType::User    => 0,
            QuotaType::Group   => 1,
            QuotaType::Project => 2,
        }
    }
    /// Quota class from Linux's fixed MAXQUOTAS slot order. # C: O(1)
    pub const fn from_slot(slot: usize) -> Self {
        match slot {
            0 => QuotaType::User,
            1 => QuotaType::Group,
            _ => QuotaType::Project,
        }
    }
}

/// Number of Linux dquot slots carried by an inode. # C: O(1)
pub const MAXQUOTAS: usize = 3;

/// Kernel quota id (`struct kqid`) inside one filesystem's quota table. # C: O(1)
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Kqid {
    pub kind: QuotaType,
    pub id:   u32,
}

/// Back-compat alias for callers that already used the quota cache key name.
pub type QuotaId = Kqid;

impl Kqid {
    /// User-quota identity. # C: O(1)
    pub const fn user(id: u32) -> Self { Self { kind: QuotaType::User, id } }
    /// Group-quota identity. # C: O(1)
    pub const fn group(id: u32) -> Self { Self { kind: QuotaType::Group, id } }
    /// Project-quota identity. # C: O(1)
    pub const fn project(id: u32) -> Self { Self { kind: QuotaType::Project, id } }
    /// Inode dquot slot index matching Linux's MAXQUOTAS order. # C: O(1)
    pub const fn slot(self) -> usize {
        self.kind.slot()
    }
}
