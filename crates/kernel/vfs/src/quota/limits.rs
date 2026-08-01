use crate::quota::DquotUsage;
use crate::types::{KResult, VfsError};

use super::control::{QFMT_VFS_V0, QFMT_VFS_V1};

pub const VFS_V0_MAX_SPACE_LIMIT: u64 = (u32::MAX as u64) << 10;
pub const VFS_V0_MAX_INODE_LIMIT: u64 = u32::MAX as u64;
pub const VFS_V1_MAX_LIMIT: u64 = i64::MAX as u64;
pub const IIF_BGRACE: u32 = 1 << 0;
pub const IIF_IGRACE: u32 = 1 << 1;
pub const IIF_FLAGS:  u32 = 1 << 2;
pub const IIF_RT_BGRACE: u32 = 1 << 3;
pub const IIF_BWARN:     u32 = 1 << 4;
pub const IIF_IWARN:     u32 = 1 << 5;
pub const IIF_RTBWARN:   u32 = 1 << 6;
pub const IIF_ALL:    u32 = IIF_BGRACE | IIF_IGRACE | IIF_FLAGS
    | IIF_RT_BGRACE | IIF_BWARN | IIF_IWARN | IIF_RTBWARN;
pub const DQF_ROOT_SQUASH: u32 = 1 << 0;
pub const DQF_SYS_FILE: u32 = 1 << 16;
pub const DQF_GETINFO_MASK: u32 = DQF_ROOT_SQUASH | DQF_SYS_FILE;
pub const DQF_SETINFO_MASK: u32 = DQF_ROOT_SQUASH;
pub const DQB_INO_SOFT:  u32 = 1 << 0;
pub const DQB_INO_HARD:  u32 = 1 << 1;
pub const DQB_SPC_SOFT:  u32 = 1 << 2;
pub const DQB_SPC_HARD:  u32 = 1 << 3;
pub const DQB_SPC_TIMER: u32 = 1 << 6;
pub const DQB_INO_TIMER: u32 = 1 << 7;
pub const DQB_RTB_SOFT:  u32 = 1 << 8;
pub const DQB_RTB_HARD:  u32 = 1 << 9;
pub const DQB_RTB_TIMER: u32 = 1 << 10;
pub const DQB_SPACE:     u32 = 1 << 12;
pub const DQB_INO_COUNT: u32 = 1 << 13;
pub const DQB_RTB_COUNT: u32 = 1 << 14;
/// Fields the GENERIC quota-file backend can store. The realtime-device
/// counters and the per-dquot warning counters are deliberately absent: no
/// generic quota file has a place to put them, so a request that names one is
/// `EINVAL` rather than a silently dropped write. A backend with a realtime
/// device installs its own record setter and accepts the wider set.
pub const DQB_VFS_MASK:  u32 = DQB_SPACE | DQB_SPC_SOFT | DQB_SPC_HARD
    | DQB_INO_COUNT | DQB_INO_SOFT | DQB_INO_HARD | DQB_SPC_TIMER | DQB_INO_TIMER;

/// Linux-style quota limit pair. Zero means unlimited. # C: O(1)
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QuotaLimit {
    pub soft: u64,
    pub hard: u64,
}

impl QuotaLimit {
    /// Unlimited quota limit. # C: O(1)
    pub const fn unlimited() -> Self { Self { soft: 0, hard: 0 } }
    /// Hard-only limit; soft remains advisory/disabled. # C: O(1)
    pub const fn hard(n: u64) -> Self { Self { soft: 0, hard: n } }
    /// True when current plus delta stays under the hard limit. # C: O(1)
    pub fn admits(self, cur: u64, delta: u64) -> bool {
        if self.hard == 0 { return cur.checked_add(delta).is_some(); }
        match cur.checked_add(delta) {
            Some(next) => next <= self.hard,
            None => false,
        }
    }
}

/// Per-dquot admission limits. `space` and `reserved_space` are byte limits;
/// `inodes` is an inode-count limit. # C: O(1)
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DquotLimits {
    pub space:          QuotaLimit,
    pub reserved_space: QuotaLimit,
    pub inodes:         QuotaLimit,
}

impl DquotLimits {
    /// No enforced hard limits. # C: O(1)
    pub const fn unlimited() -> Self {
        Self {
            space: QuotaLimit::unlimited(),
            reserved_space: QuotaLimit::unlimited(),
            inodes: QuotaLimit::unlimited(),
        }
    }
    /// True when charging `delta` to `cur` would not exceed hard limits. # C: O(1)
    pub fn admits(self, cur: DquotUsage, delta: DquotUsage) -> bool {
        self.space.admits(cur.space, delta.space)
            && self.reserved_space.admits(cur.reserved_space, delta.reserved_space)
            && self.inodes.admits(cur.inodes, delta.inodes)
    }
}

/// Linux `struct mem_dqblk` in core form. Hard/soft zero means unlimited. # C: O(1)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemDqblk {
    pub dqb_bhardlimit: u64,
    pub dqb_bsoftlimit: u64,
    pub dqb_curspace:   u64,
    pub dqb_rsvspace:   u64,
    pub dqb_ihardlimit: u64,
    pub dqb_isoftlimit: u64,
    pub dqb_curinodes:  u64,
    pub dqb_btime:      i64,
    pub dqb_itime:      i64,
    pub dqb_rtb_hardlimit: u64,
    pub dqb_rtb_softlimit: u64,
    pub dqb_rtbcount:      u64,
    pub dqb_rtbtimer:      i64,
    pub dqb_valid:      u32,
}

/// Linux `struct if_dqinfo` for Q_GETINFO/Q_SETINFO. # C: O(1)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemDqinfo {
    pub dqi_bgrace: u64,
    pub dqi_igrace: u64,
    pub dqi_rt_bgrace: u64,
    pub dqi_bwarnlimit: u16,
    pub dqi_iwarnlimit: u16,
    pub dqi_rtbwarnlimit: u16,
    pub dqi_flags:  u32,
    pub dqi_valid:  u32,
}

impl MemDqblk {
    /// Empty unlocked quota record. # C: O(1)
    pub const fn new() -> Self {
        Self {
            dqb_bhardlimit: 0, dqb_bsoftlimit: 0, dqb_curspace: 0, dqb_rsvspace: 0,
            dqb_ihardlimit: 0, dqb_isoftlimit: 0, dqb_curinodes: 0, dqb_btime: 0,
            dqb_itime: 0, dqb_rtb_hardlimit: 0, dqb_rtb_softlimit: 0, dqb_rtbcount: 0,
            dqb_rtbtimer: 0, dqb_valid: 0,
        }
    }
    /// Convert this Linux record to enforced hard-limit pairs. # C: O(1)
    pub const fn limits(self) -> DquotLimits {
        DquotLimits {
            space:          QuotaLimit { soft: self.dqb_bsoftlimit, hard: self.dqb_bhardlimit },
            reserved_space: QuotaLimit { soft: 0, hard: 0 },
            inodes:         QuotaLimit { soft: self.dqb_isoftlimit, hard: self.dqb_ihardlimit },
        }
    }
    /// Current usage counters from this Linux record. # C: O(1)
    pub const fn usage(self) -> DquotUsage {
        DquotUsage { space: self.dqb_curspace, reserved_space: self.dqb_rsvspace, inodes: self.dqb_curinodes }
    }
    /// Check Linux format-specific soft/hard limit maxima. # C: O(1)
    pub fn validate_limits_for_format(self, fmt: u32) -> KResult<()> {
        let (max_space, max_ino) = match fmt {
            QFMT_VFS_V0 => (VFS_V0_MAX_SPACE_LIMIT, VFS_V0_MAX_INODE_LIMIT),
            QFMT_VFS_V1 => (VFS_V1_MAX_LIMIT, VFS_V1_MAX_LIMIT),
            _ => return Err(VfsError::Einval),
        };
        if self.dqb_bhardlimit > max_space || self.dqb_bsoftlimit > max_space
            || self.dqb_ihardlimit > max_ino || self.dqb_isoftlimit > max_ino
            || self.dqb_rtb_hardlimit > max_space || self.dqb_rtb_softlimit > max_space {
            return Err(VfsError::Erange);
        }
        Ok(())
    }
    /// Check Linux format maxima only for caller-selected limit fields. # C: O(1)
    pub fn validate_masked_limits_for_format(self, fmt: u32, fieldmask: u32) -> KResult<()> {
        let (max_space, max_ino) = match fmt {
            QFMT_VFS_V0 => (VFS_V0_MAX_SPACE_LIMIT, VFS_V0_MAX_INODE_LIMIT),
            QFMT_VFS_V1 => (VFS_V1_MAX_LIMIT, VFS_V1_MAX_LIMIT),
            _ => return Err(VfsError::Einval),
        };
        if fieldmask & DQB_SPC_HARD != 0 && self.dqb_bhardlimit > max_space { return Err(VfsError::Erange); }
        if fieldmask & DQB_SPC_SOFT != 0 && self.dqb_bsoftlimit > max_space { return Err(VfsError::Erange); }
        if fieldmask & DQB_INO_HARD != 0 && self.dqb_ihardlimit > max_ino { return Err(VfsError::Erange); }
        if fieldmask & DQB_INO_SOFT != 0 && self.dqb_isoftlimit > max_ino { return Err(VfsError::Erange); }
        if fieldmask & DQB_RTB_HARD != 0 && self.dqb_rtb_hardlimit > max_space { return Err(VfsError::Erange); }
        if fieldmask & DQB_RTB_SOFT != 0 && self.dqb_rtb_softlimit > max_space { return Err(VfsError::Erange); }
        Ok(())
    }
    /// Build a Linux record from local limits plus usage. # C: O(1)
    pub const fn from_limits_usage(limits: DquotLimits, usage: DquotUsage) -> Self {
        Self {
            dqb_bhardlimit: limits.space.hard,
            dqb_bsoftlimit: limits.space.soft,
            dqb_curspace: usage.space,
            dqb_rsvspace: usage.reserved_space,
            dqb_ihardlimit: limits.inodes.hard,
            dqb_isoftlimit: limits.inodes.soft,
            dqb_curinodes: usage.inodes,
            dqb_btime: 0,
            dqb_itime: 0,
            dqb_rtb_hardlimit: 0,
            dqb_rtb_softlimit: 0,
            dqb_rtbcount: 0,
            dqb_rtbtimer: 0,
            dqb_valid: 0,
        }
    }
}
