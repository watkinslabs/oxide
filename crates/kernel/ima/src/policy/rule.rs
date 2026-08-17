// One policy rule: an action plus the set of conditions that must all hold for
// the action to apply. A condition value is only consulted when its bit is set
// in `flags`; a value set without its bit is a condition that can never fire.

use alloc::string::String;
use alloc::vec::Vec;

use crate::limits::MAX_LSM_RULES;
use crate::uapi::Hook;

/// Comparator a uid/gid condition applies against the request's value.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CmpOp { Eq, Gt, Lt }

impl CmpOp {
    /// Apply the comparator: request value on the left, rule value on the
    /// right, matching the direction the policy text reads. # C: O(1)
    pub fn apply(self, have: u32, want: u32) -> bool {
        match self { Self::Eq => have == want, Self::Gt => have > want, Self::Lt => have < want }
    }
    /// The character the policy file renders between key and value. # C: O(1)
    pub fn sep(self) -> char {
        match self { Self::Eq => '=', Self::Gt => '>', Self::Lt => '<' }
    }
}

/// LSM condition slots, in the order a rule stores them.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(usize)]
pub enum LsmSlot { ObjUser = 0, ObjRole, ObjType, SubjUser, SubjRole, SubjType }

impl LsmSlot {
    /// Policy keyword owning this slot. # C: O(1)
    pub fn key(self) -> &'static str {
        match self {
            Self::ObjUser => "obj_user", Self::ObjRole => "obj_role", Self::ObjType => "obj_type",
            Self::SubjUser => "subj_user", Self::SubjRole => "subj_role", Self::SubjType => "subj_type",
        }
    }
    /// Every slot, in storage order. # C: O(1)
    pub fn all() -> [LsmSlot; MAX_LSM_RULES] {
        [Self::ObjUser, Self::ObjRole, Self::ObjType, Self::SubjUser, Self::SubjRole, Self::SubjType]
    }
    /// True when the slot names a property of the object (the inode) rather
    /// than of the subject (the acting task). # C: O(1)
    pub fn is_obj(self) -> bool { matches!(self, Self::ObjUser | Self::ObjRole | Self::ObjType) }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub action: u32,
    pub flags: u32,
    pub func: Hook,
    pub mask: u32,
    pub fsmagic: u64,
    pub fsuuid: [u8; 16],
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub fowner: Option<u32>,
    pub fgroup: Option<u32>,
    pub uid_op: CmpOp,
    pub gid_op: CmpOp,
    pub fowner_op: CmpOp,
    pub fgroup_op: CmpOp,
    pub pcr: u32,
    pub allowed_algos: u32,
    pub lsm: [Option<String>; MAX_LSM_RULES],
    pub fsname: Option<String>,
    pub fs_subtype: Option<String>,
    pub keyrings: Option<Vec<String>>,
    pub label: Option<Vec<String>>,
    pub template: Option<String>,
}

impl Default for Rule {
    fn default() -> Self { Self::new() }
}

impl Rule {
    /// An empty rule: no action, no conditions, comparators defaulting to
    /// equality. # C: O(1)
    pub fn new() -> Self {
        Self {
            action: crate::flags::UNKNOWN,
            flags: 0,
            func: Hook::None,
            mask: 0,
            fsmagic: 0,
            fsuuid: [0u8; 16],
            uid: None, gid: None, fowner: None, fgroup: None,
            uid_op: CmpOp::Eq, gid_op: CmpOp::Eq, fowner_op: CmpOp::Eq, fgroup_op: CmpOp::Eq,
            pcr: 0,
            allowed_algos: 0,
            lsm: [None, None, None, None, None, None],
            fsname: None, fs_subtype: None,
            keyrings: None, label: None, template: None,
        }
    }

    /// True when the rule carries every condition bit in `bits`. # C: O(1)
    pub fn has(&self, bits: u32) -> bool { self.flags & bits == bits }

    /// True when any LSM condition is present. Hooks whose match path never
    /// consults the LSM reject such rules rather than storing a condition that
    /// could not fire. # C: O(1)
    pub fn has_lsm_cond(&self) -> bool { self.lsm.iter().any(|s| s.is_some()) }

    /// Read an LSM slot. # C: O(1)
    pub fn lsm_at(&self, slot: LsmSlot) -> Option<&str> {
        self.lsm[slot as usize].as_deref()
    }
}
