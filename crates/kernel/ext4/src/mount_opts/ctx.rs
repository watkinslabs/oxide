// Mount-option state objects: the per-mount-call parse context, the live
// per-superblock quota option state it folds into, and the on-disk feature
// bits the consistency checks read.

use alloc::string::String;
use alloc::vec::Vec;
use vfs::MAXQUOTAS;

use super::behaviour::Ext4Behaviour;
use super::flags::{EXT4_MOUNT_QUOTA_MASK, limit_bit};

/// On-disk quota-relevant feature bits of the filesystem being mounted.
/// `quota` = kernel-owned hidden quota inodes; `project` = project id field.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FsQuotaFeatures {
    pub quota: bool,
    pub project: bool,
}

/// Quota-family options parsed out of one mount/remount data string.
///
/// `vals`/`mask` follow the set/clear model the option table needs: `mask`
/// records every bit an option TOUCHED, `vals` the value it left. `noquota`
/// therefore masks the whole quota set while leaving `vals` empty, which is
/// what distinguishes "quota unmentioned" from "quota explicitly turned off".
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Ext4MountOpts {
    pub vals: u32,
    pub mask: u32,
    /// Journalled quota file names, indexed by quota-class slot.
    pub qf_names: [Option<String>; MAXQUOTAS],
    /// Bit per slot whose journalled quota file name this data string named
    /// (including naming it EMPTY, which un-sets it).
    pub qname_spec: u32,
    /// A `usrjquota=`/`grpjquota=` option appeared.
    pub spec_jquota: bool,
    /// A `jqfmt=` option appeared.
    pub spec_jqfmt: bool,
    pub jquota_fmt: u32,
    /// Non-quota tokens carried through unrecognised. ext4 is the root
    /// filesystem: an unknown token here must not fail the mount.
    pub other: Vec<String>,
    /// The behavioural options this data string leaves in force. Seeded from
    /// what the filesystem already has, so a remount that names one option
    /// does not reset the others.
    pub behaviour: Ext4Behaviour,
}

impl Ext4MountOpts {
    /// Set quota mount-opt bits (option-table SET). # C: O(1)
    pub fn set_opt(&mut self, bits: u32) { self.mask |= bits; self.vals |= bits; }
    /// Clear quota mount-opt bits (option-table CLEAR). # C: O(1)
    pub fn clear_opt(&mut self, bits: u32) { self.mask |= bits; self.vals &= !bits; }
    /// True when every named bit is set in this context. # C: O(1)
    pub fn test_opt(&self, bits: u32) -> bool { self.vals & bits != 0 }
    /// True when this data string touched any quota mount-opt bit. # C: O(1)
    pub fn touched_quota_opts(&self) -> bool { self.mask & EXT4_MOUNT_QUOTA_MASK != 0 }
    /// Journalled quota file name this data string requested for `slot`. # C: O(1)
    pub fn qf_name(&self, slot: usize) -> Option<&str> { self.qf_names[slot].as_deref() }
    /// True when this data string named (or un-named) `slot`'s quota file. # C: O(1)
    pub fn names_slot(&self, slot: usize) -> bool { self.qname_spec & (1 << slot) != 0 }
}

/// Live quota option state of a mounted ext4 superblock.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Ext4SbOpts {
    pub mount_opt: u32,
    pub qf_names: [Option<String>; MAXQUOTAS],
    pub jquota_fmt: u32,
    /// The behavioural options in force. This is their ONLY home: every
    /// consumer reads them from the mounted filesystem's option state, so a
    /// remount cannot leave two copies disagreeing.
    pub behaviour: Ext4Behaviour,
}

impl Ext4SbOpts {
    /// True when every named bit is set on the superblock. # C: O(1)
    pub fn test_opt(&self, bits: u32) -> bool { self.mount_opt & bits != 0 }
    /// Journalled quota file name in force for `slot`. # C: O(1)
    pub fn qf_name(&self, slot: usize) -> Option<&str> { self.qf_names[slot].as_deref() }
    /// True when limit enforcement (not just usage tracking) was requested for
    /// `kind`. A quota class without it is loaded usage-only. # C: O(1)
    pub fn limits_requested(&self, kind: vfs::QuotaType) -> bool {
        self.mount_opt & limit_bit(kind) != 0
    }
    /// Journalled quota file name in force for `kind`. # C: O(1)
    pub fn journalled_file(&self, kind: vfs::QuotaType) -> Option<&str> {
        self.qf_name(kind.slot())
    }
    /// True when a journalled quota file is named for any class. # C: O(MAXQUOTAS)
    pub fn has_journalled_files(&self) -> bool { self.qf_names.iter().any(|n| n.is_some()) }
}
