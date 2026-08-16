// Policy database header constants and the version range this engine reads.

/// Leading magic word of a binary policy image.
pub const POLICYDB_MAGIC: u32 = 0xf97c_ff8c;

/// Signature string following the magic, stored with its own length prefix.
pub const POLICYDB_SIGNATURE: &[u8] = b"SE Linux";

/// Base version: symbol tables, access vectors, initial SIDs.
pub const POLICYDB_VERSION_BASE: u32 = 15;
/// Adds conditional booleans.
pub const POLICYDB_VERSION_BOOL: u32 = 16;
/// Adds IPv6 node contexts.
pub const POLICYDB_VERSION_IPV6: u32 = 17;
/// Adds the netlink class split.
pub const POLICYDB_VERSION_NLCLASS: u32 = 18;
/// Adds validatetrans constraints, and MLS as a policy config bit.
pub const POLICYDB_VERSION_VALIDATETRANS: u32 = 19;
/// Same version as validatetrans; names the MLS introduction.
pub const POLICYDB_VERSION_MLS: u32 = 19;
/// Adds the hashed access-vector table format.
pub const POLICYDB_VERSION_AVTAB: u32 = 20;
/// Adds range transitions.
pub const POLICYDB_VERSION_RANGETRANS: u32 = 21;
/// Adds the policy-capability bitmap.
pub const POLICYDB_VERSION_POLCAP: u32 = 22;
/// Adds the permissive-type bitmap.
pub const POLICYDB_VERSION_PERMISSIVE: u32 = 23;
/// Adds type and role bounds.
pub const POLICYDB_VERSION_BOUNDARY: u32 = 24;
/// Adds filename transitions.
pub const POLICYDB_VERSION_FILENAME_TRANS: u32 = 25;
/// Adds role transitions qualified by class.
pub const POLICYDB_VERSION_ROLETRANS: u32 = 26;
/// Adds per-class default user, role and range.
pub const POLICYDB_VERSION_NEW_OBJECT_DEFAULTS: u32 = 27;
/// Adds per-class default type.
pub const POLICYDB_VERSION_DEFAULT_TYPE: u32 = 28;
/// Adds named type sets in constraints.
pub const POLICYDB_VERSION_CONSTRAINT_NAMES: u32 = 29;
/// Adds extended ioctl permissions.
pub const POLICYDB_VERSION_XPERMS_IOCTL: u32 = 30;
/// Adds InfiniBand pkey and endport contexts.
pub const POLICYDB_VERSION_INFINIBAND: u32 = 31;
/// Adds the greatest-lower-bound range-transition default.
pub const POLICYDB_VERSION_GLBLUB: u32 = 32;
/// Compressed filename transitions.
pub const POLICYDB_VERSION_COMP_FTRANS: u32 = 33;
/// Extended permissions inside conditional policy.
pub const POLICYDB_VERSION_COND_XPERMS: u32 = 34;
/// Neveraudit types.
pub const POLICYDB_VERSION_NEVERAUDIT: u32 = 35;

/// Oldest policy version this engine reads.
pub const POLICYDB_VERSION_MIN: u32 = POLICYDB_VERSION_BASE;
/// Newest policy version this engine reads.
pub const POLICYDB_VERSION_MAX: u32 = POLICYDB_VERSION_NEVERAUDIT;

/// Policy config bit: the policy carries MLS levels and categories.
pub const POLICYDB_CONFIG_MLS: u32 = 1;

/// Unspecified SID.
pub const SECSID_NULL: u32 = 0;
/// Wildcard SID.
pub const SECSID_WILD: u32 = 0xffff_ffff;
/// Absence of a security class.
pub const SECCLASS_NULL: u16 = 0;

/// Superblock flag: whole-mount context supplied at mount time.
pub const CONTEXT_MNT: u16 = 0x01;
/// Superblock flag: filesystem context supplied at mount time.
pub const FSCONTEXT_MNT: u16 = 0x02;
/// Superblock flag: root-inode context supplied at mount time.
pub const ROOTCONTEXT_MNT: u16 = 0x04;
/// Superblock flag: default file context supplied at mount time.
pub const DEFCONTEXT_MNT: u16 = 0x08;
/// Mask covering only the mount-supplied context flags.
pub const SE_MNTMASK: u16 = 0x0f;
/// Superblock flag: the filesystem carries per-inode labels.
pub const SBLABEL_MNT: u16 = 0x10;
/// Superblock flag: labelling behaviour has been decided for this mount.
pub const SE_SBINITIALIZED: u16 = 0x0100;
/// Superblock flag: proc-like filesystem labelled by path.
pub const SE_SBPROC: u16 = 0x0200;
/// Superblock flag: labelled from genfscon entries.
pub const SE_SBGENFS: u16 = 0x0400;
/// Superblock flag: genfscon-labelled but also carrying xattrs.
pub const SE_SBGENFS_XATTR: u16 = 0x0800;
/// Superblock flag: the filesystem supplies labels natively.
pub const SE_SBNATIVE: u16 = 0x1000;

/// Whether this engine can read a policy of the given version. # C: O(1)
pub fn version_supported(version: u32) -> bool {
    (POLICYDB_VERSION_MIN..=POLICYDB_VERSION_MAX).contains(&version)
}
