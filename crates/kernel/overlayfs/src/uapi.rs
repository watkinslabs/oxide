//! The names and numbers a union filesystem puts on disk.
//!
//! Everything here is read by tools that are not this kernel — a container
//! runtime inspecting an upper layer, an image builder writing one, a `tar`
//! of a layer restored on another machine. A name spelled differently here is
//! a layer nobody else can read.

/// `statfs.f_type` for an overlay mount.
pub const OVERLAYFS_SUPER_MAGIC: u64 = 0x794c_7630;

/// Namespace all private markers live under, inside `trusted.` or `user.`.
pub const XATTR_NAMESPACE: &str = "overlay.";
/// Prefix when the mount holds privilege over `trusted.` (the default).
pub const XATTR_TRUSTED_PREFIX: &str = "trusted.overlay.";
/// Prefix when `userxattr` moved the markers into the unprivileged namespace.
pub const XATTR_USER_PREFIX: &str = "user.overlay.";

/// A marker's suffix, shared by both prefixes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Marker {
    /// Directory hides every lower directory of the same name.
    Opaque,
    /// Name of the lower object this one stands for, absolute or relative.
    Redirect,
    /// Handle of the lower inode this upper object was copied from.
    Origin,
    /// Directory may hold entries whose lower origin differs from their name.
    Impure,
    /// Link count adjustment recorded while an index entry is in flight.
    Nlink,
    /// Handle of the upper directory an index entry stands for.
    Upper,
    /// UUID stamped on the upper root, tying origin handles to a layer.
    Uuid,
    /// Object carries metadata only; its data is still in the lower layer.
    Metacopy,
    /// Immutable/append flags that cannot be set on the upper inode itself.
    Protattr,
    /// Regular file acting as a whiteout on a layer that has no device nodes.
    Xwhiteout,
}

impl Marker {
    /// Suffix after the namespace. # C: O(1)
    pub fn suffix(self) -> &'static str {
        match self {
            Marker::Opaque => "opaque",
            Marker::Redirect => "redirect",
            Marker::Origin => "origin",
            Marker::Impure => "impure",
            Marker::Nlink => "nlink",
            Marker::Upper => "upper",
            Marker::Uuid => "uuid",
            Marker::Metacopy => "metacopy",
            Marker::Protattr => "protattr",
            Marker::Xwhiteout => "whiteout",
        }
    }
}

/// `rdev` of the character device that stands for a deleted lower name.
/// Major and minor both zero — no real device ever has it, which is why it
/// was chosen.
pub const WHITEOUT_RDEV: u32 = 0;

/// Value written into an opaque or impure marker.
pub const MARKER_YES: &[u8] = b"y";
/// Value an opaque marker carries when the directory instead holds
/// regular-file whiteouts.
pub const MARKER_XWHITEOUTS: &[u8] = b"x";

/// Version of the origin-handle record this kernel writes.
pub const FH_VERSION: u8 = 0;
/// First byte after the version, identifying the record as ours.
pub const FH_MAGIC: u8 = 0xfb;
/// Record was written by a big-endian kernel.
pub const FH_FLAG_BIG_ENDIAN: u8 = 1 << 0;
/// Record's body is endian-neutral and may be decoded either way.
pub const FH_FLAG_ANY_ENDIAN: u8 = 1 << 1;
/// Record names an upper object rather than a lower one.
pub const FH_FLAG_PATH_UPPER: u8 = 1 << 2;
/// Every flag this version understands; anything else means "unknown origin".
pub const FH_FLAG_ALL: u8 = FH_FLAG_BIG_ENDIAN | FH_FLAG_ANY_ENDIAN | FH_FLAG_PATH_UPPER;
/// Flag value matching this build's byte order.
pub const FH_FLAG_CPU_ENDIAN: u8 = if cfg!(target_endian = "big") { FH_FLAG_BIG_ENDIAN } else { 0 };

/// Bytes of header before the identifier in an origin record: version, magic,
/// length, flags, type, then the sixteen-byte layer UUID.
pub const FB_HEADER_LEN: usize = 5 + 16;

/// Directory created under `workdir=` for in-flight objects.
pub const WORKDIR_NAME: &str = "work";
/// Directory created under `workdir=` for the hardlink index.
pub const INDEXDIR_NAME: &str = "index";
/// File the volatile mode drops in the work directory, so a later mount can
/// tell that an unsynced upper layer was left behind.
pub const VOLATILE_DIRTY_NAME: &str = "incompat/volatile/dirty";
