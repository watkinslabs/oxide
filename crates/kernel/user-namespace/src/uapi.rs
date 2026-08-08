// Linux user_namespace(7) uid_map/gid_map ABI constants.

/// Max extent lines accepted across the lifetime of one map — widened from
/// 5 to 340 upstream so systemd-nspawn-style multi-range container maps fit
/// in one write. # C: O(1)
pub const UID_GID_MAP_MAX_EXTENTS: usize = 340;

/// `(uid_t)-1` sentinel for an id no extent covers, and the initial
/// namespace's identity extent deliberately stops one id short so the
/// sentinel is unmapped there too. # C: O(1)
pub const INVALID_ID: u32 = u32::MAX;

/// Default id an unmapped uid translates to at the namespace boundary.
/// # C: O(1)
pub const OVERFLOW_UID: u32 = 65534;

/// Default id an unmapped gid translates to at the namespace boundary.
/// # C: O(1)
pub const OVERFLOW_GID: u32 = 65534;

/// The id an unmapped project id translates to at the namespace boundary.
/// Fixed, unlike the uid/gid pair, which are also sysctl-settable. # C: O(1)
pub const OVERFLOW_PROJID: u32 = 65534;

/// Identity extent seeded into the initial user namespace's uid/gid maps at
/// boot: one extent, ns id 0 maps to host id 0, spanning the full 32-bit
/// space. # C: O(1)
pub const INITIAL_NS_ID: u32 = 0;
pub const INITIAL_HOST_ID: u32 = 0;
pub const INITIAL_COUNT: u32 = u32::MAX;
