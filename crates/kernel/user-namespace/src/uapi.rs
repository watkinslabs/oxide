// Linux user_namespace(7) uid_map/gid_map ABI constants.

/// Linux `UID_GID_MAP_MAX_EXTENTS` (`include/linux/user_namespace.h`) —
/// max extent lines accepted across the lifetime of one map (kernel 4.15+
/// widened this from 5 to 340 so systemd-nspawn-style multi-range
/// container maps fit in one write). # C: O(1)
pub const UID_GID_MAP_MAX_EXTENTS: usize = 340;

/// Linux `overflowuid` default (`kernel/sys.c`) — the id an unmapped uid
/// translates to at the namespace boundary. # C: O(1)
pub const OVERFLOW_UID: u32 = 65534;

/// Linux `overflowgid` default (`kernel/sys.c`) — the id an unmapped gid
/// translates to at the namespace boundary. # C: O(1)
pub const OVERFLOW_GID: u32 = 65534;

/// Identity extent Linux seeds `init_user_ns.{uid,gid}_map` with at boot:
/// one extent, ns id 0 maps to host id 0, spanning the full 32-bit space.
/// # C: O(1)
pub const INITIAL_NS_ID: u32 = 0;
pub const INITIAL_HOST_ID: u32 = 0;
pub const INITIAL_COUNT: u32 = u32::MAX;
