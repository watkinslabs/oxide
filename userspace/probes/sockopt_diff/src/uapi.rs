//! `SOL_NETLINK` option names. `libc` exports `SOL_NETLINK` and
//! `AF_NETLINK`/`NETLINK_ROUTE` at its top level, but not the per-socket
//! `NETLINK_*` option numbers this probe sets/gets — those live under a
//! `libc` internal module this crate does not depend on, so they are named
//! here as the owning UAPI contract for this probe (`CLAUDE.md` "UAPI is not
//! policy" — constants live in `uapi.rs`, not inline in call sites).

pub const NETLINK_ADD_MEMBERSHIP: i32 = 1;
pub const NETLINK_DROP_MEMBERSHIP: i32 = 2;
pub const NETLINK_PKTINFO: i32 = 3;
pub const NETLINK_BROADCAST_ERROR: i32 = 4;
pub const NETLINK_NO_ENOBUFS: i32 = 5;
pub const NETLINK_LISTEN_ALL_NSID: i32 = 8;
pub const NETLINK_LIST_MEMBERSHIPS: i32 = 9;
pub const NETLINK_CAP_ACK: i32 = 10;
pub const NETLINK_EXT_ACK: i32 = 11;
pub const NETLINK_GET_STRICT_CHK: i32 = 12;

/// An option number no `SOL_NETLINK` or `SOL_SOCKET` handler will ever define,
/// for the "unknown option" error-ordering probes.
pub const UNKNOWN_OPTION: i32 = 0x7fff_fffe;

/// A netlink multicast group past any real protocol's group count, for the
/// "out of range group" probe. `NETLINK_ROUTE` carries well under 100 groups.
pub const GROUP_OUT_OF_RANGE: i32 = 100_000;

/// A `sockaddr`-adjacent unmapped sentinel used as a NULL-optval stand-in is
/// not needed here: NULL itself is the probe.

/// Netlink multicast groups this probe adds membership to before reading
/// `NETLINK_LIST_MEMBERSHIPS`, chosen so the resulting bitmap word is
/// non-zero and non-trivial (`0b1_0000_0101` = groups 1, 3, 9) without
/// depending on any group's real-world meaning.
pub const MEMBERSHIP_GROUPS: [i32; 3] = [1, 3, 9];

/// Unprivileged sentinel uid/gid for the privilege-ladder probes
/// (`sock::priv_pair`). Numeric only — no `/etc/passwd` lookup — so it needs
/// no `nobody` entry to exist in the image, only that the id is unassigned.
pub const UNPRIV_ID: libc::uid_t = 65534;
