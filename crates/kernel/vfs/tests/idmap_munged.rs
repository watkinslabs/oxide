//! idmap copy-out munge (`from_kuid_munged`/`from_kgid_munged`,
//! `kernel/user_namespace.c`): the stat(2) `st_uid`/`st_gid` copy-out boundary
//! turns the INVALID miss sentinel `(uid_t)-1` into the global `overflowuid`
//! (65534) so an unmapped owner on an idmapped mount shows up as "nobody"
//! rather than leaking `0xffffffff` into userspace. `map_out_*` keeps INVALID
//! for in-kernel miss detection; `map_out_*_munged` is the userspace-facing form.

use vfs::Idmap;
use vfs::idmap::{INVALID_ID, OVERFLOW_UID, OVERFLOW_GID};

// The overflow ids are the Linux defaults (65534 = "nobody"/"nogroup"), and
// distinct from the in-kernel INVALID sentinel.
#[test]
fn overflow_constants_are_linux_defaults() {
    assert_eq!(OVERFLOW_UID, 65534);
    assert_eq!(OVERFLOW_GID, 65534);
    assert_ne!(OVERFLOW_UID, INVALID_ID);
}

// A real idmap: in-range ids munge to their mapped value (no munge needed);
// out-of-range ids munge to overflowuid/gid, NOT INVALID and NOT the raw id.
#[test]
fn real_idmap_miss_munges_to_overflow() {
    // fs [0,65536) <-> vfs [100000,165536).
    let map = Idmap::uniform(0, 100_000, 65_536);
    // in-range: same translation as the plain map_out, no munge.
    assert_eq!(map.map_out_uid_munged(1_000), 101_000);
    assert_eq!(map.map_out_gid_munged(1_000), 101_000);
    // plain map_out still returns INVALID on a miss (in-kernel detection)...
    assert_eq!(map.map_out_uid(70_000), INVALID_ID);
    // ...but the munged copy-out form substitutes overflowuid/gid.
    assert_eq!(map.map_out_uid_munged(70_000), OVERFLOW_UID);
    assert_eq!(map.map_out_gid_munged(70_000), OVERFLOW_GID);
}

// The nop/identity map never misses, so the munged form is a pure pass-through
// — byte-identical to the non-idmapped stat path (no spurious overflowuid).
#[test]
fn identity_munge_is_passthrough() {
    let id = Idmap::identity();
    assert_eq!(id.map_out_uid_munged(0), 0);
    assert_eq!(id.map_out_uid_munged(1_000), 1_000);
    assert_eq!(id.map_out_gid_munged(65_534), 65_534);
    // even the literal overflow value passes straight through (it IS a valid id
    // for a non-idmapped mount, not a synthesised miss).
    assert_eq!(id.map_out_uid_munged(70_000), 70_000);
}

// An empty real idmap maps EVERY id to INVALID (Linux user-ns with empty
// uid_map), so the munged copy-out reports overflowuid for all owners.
#[test]
fn empty_real_idmap_munges_everything_to_overflow() {
    let map = Idmap::new(Vec::new(), Vec::new());
    assert_eq!(map.map_out_uid_munged(0), OVERFLOW_UID);
    assert_eq!(map.map_out_uid_munged(1_000), OVERFLOW_UID);
    assert_eq!(map.map_out_gid_munged(0), OVERFLOW_GID);
}
