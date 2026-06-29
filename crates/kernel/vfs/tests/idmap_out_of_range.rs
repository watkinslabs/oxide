//! idmap-D4b (out-of-range part): an idmapped mount with a real (non-nop) idmap
//! maps any filesystem id NOT covered by an extent to the INVALID sentinel
//! (`(uid_t)-1` == `u32::MAX`), matching Linux `make_vfsuid`/`from_vfsuid`
//! (`fs/mnt_idmapping.c`): `map_id_down`/`map_id_up` return `(u32)-1` on an
//! extent miss, so the kernel surfaces the unmapped owner as INVALID_VFSUID /
//! INVALID_UID (later munged to overflowuid at the userspace copy-out boundary).
//!
//! The naive "pass the id through unchanged on a miss" leaks an unmapped on-disk
//! uid straight to the caller of an idmapped mount — a confinement hole. This
//! pins the miss path to INVALID for a real idmap, while the nop/identity map
//! (no extents) still passes every id through verbatim (Linux `nop_mnt_idmap`).

use vfs::Idmap;

/// Linux `(uid_t)-1`: the unmapped/INVALID owner sentinel `make_vfsuid` yields.
const INVALID: u32 = u32::MAX;

// Out-of-range fs id through a real idmap -> INVALID, not a silent pass-through.
#[test]
fn map_out_miss_is_invalid() {
    // fs [0,65536) <-> vfs [100000,165536).
    let map = Idmap::uniform(0, 100_000, 65_536);
    // in-range: translated.
    assert_eq!(map.map_out_uid(1_000), 101_000);
    assert_eq!(map.map_out_gid(1_000), 101_000);
    // out-of-range (>= fs_lo+count): INVALID, NOT the raw 70000.
    assert_eq!(map.map_out_uid(70_000), INVALID);
    assert_eq!(map.map_out_gid(70_000), INVALID);
}

// Out-of-range vfs id through a real idmap's reverse map -> INVALID.
#[test]
fn map_in_miss_is_invalid() {
    let map = Idmap::uniform(0, 100_000, 65_536);
    // in-range reverse: vfsuid 101000 -> fs uid 1000.
    assert_eq!(map.map_in_uid(101_000), 1_000);
    assert_eq!(map.map_in_gid(101_000), 1_000);
    // below the mapped vfs window and above it: both INVALID.
    assert_eq!(map.map_in_uid(50_000), INVALID);
    assert_eq!(map.map_in_uid(200_000), INVALID);
    assert_eq!(map.map_in_gid(200_000), INVALID);
}

// The nop/identity map (no extents) passes every id through verbatim — no
// INVALID, matching Linux `nop_mnt_idmap` short-circuit.
#[test]
fn identity_passes_through() {
    let id = Idmap::identity();
    assert!(id.is_identity());
    assert_eq!(id.map_out_uid(70_000), 70_000);
    assert_eq!(id.map_in_uid(200_000), 200_000);
    assert_eq!(id.map_out_gid(0), 0);
}
