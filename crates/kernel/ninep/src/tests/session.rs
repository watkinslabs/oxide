// Version negotiation: the dialect match and the one-directional size rule.

use crate::client::session::resolve_version;
use crate::codec::Dialect;
use crate::err::NpError;
use crate::uapi::{limits, version};

#[test]
fn the_longest_dialect_string_wins() {
    // Both `.L` and `.u` begin with `9P2000`. A shortest-first test silently
    // downgrades every Linux server to the legacy dialect: the mount still
    // works, reports string errors, loses `Treaddir`, and nothing is red.
    let n = resolve_version(8192, version::V9P2000L, 8192).unwrap();
    assert_eq!(n.dialect, Dialect::DotL);
    let n = resolve_version(8192, version::V9P2000U, 8192).unwrap();
    assert_eq!(n.dialect, Dialect::DotU);
    let n = resolve_version(8192, version::V9P2000, 8192).unwrap();
    assert_eq!(n.dialect, Dialect::Legacy);
}

#[test]
fn a_version_string_with_a_suffix_still_matches_its_dialect() {
    // Servers append their own build information after the dialect name.
    let n = resolve_version(8192, "9P2000.L.qemu", 8192).unwrap();
    assert_eq!(n.dialect, Dialect::DotL);
}

#[test]
fn an_unknown_version_fails_the_handshake() {
    assert_eq!(resolve_version(8192, version::UNKNOWN, 8192).unwrap_err(), NpError::BadVersion);
    assert_eq!(resolve_version(8192, "9P2001", 8192).unwrap_err(), NpError::BadVersion);
    assert_eq!(resolve_version(8192, "", 8192).unwrap_err(), NpError::BadVersion);
}

#[test]
fn the_client_shrinks_to_the_server_but_never_grows() {
    // Server smaller: the client must adopt it or frame messages the server
    // will reject.
    assert_eq!(resolve_version(65536, version::V9P2000L, 8192).unwrap().msize, 8192);
    // Server larger: the client keeps its own, because the transport was sized
    // against the request, not against whatever the server would allow.
    assert_eq!(resolve_version(8192, version::V9P2000L, 65536).unwrap().msize, 8192);
    // Equal.
    assert_eq!(resolve_version(8192, version::V9P2000L, 8192).unwrap().msize, 8192);
}

#[test]
fn a_server_below_the_protocol_floor_fails_rather_than_being_clamped_up() {
    // Clamping up would leave the two sides framing to different sizes.
    assert_eq!(resolve_version(65536, version::V9P2000L, limits::MIN_MSIZE - 1).unwrap_err(),
               NpError::BadVersion);
    assert_eq!(resolve_version(65536, version::V9P2000L, 0).unwrap_err(), NpError::BadVersion);
    assert!(resolve_version(65536, version::V9P2000L, limits::MIN_MSIZE).is_ok());
}

#[test]
fn the_default_frame_size_leaves_room_for_the_io_envelope() {
    // A default one byte short of a round payload forces a second round trip on
    // every full-size transfer.
    assert_eq!(limits::DEFAULT_MSIZE as usize, 128 * 1024 + limits::IOHDRSZ);
    assert!(limits::DEFAULT_MSIZE >= limits::MIN_MSIZE);
}

#[test]
fn the_virtio_frame_ceiling_reserves_its_descriptors() {
    // Three descriptors are not available for payload: the request header run,
    // the reply header, and the page a non-aligned payload spills into.
    assert_eq!(limits::virtio_max_msize(4096), 4096 * (128 - 3));
    assert_eq!(limits::virtio_max_msize(16384), 16384 * (128 - 3));
    assert!(limits::virtio_max_msize(4096) >= limits::MIN_MSIZE);
}
