//! path-PATH_MAX: Linux `getname` enforces a TOTAL pathname length limit
//! (`PATH_MAX`, `linux/limits.h`) at the syscall boundary, distinct from the
//! per-component `NAME_MAX` gate (`path_name_max.rs`). The kernel pathname
//! buffer is 4096 bytes INCLUDING the terminating NUL, so the longest pathname
//! accepted is `PATH_MAX - 1` = 4095 on-disk bytes; a 4096-byte (or longer)
//! pathname is rejected with `ENAMETOOLONG` before any walk begins. The
//! syscall shim (`read_user_path`) consumes this same `vfs::path` primitive.
//! These tests pin the contract on the reusable vfs gate.

use vfs::path::{check_path_len, PATH_MAX};
use vfs::VfsError;

// A pathname of exactly PATH_MAX-1 (4095) on-disk bytes is accepted; one byte
// longer (4096, == PATH_MAX) is rejected. PATH_MAX counts the NUL, so 4095 is
// the longest legal pathname content.
#[test]
fn path_max_boundary() {
    let ok = "a".repeat(PATH_MAX - 1);
    assert_eq!(ok.len(), 4095);
    assert_eq!(check_path_len(&ok), Ok(()), "4095 bytes (PATH_MAX-1) accepted");

    let toolong = "a".repeat(PATH_MAX);
    assert_eq!(toolong.len(), 4096);
    assert_eq!(check_path_len(&toolong), Err(VfsError::Enametoolong), "4096 (==PATH_MAX) rejected");

    let way_long = "a".repeat(PATH_MAX + 1);
    assert_eq!(check_path_len(&way_long), Err(VfsError::Enametoolong), "4097 rejected");
}

// Short / empty pathnames are always fine. (Empty maps to ENOENT at the
// syscall boundary, but the length gate itself accepts it.)
#[test]
fn short_paths_ok() {
    assert_eq!(check_path_len(""), Ok(()));
    assert_eq!(check_path_len("/"), Ok(()));
    assert_eq!(check_path_len("/etc/passwd"), Ok(()));
}

// PATH_MAX is measured in on-disk BYTES, not scalar values: a pathname of
// multi-byte UTF-8 chars overflows at 4096 bytes, not 4096 chars. 1365 '€'
// (3 bytes each) = 4095 bytes (ok); 1366 '€' = 4098 bytes (too long).
#[test]
fn path_max_counts_bytes_not_chars() {
    let euros_ok = "\u{20AC}".repeat(1365); // 4095 bytes, 1365 chars
    assert_eq!(euros_ok.len(), 4095);
    assert_eq!(check_path_len(&euros_ok), Ok(()));

    let euros_bad = "\u{20AC}".repeat(1366); // 4098 bytes, 1366 chars
    assert_eq!(euros_bad.len(), 4098);
    assert_eq!(check_path_len(&euros_bad), Err(VfsError::Enametoolong));
}

// Escaped non-UTF-8 bytes (path_from_bytes maps each bad byte to a 3-byte PUA
// scalar) must count as ONE on-disk byte each, matching the original user
// buffer length the syscall boundary measured — NOT three. A pathname of 4095
// escaped bytes is exactly at the limit and must pass; 4096 must fail.
#[test]
fn path_max_counts_escaped_bytes_as_one() {
    let raw = vec![0xFFu8; PATH_MAX - 1]; // 4095 raw 0xFF bytes
    let escaped = vfs::path_from_bytes(&raw);
    assert!(escaped.len() > PATH_MAX, "escaped form is byte-inflated (>3x)");
    assert_eq!(check_path_len(&escaped), Ok(()), "4095 on-disk bytes ok");

    let raw2 = vec![0xFFu8; PATH_MAX]; // 4096 raw 0xFF bytes
    let escaped2 = vfs::path_from_bytes(&raw2);
    assert_eq!(check_path_len(&escaped2), Err(VfsError::Enametoolong), "4096 on-disk bytes rejected");
}

// A total pathname over PATH_MAX whose every component is within NAME_MAX is
// still rejected by the total gate (the per-component gate would pass it —
// see path_name_max.rs `control_segments_exempt`). This is the complementary
// half of the two-tier length contract.
#[test]
fn long_path_of_legal_components_rejected_by_total_gate() {
    let seg = "x".repeat(255); // exactly NAME_MAX per component
    let mut path = String::new();
    for _ in 0..17 { path.push('/'); path.push_str(&seg); } // 17*256 = 4352 bytes
    assert!(path.len() > PATH_MAX);
    assert_eq!(check_path_len(&path), Err(VfsError::Enametoolong));
}
