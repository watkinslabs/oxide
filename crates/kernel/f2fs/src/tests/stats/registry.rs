//! The list of mounts, and the numbering the report takes from it.
//!
//! One test, not several. The list is global — the report is a single file
//! describing every mount — so two tests registering at once would each see
//! the other's volumes, and a suite that passes only when run alone is not a
//! check.

use alloc::string::{String, ToString};
use alloc::sync::Arc;

use crate::stats::registry::{self, PartFn};

/// # C: O(1)
fn part(text: &'static str) -> PartFn {
    Arc::new(move |i: usize| Ok(alloc::format!("[{i}:{text}]")))
}

#[test]
fn the_report_covers_every_mount_in_the_order_they_were_published() {
    registry::clear();
    assert_eq!(registry::mounted(), 0);
    assert_eq!(registry::status_body().unwrap(), b"");

    registry::register("vda", part("a"));
    registry::register("vdb", part("b"));
    assert_eq!(registry::mounted(), 2);
    assert!(registry::is_registered("vda"));

    // The banner's number is the position in this list, which is why the
    // renderer is handed its index rather than remembering one: a mount that
    // was withdrawn must not leave a gap in the numbering.
    let body = String::from_utf8(registry::status_body().unwrap()).unwrap();
    assert_eq!(body, "[0:a][1:b]");

    registry::unregister("vda");
    let body = String::from_utf8(registry::status_body().unwrap()).unwrap();
    assert_eq!(body, "[0:b]", "the survivor is renumbered rather than leaving a hole");

    // A device mounted again while a stale entry survives must replace it.
    // Two sections for one device would report a volume nobody can reach
    // beside the live one, and a reader cannot tell which is which.
    registry::register("vdb", part("b2"));
    assert_eq!(registry::mounted(), 1);
    let body = String::from_utf8(registry::status_body().unwrap()).unwrap();
    assert_eq!(body, "[0:b2]");

    // One unreachable volume must not hide the others, which are the ones the
    // reader can still act on.
    let broken: PartFn = Arc::new(|_| Err(vfs::VfsError::Eio));
    registry::register("vdc", broken);
    registry::register("vdd", part("d"));
    let body = String::from_utf8(registry::status_body().unwrap()).unwrap();
    assert_eq!(body, "[0:b2][2:d]");

    // Withdrawing something that was never listed is not an error: unmount
    // runs the withdrawal whether or not the mount ever published.
    registry::unregister("nothing");
    assert_eq!(registry::mounted(), 3);

    registry::clear();
    assert_eq!(registry::mounted(), 0);
}

/// The report's own place in the tree is fixed: a reader opens a path, and a
/// path that moves is a report nobody finds.
#[test]
fn the_report_is_published_where_readers_look_for_it() {
    assert_eq!(registry::STATUS_DIR, "f2fs");
    assert_eq!(registry::STATUS_NAME, "status");
    assert_eq!(registry::STATUS_PATH.to_string(),
               alloc::format!("/sys/kernel/debug/{}/{}",
                              registry::STATUS_DIR, registry::STATUS_NAME));
}
