//! What one mount reports about the errors its volume has seen.
//!
//! Nine reports over one record: how many errors the volume has had, and the
//! first and the last of them. A monitoring daemon polls the count; the two
//! events are what someone reads afterwards to find out what happened.
//!
//! The record is seeded from the superblock at mount, so these answer for the
//! volume's whole life rather than for this boot.
//!
//! Absent, because the one place this filesystem reports an error from is
//! handed the failure and not the object it was found on: `first_error_line`,
//! `last_error_line`, `first_error_func` and `last_error_func`, which name a
//! source coordinate this build does not carry. The inode and block reports
//! ARE published — the record holds them, seeded from the volume, and zero is
//! the value the record itself uses for "the site did not name one".

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::errstat::{ErrEvent, ErrRecord};
use crate::fsattr::{line_u64, Attr};
use crate::rootfs::RootfsState;

/// One report per field of the record. # C: O(1)
pub fn attrs(st: &Arc<RootfsState>, dev: &str) -> Vec<Attr> {
    let mut out = alloc::vec![report(st, dev, "errors_count", |r| r.count as u64)];
    out.extend(event_attrs(st, dev, "first", |r| r.first));
    out.extend(event_attrs(st, dev, "last", |r| r.last));
    out
}

/// The four reports over one recorded event.
///
/// Named by a `&'static str` pair rather than built from the `which` word,
/// because an attribute's name is what a reader opens and a name assembled at
/// runtime could not be checked against the reference's spelling.
/// # C: O(1)
fn event_attrs(st: &Arc<RootfsState>, dev: &str, which: &str,
               pick: fn(&ErrRecord) -> ErrEvent) -> Vec<Attr> {
    let names: [&'static str; 4] = if which == "first" {
        ["first_error_time", "first_error_ino", "first_error_block", "first_error_errcode"]
    } else {
        ["last_error_time", "last_error_ino", "last_error_block", "last_error_errcode"]
    };
    alloc::vec![
        report(st, dev, names[0], move |r| pick(r).time_secs),
        report(st, dev, names[1], move |r| pick(r).ino as u64),
        report(st, dev, names[2], move |r| pick(r).block),
        report(st, dev, names[3], move |r| pick(r).errcode as u64),
    ]
}

/// One number read off the live record. # C: O(1)
fn report<F>(st: &Arc<RootfsState>, dev: &str, name: &'static str, f: F) -> Attr
    where F: Fn(&ErrRecord) -> u64 + Send + Sync + 'static
{
    let st = Arc::clone(st);
    Attr::ro(dev, name, Arc::new(move || Ok(line_u64(f(&st.mount.error_record())))))
}
