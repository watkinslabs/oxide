//! The write paths, driven end to end against an image in memory.

use crate::test_image::{self, CLUSTER};
use crate::uapi::*;
use crate::volume::Volume;
use sectors::MemImage;
use syscall::errno::Errno;

/// A timestamp every test writes with, so nothing depends on a clock.
fn now() -> i64 { crate::time::from_unix(vfs::timespec::Timespec64::from_secs(1_800_000_000)) }

fn names(v: &Volume<MemImage>) -> alloc::vec::Vec<alloc::string::String> {
    v.read_dir(MFT_REC_ROOT).unwrap().into_iter().map(|e| e.name).collect()
}


#[path = "tests/create.rs"]
mod create;
#[path = "tests/data.rs"]
mod data;
#[path = "tests/directories.rs"]
mod directories;
#[path = "tests/rename.rs"]
mod rename;
#[path = "tests/persistence.rs"]
mod persistence;
