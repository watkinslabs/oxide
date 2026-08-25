//! The write paths, driven end to end against an image in memory.

use crate::test_image::{self, Builder, CLUSTER};
use crate::time::Stamp;
use crate::uapi::*;
use crate::volume::dirops::rename::{RENAME_EXCHANGE, RENAME_NOREPLACE};
use crate::chain::Chain;
use crate::volume::{DirHandle, Volume};
use sectors::MemImage;
use syscall::errno::Errno;

fn stamp() -> Stamp {
    Stamp { fields: dostime::DosTime { time: (12 << 11) | (30 << 5) | 5,
                                       date: (40 << 9) | (6 << 5) | 15, cs: 0 },
            tz: TZ_VALID }
}

fn root(_v: &Volume<MemImage>) -> DirHandle { DirHandle::Root }

fn names(v: &Volume<MemImage>) -> alloc::vec::Vec<alloc::string::String> {
    v.read_dir(&v.root_chain()).unwrap().into_iter().map(|e| e.name).collect()
}

#[path = "write/files.rs"]
mod files;
#[path = "write/dirs.rs"]
mod dirs;
#[path = "write/rename.rs"]
mod rename;
#[path = "write/integrity.rs"]
mod integrity;
