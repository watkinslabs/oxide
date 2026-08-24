#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

//! FAT: the filesystem on every EFI system partition and almost every USB
//! stick handed between machines.
//!
//! Without it `/boot/efi` cannot be mounted on a UEFI install and no removable
//! medium formatted elsewhere can be read at all.
//!
//! Module manifest:
//! - `bpb`:      the boot sector's fields, and which of them are valid.
//! - `geometry`: where everything lives, and which FAT width this volume is.
//! - `dirent`:   the 32-byte records, and the long name spread across several.
//! - `name`:     code pages, 8.3 generation, long-name slots, name matching.
//! - `time`:     the three timestamps a record carries, and their granularities.
//! - `chain`:    the allocation table, and walking a file's clusters through it.
//! - `cluster_alloc`: changing that table: claiming, linking, releasing.
//! - `fsinfo`:   the FAT32 information sector, and the free-cluster count.
//! - `fatcache`: remembered chain positions, so a seek does not rewalk.
//! - `attrs`:    the attribute byte, and the mode an entry presents as.
//! - `volstate`: the dirty flag, and every copy of the table kept identical.
//! - `namei`:    creating, deleting and renaming names, as pure decisions.
//! - `opts`:     what a mount was asked for, and what it reports back.
//! - `volume`:   a mounted volume: name resolution and file reads over the rest.
//! - `ident`:    what an inode number is on a filesystem that has none.
//! - `mount`:    the VFS-facing filesystem, its inodes and their operations.
//!
//! Both are pure functions over bytes, so the whole layout contract — the
//! validation order, the cluster-count rule that decides FAT12 from FAT16, the
//! clamp against a short table — fails a test without a disk or a mount.

extern crate alloc;

pub mod bpb;
pub mod geometry;
pub mod dirent;
pub mod name;
pub mod time;
pub mod chain;
pub mod cluster_alloc;
pub mod fsinfo;
pub mod fatcache;
pub mod attrs;
pub mod volstate;
pub mod namei;
pub mod opts;
pub mod volume;
pub mod ident;
pub mod mount;

pub use bpb::{Bpb, BpbError};
pub use chain::{classify, clusters_for_size, read_entry, walk, ChainError, Link};
pub use ident::{inode_number, location_of, DirLocation};
pub use mount::{FatFs, MSDOS_SUPER_MAGIC};
pub use namei::{build_group, dir_is_empty, dot_records, find_free_run, find_short, FreeRun, Group};
pub use opts::{Options, MSDOS_NAME_MAX, VFAT_NAME_MAX};
pub use volume::DirHandle;
pub use attrs::{is_exec, make_attrs, make_mode};
pub use cluster_alloc::{alloc_clusters, allocate, count_free, count_free_clusters, free_chain,
    free_chain_state, truncate_chain, truncate_chain_state, write_entry, NewCluster};
pub use fsinfo::{FreeState, FsInfo};
pub use fatcache::{get_cluster, ChainCache, Seek};
pub use volstate::{fat_copy_starts, is_dirty, set_dirty, FAT_STATE_DIRTY};
pub use volume::{DirEntry, SectorSource, Volume};
pub use dirent::{checksum, short_name, short_name_with, Entry, LongName, Record, RecordTimes,
                 ShortEntry};
pub use name::{CodePage, ShortName, CP437, CP737, CP852, CP855, CP857, CP860, CP861, CP862, CP863, CP864, CP865, CP866, CP869, CP874, CP1250, CP1251, SFN_DEFAULT, SFN_MSDOS};
pub use time::{from_unix, to_unix, truncate_atime, truncate_mtime, FatTime, TimeConfig};
pub use geometry::{Geometry, GeometryError, FatWidth};
