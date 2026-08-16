//! Tests for the allocation table's write side.
//!
//! Module manifest:
//! - `entry`: one entry written at each width, and the bits it must not touch.
//! - `alloc`: the scan order, the wrap, and what a shortfall undoes.
//! - `free`:  releasing and truncating, including corrupt and circular chains.
//! - `count`: the free total, by scan and by maintenance.
//! - `zero`:  which newly claimed clusters must be cleared.

use crate::bpb::Bpb;
use crate::geometry::{resolve, FatWidth, Geometry};
use ::alloc::vec::Vec;
use ::alloc::vec;

/// A small volume of each width, with a table big enough not to clamp.
pub fn geo(width: FatWidth) -> (Geometry, Vec<u8>) {
    let b = match width {
        FatWidth::Fat12 => Bpb { sector_size: 512, sec_per_clus: 1, reserved: 1, fats: 1,
            dir_entries: 16, media: 0xf8, fat_length16: 4, fat_length32: 0,
            total_sect16: 600, total_sect32: 0, root_cluster: 0, fsinfo_sector: 0 },
        FatWidth::Fat16 => Bpb { sector_size: 512, sec_per_clus: 1, reserved: 1, fats: 1,
            dir_entries: 16, media: 0xf8, fat_length16: 64, fat_length32: 0,
            total_sect16: 0, total_sect32: 20_000, root_cluster: 0, fsinfo_sector: 0 },
        FatWidth::Fat32 => Bpb { sector_size: 512, sec_per_clus: 1, reserved: 1, fats: 1,
            dir_entries: 0, media: 0xf8, fat_length16: 0, fat_length32: 256,
            total_sect16: 0, total_sect32: 20_000, root_cluster: 2, fsinfo_sector: 1 },
    };
    let g = resolve(&b).expect("valid volume");
    assert_eq!(g.width, width);
    let table = vec![0u8; (g.fat_length * g.sector_size) as usize];
    (g, table)
}

#[path = "tests/entry.rs"] mod entry;
#[path = "tests/alloc.rs"] mod alloc;
#[path = "tests/free.rs"] mod free;
#[path = "tests/count.rs"] mod count;
#[path = "tests/zero.rs"] mod zero;
