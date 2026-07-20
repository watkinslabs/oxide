// /proc/partitions — the live block-device registry (Linux genhd
// `show_partition`). Replaces the header-only static stub. One row per
// registered disk: major, minor, size in 1 KiB blocks, name.
#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use vfs::{Ino, InodeRef};

struct VecFmt<'a>(&'a mut Vec<u8>);
impl<'a> core::fmt::Write for VecFmt<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result { self.0.extend_from_slice(s.as_bytes()); Ok(()) }
}

fn body() -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(256);
        out.extend_from_slice(b"major minor  #blocks  name\n\n");
        for d in block::registry::snapshot() {
            let (maj, min) = (d.number.major, d.number.minor);
            // /proc/partitions #blocks counts 1 KiB blocks (sectors/2).
            let blocks = block::registry::size_512_sectors(
                d.dev.capacity_blocks(), d.dev.block_size()) / 2;
            let _ = core::fmt::Write::write_fmt(&mut VecFmt(&mut out), format_args!(
                "{maj:>4} {min:>7} {blocks:>10} {n}\n", n = d.name));
        }
        out
}

/// `/proc/partitions` inode (KEYSTONE struct-`Inode`). # C: O(1)
pub fn make_proc_partitions() -> InodeRef { crate::dyn_file::make_gen_file(crate::ids::PARTITIONS as Ino, body) }
