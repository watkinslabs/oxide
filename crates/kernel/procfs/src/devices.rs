// /proc/devices — registered character + block major numbers (Linux
// `devinfo`). Char majors reflect the fixed device set the kernel
// mknods at boot (mem/tty/console/pts). Block majors are derived live
// from the block registry snapshot, deduplicated, with the Linux name
// for each major our `registry::major_minor` assigns.
#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use vfs::{Ino, InodeRef};

struct VecFmt<'a>(&'a mut Vec<u8>);
impl<'a> core::fmt::Write for VecFmt<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result { self.0.extend_from_slice(s.as_bytes()); Ok(()) }
}

/// Linux block-driver name for the majors `registry::major_minor` emits.
fn block_major_name(major: u32) -> &'static str {
    match major {
        block::registry::BLOCK_MAJOR_SCSI => "sd",
        block::registry::BLOCK_MAJOR_VIRTIO => "virtblk",
        block::registry::BLOCK_MAJOR_EXT => "blkext",
        _ => "block",
    }
}

fn body() -> Vec<u8> {
        use core::fmt::Write;
        let mut out: Vec<u8> = Vec::with_capacity(256);
        // Character devices: the fixed kernel-created set (real majors).
        out.extend_from_slice(b"Character devices:\n");
        out.extend_from_slice(b"  1 mem\n  4 tty\n  5 /dev/tty\n  5 ptmx\n 10 misc\n136 pts\n");
        // Block devices: dedup majors from the live registry.
        out.extend_from_slice(b"\nBlock devices:\n");
        let disks = block::registry::snapshot();
        let mut seen: [u32; 16] = [u32::MAX; 16];
        let mut n = 0usize;
        for d in disks.iter() {
            let (major, _) = block::registry::major_minor(&d.name, d.index);
            if seen[..n].contains(&major) { continue; }
            if n < seen.len() { seen[n] = major; n += 1; }
            let _ = write!(VecFmt(&mut out), "{major:>3} {}\n", block_major_name(major));
        }
        out
}

/// `/proc/devices` inode (KEYSTONE struct-`Inode`). # C: O(1)
pub fn make_proc_devices() -> InodeRef { crate::dyn_file::make_gen_file(0x3000_1026 as Ino, body) }
