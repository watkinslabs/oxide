// /proc/buddyinfo — per-order free-block counts from the buddy allocator
// (Linux `frag_show`). One row per memory zone; oxide has a single
// Normal zone. Column `o` = number of free order-`o` blocks. Counts come
// live from the PMM (`free_orders()`).
#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use vfs::{Ino, InodeRef};

struct VecFmt<'a>(&'a mut Vec<u8>);
impl<'a> core::fmt::Write for VecFmt<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result { self.0.extend_from_slice(s.as_bytes()); Ok(()) }
}

fn body() -> Vec<u8> {
        use core::fmt::Write;
        let mut out: Vec<u8> = Vec::with_capacity(256);
        let orders = match pmm::setup::pmm_static() {
            Some(p) => p.free_orders(),
            None => return out,
        };
        // Single Normal zone (oxide has no DMA/DMA32 split).
        let _ = write!(VecFmt(&mut out), "Node 0, zone   Normal");
        for c in orders.iter() {
            let _ = write!(VecFmt(&mut out), " {c:>6}");
        }
        out.push(b'\n');
        out
}

/// `/proc/buddyinfo` inode (KEYSTONE struct-`Inode`). # C: O(1)
pub fn make_proc_buddyinfo() -> InodeRef { crate::dyn_file::make_gen_file(crate::ids::BUDDYINFO as Ino, body) }
