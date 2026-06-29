// Writable `/proc/sys/*` tunables (R5). systemd-sysctl applies
// `/etc/sysctl.d/*.conf` by writing these; a `StaticFileInode` returns
// EROFS and the unit fails. `SysctlInode` is a mutable byte slot: writes
// persist, reads reflect the latest write (seeded with a Linux-plausible
// default). The kernel doesn't yet *act* on most tunables (swappiness,
// overcommit are advisory in v1's VM); R5's contract is that userspace
// can set+get them without error so sysctl-applying tools succeed.
//
// Genuine read-only constants (cap_last_cap, ngroups_max, ostype, …)
// stay `StaticFileInode` — Linux rejects writes to those too.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use sync::{Spinlock, TaskList as TaskListClass};
use vfs::{default_inode_ops, mk_mode, FileOps, FileType, Inode, InodeBuilder, InodeRef, KResult, VfsError};

use core::sync::atomic::Ordering;
use crate::dyn_file::read_at;
use crate::live::NEXT_INO;

/// `i_private` for a mutable sysctl value (KEYSTONE struct-`Inode`). Stored
/// verbatim (callers write e.g. "1\n" or "1"); reads return exactly the
/// stored bytes. `bounds` is the `proc_dointvec_minmax` window
/// (`extra1`/`extra2`): when `Some((min,max))` a write is parsed + range-checked
/// before it is stored (EINVAL on a non-integer or out-of-range value, like
/// Linux); `None` is a plain `proc_dointvec`-style free byte slot.
pub struct SysctlInode {
    val:    Spinlock<alloc::vec::Vec<u8>, TaskListClass>,
    bounds: Option<(i64, i64)>,
}

/// `i_fop` for a writable sysctl byte slot — read returns the stored bytes;
/// write (offset 0) validates against `bounds` then replaces them.
struct SysctlFileOps;
impl FileOps for SysctlFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<SysctlInode>().ok_or(VfsError::Einval)?;
        let body = d.val.lock();
        Ok(read_at(&body, off, buf))
    }
    fn write(&self, inode: &Inode, off: u64, src: &[u8]) -> KResult<usize> {
        let d = inode.private::<SysctlInode>().ok_or(VfsError::Einval)?;
        // sysctl writes replace the value (offset 0). A normal `echo >`
        // truncates first; we treat any write as a full replace so the
        // stored value always reflects the last writer.
        if off == 0 {
            // proc_dointvec_minmax: a bounded integer leaf rejects a
            // non-integer / out-of-range write before it is stored.
            if let Some((min, max)) = d.bounds {
                crate::proc_dointvec::validate_intvec(src, min, max)
                    .map_err(|_| VfsError::Einval)?;
            }
            let mut v = d.val.lock();
            v.clear();
            v.extend_from_slice(src);
        }
        Ok(src.len())
    }
}

impl SysctlInode {
    /// New unbounded writable sysctl inode seeded with `default`
    /// (`proc_dointvec` free byte slot). # C: O(len default)
    pub fn new(default: &[u8]) -> InodeRef {
        Self::new_inner(default, None)
    }

    /// New `proc_dointvec_minmax` integer leaf: writes are parsed + checked
    /// against `[min,max]` (EINVAL otherwise). # C: O(len default)
    pub fn new_minmax(default: &[u8], min: i64, max: i64) -> InodeRef {
        Self::new_inner(default, Some((min, max)))
    }

    /// # C: O(len default)
    fn new_inner(default: &[u8], bounds: Option<(i64, i64)>) -> InodeRef {
        let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
        InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), Arc::new(SysctlFileOps))
            .private(Arc::new(SysctlInode { val: Spinlock::new(default.to_vec()), bounds }))
            .build()
    }
}

/// `i_fop` for `/proc/sys/net/ipv4/ip_forward` — reflects the live forwarding
/// flag; write parses a boolean and sets it.
struct IpForwardFileOps;
impl FileOps for IpForwardFileOps {
    fn read(&self, _inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let body: &[u8] = if net::forwarding::ipv4_enabled() { b"1\n" } else { b"0\n" };
        Ok(read_at(body, off, buf))
    }
    fn write(&self, _inode: &Inode, off: u64, src: &[u8]) -> KResult<usize> {
        if off == 0 {
            let Some(enabled) = net::forwarding::parse_bool_sysctl(src) else {
                return Err(VfsError::Einval);
            };
            net::forwarding::set_ipv4_enabled(enabled);
        }
        Ok(src.len())
    }
}

/// `/proc/sys/net/ipv4/ip_forward` inode (KEYSTONE struct-`Inode`).
pub struct IpForwardInode;
impl IpForwardInode {
    /// New `/proc/sys/net/ipv4/ip_forward` inode. # C: O(1)
    pub fn new() -> InodeRef {
        let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
        InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), Arc::new(IpForwardFileOps))
            .build()
    }
}
