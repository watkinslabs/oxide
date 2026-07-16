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

use alloc::boxed::Box;
use alloc::sync::Arc;
use sync::{Spinlock, TaskList as TaskListClass};
use vfs::{mk_mode, File, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError};

use core::sync::atomic::Ordering;
use crate::dyn_file::read_at;

const SYSCTL_RW_MODE: u16 = 0o644;
const SYSCTL_RO_MODE: u16 = 0o444;
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

/// `i_op` for a writable `/proc` pseudo-leaf (sysctl slot, ip_forward,
/// proc_handler-bound var). Overrides only `truncate`: `ftruncate(2)` on such a
/// leaf must SUCCEED as a no-op (Linux `proc_setattr` ignores the size change on
/// a procfs inode). The `InodeOps` DEFAULT `truncate` returns `Erofs`, which
/// broke `pam_loginuid.so`: its session hook does
/// `open("/proc/self/loginuid", O_RDWR)` → `ftruncate(fd, 0)` → write. The
/// EROFS from `ftruncate` made it log "Error writing /proc/self/loginuid" +
/// "set_loginuid failed" and return `PAM_SESSION_ERR` ("Cannot make/remove an
/// entry for the specified session"), so `user@<uid>.service` failed its PAM
/// session (224/PAM) and the GNOME user manager never started. When the private
/// is a byte-slot `SysctlInode`, shrink the stored bytes to `len` so a read
/// between the truncate and the replacing write reflects the emptied file; for a
/// live-variable leaf (no `SysctlInode` private) it is a pure no-op.
struct SysctlInodeOps;
impl InodeOps for SysctlInodeOps {
    /// # C: O(1)
    fn truncate(&self, inode: &Inode, len: u64) -> KResult<()> {
        if let Some(d) = inode.private::<SysctlInode>() {
            let mut v = d.val.lock();
            if (len as usize) < v.len() { v.truncate(len as usize); }
        }
        Ok(())
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
        InodeBuilder::new(ino, mk_mode(FileType::Regular, SYSCTL_RW_MODE), Arc::new(SysctlInodeOps), Arc::new(SysctlFileOps))
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
        InodeBuilder::new(ino, mk_mode(FileType::Regular, SYSCTL_RW_MODE), Arc::new(SysctlInodeOps), Arc::new(IpForwardFileOps))
            .build()
    }
}

// ---------------------------------------------------------------------------
// proc_handler-bound leaf inode: a `/proc/sys/*` file whose `data` is a LIVE
// kernel variable (D22). Read formats the live value, write parses+validates
// against `extra1`/`extra2` and updates the live variable (EINVAL on reject).
// ---------------------------------------------------------------------------

/// `i_private` wrapper around the type-erased `proc_handler` for a bound leaf.
pub struct BoundSysctlInode { h: Arc<dyn crate::proc_handler::ProcHandler> }

/// `i_fop` for a `proc_handler`-bound leaf — read formats the live variable,
/// write parses+validates+stores it.
struct BoundSysctlFileOps;
impl FileOps for BoundSysctlFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<BoundSysctlInode>().ok_or(VfsError::Einval)?;
        let body = d.h.format();
        Ok(read_at(&body, off, buf))
    }
    fn write(&self, inode: &Inode, off: u64, src: &[u8]) -> KResult<usize> {
        let d = inode.private::<BoundSysctlInode>().ok_or(VfsError::Einval)?;
        if off == 0 {
            // proc_dointvec_minmax / proc_dobool / proc_dostring: parse +
            // validate + update the live variable; EINVAL on a bad write.
            d.h.store(src).map_err(|_| VfsError::Einval)?;
        }
        Ok(src.len())
    }
    fn read_file(&self, file: &File, off: u64, buf: &mut [u8]) -> KResult<usize> {
        read_bound_handler(open_handler(file)?, off, buf)
    }
    fn write_file(&self, file: &File, off: u64, src: &[u8]) -> KResult<usize> {
        write_bound_handler(open_handler(file)?, off, src)
    }
    fn read_nonblock_file(&self, file: &File, off: u64, buf: &mut [u8]) -> KResult<usize> {
        read_bound_handler(open_handler(file)?, off, buf)
    }
    fn write_nonblock_file(&self, file: &File, off: u64, src: &[u8]) -> KResult<usize> {
        write_bound_handler(open_handler(file)?, off, src)
    }
    fn on_open_file(&self, file: &File) -> KResult<()> {
        let d = file.inode().private::<BoundSysctlInode>().ok_or(VfsError::Einval)?;
        if let Some(h) = d.h.bind() {
            let state = Box::into_raw(Box::new(h)) as u64;
            file.set_private_data(state);
        }
        Ok(())
    }
    fn on_release_file(&self, file: &File) {
        let state = file.private_data();
        if state == 0 { return; }
        file.set_private_data(0);
        // SAFETY: on_open_file stored one Box<Arc<dyn ProcHandler>> pointer in
        // this File, and final release consumes that exact allocation once.
        unsafe { drop(Box::from_raw(state as *mut Arc<dyn crate::proc_handler::ProcHandler>)); }
    }
}

fn open_handler(file: &File) -> KResult<&dyn crate::proc_handler::ProcHandler> {
    let state = file.private_data();
    if state == 0 {
        let d = file.inode().private::<BoundSysctlInode>().ok_or(VfsError::Einval)?;
        return Ok(d.h.as_ref());
    }
    // SAFETY: nonzero private_data was installed by on_open_file as a live
    // Box<Arc<dyn ProcHandler>> and remains owned until this File's release.
    let h = unsafe { &*(state as *const Arc<dyn crate::proc_handler::ProcHandler>) };
    Ok(h.as_ref())
}

fn read_bound_handler(h: &dyn crate::proc_handler::ProcHandler, off: u64,
    buf: &mut [u8]) -> KResult<usize>
{
    let body = h.format();
    Ok(read_at(&body, off, buf))
}

fn write_bound_handler(h: &dyn crate::proc_handler::ProcHandler, off: u64,
    src: &[u8]) -> KResult<usize>
{
    if off == 0 { h.store(src).map_err(|_| VfsError::Einval)?; }
    Ok(src.len())
}

/// Build a `/proc/sys/*` leaf inode bound to a live kernel variable via the
/// `proc_handler` model. Writable leaves are `0o644`, read-only `0o444`.
/// # C: O(1)
pub fn bound_sysctl_inode(h: Arc<dyn crate::proc_handler::ProcHandler>) -> InodeRef {
    let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
    let perm = if h.writable() { SYSCTL_RW_MODE } else { SYSCTL_RO_MODE };
    InodeBuilder::new(ino, mk_mode(FileType::Regular, perm), Arc::new(SysctlInodeOps), Arc::new(BoundSysctlFileOps))
        .private(Arc::new(BoundSysctlInode { h }))
        .build()
}
