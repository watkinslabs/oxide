// 009 mmap — one syscall, one file (docs/53 §0). Moved verbatim from lib.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// # C: O(log N_vmas)
pub fn kernel_mmap(args: &SyscallArgs) -> i64 {
    let fd     = args.a4 as i64;
    let offset = args.a5;
    let flags  = args.a3;
    const MAP_ANON: u64 = 0x20;
    // File-backed mmap: resolve fd, wrap as FileBacking, pass to glue_mmap.
    // A device exposing a contiguous physical range (e.g. /dev/fbN, the
    // framebuffer) is mapped straight to that PA (Linux remap_pfn_range) via
    // `phys_base` instead of a page-cache FileBacking. Anonymous → None/None.
    let mut backing: Option<alloc::sync::Arc<dyn vmm::FileBacking>> = None;
    let mut phys_base: Option<u64> = None;
    if (flags & MAP_ANON) == 0 && fd >= 0 {
        let cur = match sched::live::current() {
            Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
        };
        // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
        let fdt = match unsafe { cur.fd_table_ref() } {
            Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
        };
        let file = match fdt.get(fd as i32) {
            Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
        };
        let inode = file.inode();
        // DRM dumb buffers: the `offset` is a MODE_MAP_DUMB cookie that
        // selects the buffer (not a within-buffer byte offset). The
        // PhysRange base must equal the buffer's PA, so pass file_off=0
        // to glue_mmap. Try DRM first; fall through to fbdev, then to
        // a page-cache file-backing.
        if let Some((pa, len)) = drm::node::mmap_backing(inode, offset) {
            if args.a1 > len { return -(Errno::Einval.as_i32() as i64); }
            return match pmm::user_as::glue_mmap(args.a0, args.a1, args.a2, args.a3, fd, 0, None, Some(pa)) {
                Ok(va)  => va as i64,
                Err(rv) => rv,
            };
        }
        // io_uring fd: map the ring page (SQ/CQ/SQE all live in it) straight
        // to its PA so userspace shares the rings with the kernel (Linux
        // io_uring_mmap → remap_pfn_range). Must precede the page-cache
        // fallback below (IoUringInode read/write return EINVAL).
        if let Some((pa, len)) = crate::io_uring::mmap_backing(inode, offset) {
            if args.a1 > len { return -(Errno::Einval.as_i32() as i64); }
            return match pmm::user_as::glue_mmap(args.a0, args.a1, args.a2, args.a3, fd, 0, None, Some(pa)) {
                Ok(va)  => va as i64,
                Err(rv) => rv,
            };
        }
        match fbdev::devfs::mmap_backing(inode) {
            Some((pa, len)) => {
                // The mapped window must fit within the device's backing.
                if offset.saturating_add(args.a1) > len {
                    return -(Errno::Einval.as_i32() as i64);
                }
                phys_base = Some(pa);
            }
            None => {
                #[cfg(feature = "debug-atexit")]
                {
                    let ino = inode.ino();
                    if ino & 0xffff_ffff_0000_0000 == 0x6e54_0000_0000_0000 {
                        klog::write_raw(b"[DYNMMAP] ino=");
                        klog::write_hex_u64(ino);
                        klog::write_raw(b" hint=");
                        klog::write_hex_u64(args.a0);
                        klog::write_raw(b" len=");
                        klog::write_hex_u64(args.a1);
                        klog::write_raw(b" prot=");
                        klog::write_hex_u64(args.a2);
                        klog::write_raw(b" flags=");
                        klog::write_hex_u64(args.a3);
                        klog::write_raw(b" off=");
                        klog::write_hex_u64(offset);
                        klog::write_raw(b"\n");
                    }
                }
                backing = Some(crate::mmap_file::InodeFileBacking::new(inode.clone()));
            },
        }
    }
    match pmm::user_as::glue_mmap(args.a0, args.a1, args.a2, args.a3, fd, offset, backing, phys_base) {
        Ok(va)  => {
            #[cfg(feature = "debug-atexit")]
            if fd >= 0 {
                klog::write_raw(b"[DYNMMAP] -> ");
                klog::write_hex_u64(va);
                klog::write_raw(b"\n");
            }
            va as i64
        },
        Err(rv) => rv,
    }
}
