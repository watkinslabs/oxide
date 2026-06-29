// 009 mmap — one syscall, one file (docs/53 §0). Moved verbatim from lib.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// # C: O(log N_vmas)
pub fn kernel_mmap(args: &SyscallArgs) -> i64 {
    let fd     = args.a4 as i64;
    let mut offset = args.a5;
    let flags  = args.a3;
    const MAP_ANON: u64 = 0x20;
    const MAP_SHARED: u64 = 0x01;
    // File-backed mmap: resolve fd, wrap as FileBacking, pass to glue_mmap.
    // A device exposing a contiguous physical range (e.g. /dev/fbN, the
    // framebuffer) is mapped straight to that PA (Linux remap_pfn_range) via
    // `phys_base` instead of a page-cache FileBacking. Anonymous → None/None.
    let mut backing: Option<alloc::sync::Arc<dyn vmm::FileBacking>> = None;
    let mut phys_base: Option<u64> = None;
    // MAP_SHARED|MAP_ANON: Linux `shmem_zero_setup` — back the mapping with a
    // fresh ANONYMOUS tmpfs (shmem) inode so its frames are owned by one
    // object that parent + child alias across fork(2). The File-backed SHARED
    // fault/fork/teardown paths (mm-vmm) then share the frames (no COW split,
    // no W-strip), so writes are mutually visible — fixing the lost-write
    // corruption that COW-splitting MAP_SHARED|ANON caused. Offset is 0 (anon
    // inode starts empty, grows sparse + zero-filled on demand). MAP_PRIVATE|
    // MAP_ANON is unchanged: pure zero-fill COW (backing stays None).
    if (flags & MAP_ANON) != 0 {
        if (flags & MAP_SHARED) != 0 {
            backing = Some(crate::mmap_file::InodeFileBacking::new(::fs::tmpfs::tmpfs_anon_file()));
            offset = 0;
        }
    } else if fd >= 0 {
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
            None => backing = Some(crate::mmap_file::InodeFileBacking::new(inode.clone())),
        }
    }
    match pmm::user_as::glue_mmap(args.a0, args.a1, args.a2, args.a3, fd, offset, backing, phys_base) {
        Ok(va)  => va as i64,
        Err(rv) => rv,
    }
}
