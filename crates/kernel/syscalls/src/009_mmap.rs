// 009 mmap — one syscall, one file (docs/53 §0). Moved verbatim from lib.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

struct DrmDumbBacking {
    pin: drm::dumb::DumbMmapPin,
}

impl vmm::FileBacking for DrmDumbBacking {
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, vmm::FileBackingError> {
        Err(vmm::FileBackingError::Io)
    }

    fn size_hint(&self) -> u64 { self.pin.size }

    fn ino(&self) -> u64 {
        0xD000_0000u64 | ((self.pin.card_id as u64) << 32) | self.pin.handle as u64
    }

    fn shared_frame(&self, off: u64) -> Result<Option<vmm::SharedFrame>, vmm::FileBackingError> {
        if (off & 0xfff) != 0 || off >= self.pin.size {
            return Ok(None);
        }
        Ok(Some(vmm::SharedFrame { pa: self.pin.pa + off, map_ref_held: false }))
    }
}

impl Drop for DrmDumbBacking {
    fn drop(&mut self) {
        drm::dumb::unpin_mmap(self.pin);
    }
}

/// # C: O(log N_vmas)
pub fn kernel_mmap(args: &SyscallArgs) -> i64 {
    let fd     = args.a4 as i32;
    let mut offset = args.a5;
    let flags  = args.a3;
    use pmm::mmap_flags::{
        validate_file_access, MAP_ANON, MAP_SHARED, MAP_SHARED_VALIDATE, MAP_TYPE,
        PROT_EXEC, PROT_READ, PROT_WRITE,
    };
    let map_type = flags & MAP_TYPE;
    let shared = map_type == MAP_SHARED || map_type == MAP_SHARED_VALIDATE;
    // Linux `do_mmap`: "does the application expect PROT_READ to imply
    // PROT_EXEC?" — personality(READ_IMPLIES_EXEC) upgrades any readable
    // mapping to executable, except when the backing file lives on a noexec
    // mount (decided in the file branch below, where the mount is known).
    let mut prot = args.a2;
    let rier = (prot & PROT_READ) != 0
        && sched::live::current().map(|c| sched::personality::read_implies_exec(c)).unwrap_or(false);
    let mut may_prot = vmm::VmaProt::READ | vmm::VmaProt::WRITE | vmm::VmaProt::EXEC;
    // Properties the mapped FILE imposes on the VMA, independent of the flags
    // the caller passed.
    let mut file_vma_flags = vmm::VmaFlags::empty();
    // File-backed mmap: resolve fd, wrap as FileBacking, pass to glue_mmap.
    // A device exposing a contiguous physical range (e.g. /dev/fbN, the
    // framebuffer) is mapped straight to that PA (Linux remap_pfn_range) via
    // `phys_range` instead of a page-cache FileBacking. Anonymous → None/None.
    let mut backing: Option<alloc::sync::Arc<dyn vmm::FileBacking>> = None;
    let mut phys_range: Option<(u64, vmm::PhysCacheMode)> = None;
    let mut seal_write_reservation: Option<vmm::WritableMapReservation> = None;
    // MAP_SHARED|MAP_ANON: Linux `shmem_zero_setup` — back the mapping with a
    // fresh ANONYMOUS tmpfs (shmem) inode so its frames are owned by one
    // object that parent + child alias across fork(2). The File-backed SHARED
    // fault/fork/teardown paths (mm-vmm) then share the frames (no COW split,
    // no W-strip), so writes are mutually visible — fixing the lost-write
    // corruption that COW-splitting MAP_SHARED|ANON caused. Offset is 0 (anon
    // inode starts empty, grows sparse + zero-filled on demand). MAP_PRIVATE|
    // MAP_ANON is unchanged: pure zero-fill COW (backing stays None).
    if (flags & MAP_ANON) != 0 {
        if (flags & MAP_TYPE) == MAP_SHARED {
            backing = Some(crate::mmap_file::InodeFileBacking::new(::fs::tmpfs::tmpfs_anon_file()));
            offset = 0;
        }
        if rier { prot |= PROT_EXEC; }
    } else {
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
        if let Err(e) = ::fs::inotify::check_mmap_perm(&file.inode(), offset, args.a1) {
            return -(e.as_i32() as i64);
        }
        let path_noexec = file.vfsmount()
            .map(|m| m.is_noexec() || m.sb().is_noexec())
            .unwrap_or(false);
        if rier && !path_noexec { prot |= PROT_EXEC; }
        if let Err(e) = validate_file_access(
            flags,
            prot,
            file.f_mode().contains(vfs::Fmode::READ),
            file.f_mode().contains(vfs::Fmode::WRITE),
            path_noexec,
        ) {
            return e;
        }
        if shared && !file.f_mode().contains(vfs::Fmode::WRITE) {
            may_prot.remove(vmm::VmaProt::WRITE);
        }
        if path_noexec {
            may_prot.remove(vmm::VmaProt::EXEC);
        }
        let inode = file.inode();
        if let Some(seals) = inode.fcntl_seals() {
            let keep_may_write = match crate::fcntl_seal::plan_write_sealed_mmap(
                seals.load(core::sync::atomic::Ordering::Acquire),
                shared,
                prot & PROT_WRITE != 0,
                may_prot.contains(vmm::VmaProt::WRITE),
            ) {
                Ok(keep) => keep,
                Err(error) => return -(error.as_i32() as i64),
            };
            if !keep_may_write {
                may_prot.remove(vmm::VmaProt::WRITE);
            } else if shared {
                seal_write_reservation = match inode.file_rmap().reserve_writable() {
                    Ok(reservation) => Some(reservation),
                    Err(_) => return -(Errno::Eperm.as_i32() as i64),
                };
            }
        }
        // Secret memory: its pages are absent from the kernel's linear map,
        // so they can be neither swapped nor dumped and there is no private
        // copy to make. The mapping must be shared, and it carries the locked
        // and never-dumped properties whether the caller asked or not — which
        // is also what charges it against the memlock limit below.
        if ::fs::secretmem::is_secretmem(inode) {
            match crate::secretmem::secretmem_mmap_prepare(shared) {
                Ok(f) => file_vma_flags |= f,
                Err(e) => return -(e.as_i32() as i64),
            }
        }
        // DRM dumb buffers: the `offset` is a MODE_MAP_DUMB cookie that
        // selects the buffer. Pin the dumb handle for the VMA lifetime and map
        // it through the file-backed shared-frame path so PTE refs keep pages
        // alive until munmap/AS teardown.
        if let Some(pin) = drm::node::pin_mmap_backing(inode, offset) {
            if (flags & MAP_SHARED) == 0 || args.a1 > pin.size {
                drm::dumb::unpin_mmap(pin);
                return -(Errno::Einval.as_i32() as i64);
            }
            let drm_backing: alloc::sync::Arc<dyn vmm::FileBacking> =
                alloc::sync::Arc::new(DrmDumbBacking { pin });
            return match pmm::user_as::glue_mmap(args.a0, args.a1, prot, args.a3, fd as i64, 0, Some(drm_backing), None, None, may_prot, vmm::VmaFlags::empty()) {
                Ok(va)  => va as i64,
                Err(rv) => rv,
            };
        }
        // io_uring fd: map the ring page (SQ/CQ/SQE all live in it) so userspace
        // shares the rings with the kernel. The ring is a REFCOUNTED kernel RAM
        // frame (alloc_object_frame), NOT device MMIO — so map it as a `kframe`
        // (VmaBacking::KernelFrame), which inc_ref's the frame for the lifetime
        // of the mapping. Mapping it as a phys range (remap_pfn_range) instead
        // left the frame's refcount/mapcount untouched, so closing the fd
        // (IoUring::Drop) freed the ring page while userspace still mapped it —
        // a free-while-mapped UAF whose stray ring writes corrupted the kalloc
        // heap (the root cause the corruption hunt traced, state.md).
        if let Some((pa, len)) = crate::io_uring::mmap_backing(inode, offset) {
            if args.a1 > len { return -(Errno::Einval.as_i32() as i64); }
            return match pmm::user_as::glue_mmap(args.a0, args.a1, prot, args.a3, fd as i64, 0, None, None, Some(pa), may_prot, vmm::VmaFlags::empty()) {
                Ok(va)  => va as i64,
                Err(rv) => rv,
            };
        }
        if let Some(result) = crate::packet_mmap::backing(&file, offset, args.a1, flags) {
            let packet_backing = match result { Ok(value) => value, Err(error) => return error };
            return match pmm::user_as::glue_mmap(args.a0, args.a1, prot, args.a3,
                                                fd as i64, 0, Some(packet_backing), None, None, may_prot, vmm::VmaFlags::empty()) {
                Ok(va) => va as i64,
                Err(error) => error,
            };
        }
        // Socket fd: a TCP socket maps a `TCP_ZEROCOPY_RECEIVE` window, whose
        // pages are REFCOUNTED RAM frames published through the file-backed
        // direct-frame arm (the fault installs one PTE reference per page, and
        // munmap/teardown release it). Never a phys range: that arm counts no
        // reference, so the owner releasing a page while userspace still maps
        // it would be a free-while-mapped UAF. Every other socket has no
        // mapping operation at all.
        if let Some(result) = crate::tcp_zerocopy::mmap_backing(&file, prot, args.a1) {
            let zc_backing = match result { Ok(value) => value, Err(error) => return error };
            return match pmm::user_as::glue_mmap(args.a0, args.a1, prot, args.a3,
                                                fd as i64, 0, Some(zc_backing), None, None, may_prot, vmm::VmaFlags::empty()) {
                Ok(va) => va as i64,
                Err(error) => error,
            };
        }
        match sysfs::pci_resource_mmap_backing(inode) {
            Some(Ok((pa, len))) => {
                if offset.saturating_add(args.a1) > len { return -(Errno::Einval.as_i32() as i64); }
                phys_range = Some((pa, vmm::PhysCacheMode::Device));
            }
            Some(Err(error)) => return crate::namei_common::errno_from_vfs(error),
            None => match fbdev::devfs::mmap_backing(inode) {
            Some((pa, len, cache)) => {
                // The mapped window must fit within the device's backing.
                if offset.saturating_add(args.a1) > len {
                    return -(Errno::Einval.as_i32() as i64);
                }
                phys_range = Some((pa, cache));
            }
            None => {
                #[cfg(feature = "debug-atexit")]
                {
                    let ino = inode.ino();
                    if ino & 0xffff_ffff_0000_0000 == 0x6e54_0000_0000_0000 {
                        klog::write_raw(b"[DYNMMAP] tid=");
                        klog::write_dec_u64(sched::live::current().map(|c| c.tid as u64).unwrap_or(0));
                        klog::write_raw(b" ino=");
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
                // Linux `generic_file_mmap`/`generic_file_readonly_mmap` run
                // `file_accessed(file)` when the mapping is established, NOT on
                // each fault — this is also the only atime a mapped `execve`
                // image ever gets (the exec path never touches atime itself).
                vfs::file_accessed(&file);
                // The mapping remembers the name it was established under, so
                // a core dump can tell a debugger which object to reopen for
                // the pages it did not carry.
                let map_path = file.dentry().dentry_path(None);
                backing = Some(crate::mmap_file::InodeFileBacking::new_named(
                    inode.clone(), map_path.into_bytes()));
            },
        },
        }
    }
    let result = pmm::user_as::glue_mmap(
        args.a0, args.a1, prot, args.a3, fd as i64, offset, backing, phys_range,
        None, may_prot, file_vma_flags,
    );
    drop(seal_write_reservation);
    match result {
        Ok(va)  => {
            #[cfg(feature = "debug-atexit")]
            if fd >= 0 {
                klog::write_raw(b"[DYNMMAP] tid=");
                klog::write_dec_u64(sched::live::current().map(|c| c.tid as u64).unwrap_or(0));
                klog::write_raw(b" -> ");
                klog::write_hex_u64(va);
                klog::write_raw(b"\n");
            }
            va as i64
        },
        Err(rv) => rv,
    }
}
