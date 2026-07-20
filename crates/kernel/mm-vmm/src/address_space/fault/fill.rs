use hal::{MmuOps, Pa, PageSize, UserVirtAddr, Va, PAGE_SIZE_BYTES};

use crate::vma::{FaultAccess, FileBackingError, VmaBacking, VmaFlags};
#[cfg(any(feature = "debug-atexit", feature = "debug-cow"))]
use crate::vma::VmaProt;
use crate::{Error, KResult};

use super::super::AddressSpace;

impl AddressSpace {
    /// Fill a not-present PTE from the VMA backing: anonymous zero page,
    /// file/private page-cache copy, shmem direct frame, kernel frame, or PFNMAP.
    /// # SAFETY: caller supplies the live MMU implementation and valid PMM/rmap callbacks.
    /// # C: O(log N_vmas) + O(page) for copied backings.
    pub(super) unsafe fn handle_not_present<M, A, DR, SR, IR, CA, UA>(
        &self,
        va: UserVirtAddr,
        access: FaultAccess,
        hhdm_offset: u64,
        alloc_frame: &mut A,
        dec_ref: &mut DR,
        set_rmap: &mut SR,
        inc_ref: &mut IR,
        charge_anon: &mut CA,
        uncharge_anon: &mut UA,
    ) -> KResult<()>
    where
        M:  MmuOps,
        A:  FnMut() -> Option<u64>,
        DR: FnMut(u64),
        SR: FnMut(u64, &alloc::sync::Arc<crate::AnonVma>, u32),
        IR: FnMut(u64),
        CA: FnMut() -> KResult<()>,
        UA: FnMut(),
    {
        // Clone the VMA then drop the read guard before File/SHARED backing I/O;
        // holding `vmas` across block sleep deadlocks peer mmap/munmap writers.
        let vma = match self.vmas.read().find_containing(va) {
            Some(v) => v.clone(),
            None    => return Err(Error::Inval),    // EFAULT upstream
        };
        if !vma.permits(access) {
            return Err(Error::Inval);                // EFAULT upstream
        }
        let va_page = va.as_u64() & !(PAGE_SIZE_BYTES - 1);
        if self.brk_fault_past_current(&vma, va_page) { return Err(Error::Inval); }

        match &vma.backing {
            VmaBacking::Anonymous => {
                // An anonymous VMA is created with its reverse-map family.
                // Treat an absent family as corrupted VM metadata rather than
                // allocating a page whose accounting ownership cannot be made
                // canonical.
                let av = vma.anon_vma.as_ref().ok_or(Error::Inval)?;
                charge_anon()?;
                let pa = match alloc_frame() {
                    Some(pa) => pa,
                    None => {
                        uncharge_anon();
                        return Err(Error::NoMem);
                    }
                };
                // Zero-fill via HHDM kernel mirror per `11§5` "zero_or_loaded".
                // SAFETY: pa is a freshly-allocated PMM frame; HHDM
                // mirror at `hhdm_offset + pa` is mapped writable in
                // the kernel's page tables (Limine-installed); 4096
                // bytes is the page granule.
                unsafe {
                    let dst = (hhdm_offset + pa) as *mut u8;
                    hal::zerotrap::trap((dst) as *const u8, (PAGE_SIZE_BYTES as usize) as usize);
                    core::ptr::write_bytes(dst, 0, PAGE_SIZE_BYTES as usize);
                }
                let pte_flags = vma.prot.to_page_flags();
                // DIAG (debug-atexit): anon-arm install in the lib arena — this
                // arm zeros the frame, so if it fires at a library-tail VA the
                // VMA-tree consulted was wrong (an anon VMA covering what should
                // be a File page). ino=0 marks the anon origin.
                #[cfg(feature = "debug-atexit")]
                if (0x7ffff6000000..0x7ffff8000000).contains(&va_page) {
                    crate::tailwatch::log_install(b"anon", 0, 0, va_page, pa, self.root_pa);
                }
                // SAFETY: va_page is the page-aligned faulting user-half VA per find_containing; pa is a fresh PMM frame; flags carry USER for the leaf U bit per `11§5` to_pte_flags; MmuOps state initialised by the live per-arch impl.
                // F157-A1: a demand fault normally installs over an empty slot
                // (`None`); if a stale present leaf is displaced, dec_ref it so
                // refcount stays == live-PTE count (the RANK-1 fix).
                let replaced = unsafe { M::map(Va(va_page), Pa(pa), pte_flags, PageSize::P4K) };
                if replaced.is_none() { self.accounting.install_pte(&vma); }
                if let Some(old) = replaced {
                    // LOST-WRITE (the ld.so link_map corruption): a NotPresent
                    // anon fault just installed a ZERO frame but M::map DISPLACED
                    // a present leaf `old` — a populated page existed here yet
                    // translate() reported it absent both times. Name it.
                    #[cfg(feature = "debug-watchdog")]
                    {
                        klog::write_raw(b"[LOSTWRITE] anon-zero displaced present leaf va=");
                        klog::write_hex_u64(va_page);
                        klog::write_raw(b" old_pa="); klog::write_hex_u64(old.0 & !(PAGE_SIZE_BYTES - 1));
                        klog::write_raw(b" newzero_pa="); klog::write_hex_u64(pa);
                        klog::write_raw(b"\n");
                    }
                    // GAP-1 (displaced-frame UAF): this fault displaced a
                    // present leaf; dec_ref below may free `old`. A peer CPU
                    // of the same mm with a stale TLB entry for va_page->old
                    // could touch a freed+realloc'd frame. Flush peers (this
                    // mm's cpumask only) BEFORE dropping our reference. No-op
                    // on UP / aarch64 / hosted.
                    hal::tlb::shootdown_others_va(va_page, self.cpumask());
                    dec_ref(old.0 & !(PAGE_SIZE_BYTES - 1));
                }
                // F156-rmap: bind the freshly-allocated anonymous
                // page to its VMA family per `page_add_anon_rmap`.
                let idx = ((va_page - vma.start.as_u64()) / PAGE_SIZE_BYTES) as u32;
                set_rmap(pa, av, idx);
                Ok(())
            }
            VmaBacking::KernelBytes { data, off: backing_off } => {
                // ELF-loader-style demand-fault path per docs/31 §4
                // step 3: copy the file-backed bytes for this page
                // into a fresh PMM frame; bytes past the slice length
                // (BSS tail of a PT_LOAD with `p_memsz > p_filesz`)
                // are zero-filled. `backing_off` lets sub-range VMAs
                // (from `clone_subrange`) start mid-Arc without
                // copying the underlying buffer.
                let pa = alloc_frame().ok_or(Error::NoMem)?;
                let va_page = va.as_u64() & !(PAGE_SIZE_BYTES - 1);
                let vma_off = (va_page - vma.start.as_u64()) as usize;
                let off = backing_off.saturating_add(vma_off);
                let page = PAGE_SIZE_BYTES as usize;
                let data_slice: &[u8] = &data[..];
                // SAFETY: pa is a freshly-allocated PMM frame; HHDM
                // mirror at hhdm_offset+pa is mapped writable; we
                // own the full page exclusively until M::map below
                // makes it user-visible.
                unsafe {
                    let dst = (hhdm_offset + pa) as *mut u8;
                    if off >= data_slice.len() {
                        // Entirely BSS (past file-backed extent).
                        hal::zerotrap::trap((dst) as *const u8, (page) as usize);
                        core::ptr::write_bytes(dst, 0, page);
                    } else {
                        let avail = (data_slice.len() - off).min(page);
                        // SAFETY: src is a valid Arc<[u8]> slice covering [off..off+avail]; dst owns `page` bytes; non-overlapping.
                        core::ptr::copy_nonoverlapping(
                            data_slice.as_ptr().add(off), dst, avail,
                        );
                        if avail < page {
                            // SAFETY: dst+avail is within the freshly-allocated frame; tail zero-fills the BSS portion of this page.
                            hal::zerotrap::trap((dst.add(avail)) as *const u8, (page - avail) as usize);
                            core::ptr::write_bytes(dst.add(avail), 0, page - avail);
                        }
                    }
                }
                let pte_flags = vma.prot.to_page_flags();
                // DIAG (debug-atexit): KernelBytes-arm install in the lib arena
                // — this arm zeros BSS tail bytes and NEVER logged before; if it
                // fires at a library VA the VMA consulted was a KernelBytes VMA
                // (exec/ld.so image) where a File VMA should be. ino=1 marks it.
                #[cfg(feature = "debug-atexit")]
                if (0x7ffff6000000..0x7ffff8000000).contains(&va_page) {
                    crate::tailwatch::log_install(b"kbytes", 1, off as u64, va_page, pa, self.root_pa);
                }
                // SAFETY: va_page page-aligned per find_containing; pa is fresh PMM frame; flags carry USER per `11§5`.
                // F157-A1: dec_ref any frame displaced by a stale present leaf.
                let replaced = unsafe { M::map(Va(va_page), Pa(pa), pte_flags, PageSize::P4K) };
                if replaced.is_none() { self.accounting.install_pte(&vma); }
                if let Some(old) = replaced {
                    // LOST-WRITE (kbytes/file arm, ALL ranges incl brk + ld.so
                    // .bss): a demand fault installed over a PRESENT leaf → the
                    // displaced page's live content was dropped. va identifies
                    // the range (0x1000_0000 exe/brk, 0x4003_xxxx ld.so .bss).
                    #[cfg(feature = "debug-watchdog")]
                    { klog::write_raw(b"[LOSTWRITE] demand-install displaced present va=");
                      klog::write_hex_u64(va_page); klog::write_raw(b" old_pa=");
                      klog::write_hex_u64(old.0 & !(PAGE_SIZE_BYTES - 1)); klog::write_raw(b"\n"); }
                    // GAP-1 (displaced-frame UAF): this fault displaced a
                    // present leaf; dec_ref below may free `old`. A peer CPU
                    // of the same mm with a stale TLB entry for va_page->old
                    // could touch a freed+realloc'd frame. Flush peers (this
                    // mm's cpumask only) BEFORE dropping our reference. No-op
                    // on UP / aarch64 / hosted.
                    hal::tlb::shootdown_others_va(va_page, self.cpumask());
                    dec_ref(old.0 & !(PAGE_SIZE_BYTES - 1));
                }
                Ok(())
            }
            VmaBacking::File { backing, off: backing_off } => {
                // File-backed demand-fault per `11§5` + `17§5`. The
                // backing impl reads through the page cache; bytes
                // past file end zero-fill.
                let va_page = va.as_u64() & !(PAGE_SIZE_BYTES - 1);
                let vma_off = (va_page - vma.start.as_u64()) as u64;
                let file_off = backing_off.saturating_add(vma_off);
                let page = PAGE_SIZE_BYTES as usize;
                // DIAG (debug-atexit): every File-arm ENTRY in the lib arena —
                // proves whether the arm runs at all for a given (ino,foff) and
                // which sub-branch (shmem vs fill) it takes. If a corrupted
                // (ino,foff) NEVER appears here, the page was made present by a
                // path OUTSIDE this arm (or never faulted in this process).
                #[cfg(feature = "debug-atexit")]
                if (0x7ffff6000000..0x7ffff8000000).contains(&va_page) {
                    klog::write_raw(b"[FARM] va=");
                    klog::write_hex_u64(va_page);
                    klog::write_raw(b" ino=");
                    klog::write_hex_u64(backing.ino());
                    klog::write_raw(b" foff=");
                    klog::write_hex_u64(file_off);
                    klog::write_raw(if vma.flags.contains(VmaFlags::SHARED) { b" SHARED" } else { b" PRIV" });
                    klog::write_raw(b"\n");
                }
                // Device mappings install their owner frame for both mapping
                // types. Page-cache frames do so only for MAP_SHARED; private
                // file mappings retain the read-copy COW path below.
                let direct = if let Some(pa) = backing.direct_frame(file_off) {
                    Some((pa, false))
                } else if vma.flags.contains(VmaFlags::SHARED) && !cfg!(feature = "debug-no-shmem") {
                    match backing.shared_frame(file_off) {
                        Ok(frame) => frame.map(|frame| (frame.pa, frame.map_ref_held)),
                        Err(FileBackingError::NoMem) => return Err(Error::NoMem),
                        Err(_) => return Err(Error::Io),
                    }
                } else { None };
                if let Some((spa, map_ref_held)) = direct {
                    #[cfg(feature = "debug-boot")]
                    {
                        klog::write_raw(b"[file frame map] va="); klog::write_hex_u64(va_page);
                        klog::write_raw(b" pa="); klog::write_hex_u64(spa);
                        klog::write_raw(b" ino="); klog::write_hex_u64(backing.ino());
                        klog::write_raw(b"\n");
                    }
                    if !map_ref_held { inc_ref(spa); }
                    let pte_flags = vma.prot.to_page_flags();
                    // SAFETY: va_page is page aligned; spa is the owner-backed
                    // frame whose refcount was bumped; flags carry USER.
                    let replaced = unsafe { M::map(Va(va_page), Pa(spa), pte_flags, PageSize::P4K) };
                    if replaced.is_none() { self.accounting.install_pte(&vma); }
                    if let Some(old) = replaced {
                        // Flush peers before releasing a displaced private frame.
                        hal::tlb::shootdown_others_va(va_page, self.cpumask());
                        dec_ref(old.0 & !(PAGE_SIZE_BYTES - 1));
                    }
                    return Ok(());
                }
                let pa = alloc_frame().ok_or(Error::NoMem)?;
                // B240: a non-EOF page MUST be filled completely before its PTE
                // is installed. `read_at` is permitted to return SHORT (page-
                // cache build race, block/extent boundary, or a short
                // `Inode::read`); discarding that count and installing the leaf
                // anyway left the unread bytes ZERO — ld.so then read zeros where
                // library code / relocation data belonged and exit(127)'d ("error
                // while loading shared libraries"). Retry-fill the file-valid
                // extent until full, a real EOF (no progress), or an FS error;
                // only the genuine-EOF tail is legitimately zero. On an
                // unrecoverable short, surface a fatal fault (Linux
                // filemap_fault VM_FAULT_SIGBUS leg, `17§5`) — never a partial page.
                let fsize = backing.size_hint();
                // Bytes that genuinely belong to the file in this page: whole
                // PAGE for an in-file page, `fsize - file_off` for a page
                // straddling EOF, 0 for a page wholly past EOF (pure BSS).
                let mut valid = if file_off >= fsize { 0usize }
                            else { core::cmp::min(page as u64, fsize - file_off) as usize };
                // Size-truth cross-check (Linux filemap_fault uses ONE i_size
                // for both the SIGBUS bound and the read clamp; Oxide's
                // size_hint (vfs i_size) and the backing's own clamp (on-disk
                // inode size) can desynchronize — a too-small size_hint made
                // `valid == 0` skip the fill AND the short-guard, silently
                // installing a zero page over real file content). If the hint
                // claims past-EOF but the backing still serves data at this
                // offset, trust the backing: the fill loop below stops at the
                // backing's own EOF anyway.
                let mut desync = false;
                if valid == 0 {
                    let mut probe = [0u8; 8];
                    if let Ok(n) = backing.read_at(file_off, &mut probe) {
                        if n > 0 {
                            #[cfg(feature = "debug-atexit")]
                            {
                                klog::write_raw(b"[SIZE-DESYNC] ino=");
                                klog::write_hex_u64(backing.ino());
                                klog::write_raw(b" foff=");
                                klog::write_hex_u64(file_off);
                                klog::write_raw(b" hint=");
                                klog::write_hex_u64(fsize);
                                klog::write_raw(b"\n");
                            }
                            valid = page;
                            desync = true;
                        }
                    }
                }
                // DIAG (debug-atexit): log every EOF-straddling / past-EOF fill
                // with the fsize observed AT FAULT TIME — a transiently-small
                // size_hint makes `valid` 0/short and silently installs a zero
                // page ([MAPZERO] corruption: ld.so skips a DT_NEEDED, GOT/.data
                // tail zeroed). Comparing this fsize against the stable exit-time
                // value pins whether i_size fluctuates.
                #[cfg(feature = "debug-atexit")]
                if valid < page {
                    klog::write_raw(b"[FILLTAIL] ino=");
                    klog::write_hex_u64(backing.ino());
                    klog::write_raw(b" foff=");
                    klog::write_hex_u64(file_off);
                    klog::write_raw(b" fsize=");
                    klog::write_hex_u64(fsize);
                    klog::write_raw(b" valid=");
                    klog::write_hex_u64(valid as u64);
                    klog::write_raw(b"\n");
                }
                // DIAG (debug-atexit): the frame this MAP_PRIVATE fill hands out
                // for a lib-arena page. If two processes (different root) log the
                // SAME pa for the SAME va, the "private" copy is not private — a
                // shared frame one process can zero for all (deterministic page,
                // random victim, D=1). Keyed (root,va,pa).
                #[cfg(feature = "debug-atexit")]
                if (0x7ffff6000000..0x7ffff8000000).contains(&va_page) {
                    klog::write_raw(b"[FILLPA] va=");
                    klog::write_hex_u64(va_page);
                    klog::write_raw(b" pa=");
                    klog::write_hex_u64(pa);
                    klog::write_raw(b" root=");
                    klog::write_hex_u64(self.root_pa);
                    klog::write_raw(b" ino=");
                    klog::write_hex_u64(backing.ino());
                    klog::write_raw(b"\n");
                }
                // SAFETY: pa is a freshly-allocated PMM frame; HHDM mirror at hhdm_offset+pa is mapped writable; full page owned exclusively until M::map below makes it user-visible.
                let short = unsafe {
                    let dst = (hhdm_offset + pa) as *mut u8;
                    hal::zerotrap::trap((dst) as *const u8, (page) as usize);
                    core::ptr::write_bytes(dst, 0, page);
                    let slice = core::slice::from_raw_parts_mut(dst, page);
                    let mut filled = 0usize;
                    let mut err = false;
                    let mut no_mem = false;
                    while filled < valid {
                        match backing.read_at(file_off + filled as u64, &mut slice[filled..valid]) {
                            Ok(0)   => break,                 // no progress → real short/EOF
                            Ok(n)   => {
                                #[cfg(feature = "debug-shortfill")]
                                if filled + n < valid {
                                    // A non-EOF region returned short — the exact B240 symptom,
                                    // caught here even when the retry below recovers it.
                                    klog::write_raw(b"[SHORT-FILE-FAULT ino="); klog::write_hex_u64(backing.ino());
                                    klog::write_raw(b" off="); klog::write_hex_u64(file_off + filled as u64);
                                    klog::write_raw(b" n="); klog::write_hex_u64(n as u64);
                                    klog::write_raw(b" valid="); klog::write_hex_u64(valid as u64);
                                    klog::write_raw(b" size="); klog::write_hex_u64(fsize);
                                    klog::write_raw(b"]\n");
                                }
                                filled += n;
                            }
                            Err(FileBackingError::NoMem) => { no_mem = true; err = true; break; }
                            Err(_) => { err = true; break; }
                        }
                    }
                    // A desync-recovered fill legitimately stops at the
                    // BACKING's own EOF mid-page (the zeroed tail is real
                    // bss); only a non-desync shortfall is fatal.
                    (err || (filled < valid && !desync), no_mem)
                };
                if short.0 {
                    // Unrecoverable: the backing could not supply the full
                    // file-valid extent. Do NOT install a partially-zero page
                    // (silent corruption). Free the fresh frame and fail the
                    // fault → SIGBUS-equivalent at the dispatcher (false→fatal).
                    #[cfg(feature = "debug-shortfill")]
                    {
                        klog::write_raw(b"[SHORT-FILE-FAULT-FATAL ino="); klog::write_hex_u64(backing.ino());
                        klog::write_raw(b" off="); klog::write_hex_u64(file_off);
                        klog::write_raw(b" valid="); klog::write_hex_u64(valid as u64);
                        klog::write_raw(b" size="); klog::write_hex_u64(fsize);
                        klog::write_raw(b"]\n");
                    }
                    dec_ref(pa);
                    return Err(if short.1 { Error::NoMem } else { Error::Io });
                }
                // DIAG (debug-atexit): sample the JUST-FILLED frame vs a fresh
                // backing read for lib-arena pages. If they DISAGREE now, the
                // FILL is wrong (read_at nondeterministic / short). If they
                // AGREE now but the page is zero at exit, a later user store
                // zeroed it. Decisive fill-vs-post-write discriminator.
                #[cfg(feature = "debug-atexit")]
                if (0x7ffff6000000..0x7ffff8000000).contains(&va_page) && valid == page {
                    let mut chk = [0u8; 32];
                    if backing.read_at(file_off, &mut chk).is_ok() {
                        // SAFETY: pa is the just-filled frame; HHDM mirror readable; 32 bytes within page.
                        let framebytes = unsafe {
                            core::slice::from_raw_parts((hhdm_offset + pa) as *const u8, 32)
                        };
                        if framebytes != &chk[..] {
                            klog::write_raw(b"[FILLBAD] va=");
                            klog::write_hex_u64(va_page);
                            klog::write_raw(b" ino=");
                            klog::write_hex_u64(backing.ino());
                            klog::write_raw(b" foff=");
                            klog::write_hex_u64(file_off);
                            klog::write_raw(b" frame0=");
                            klog::write_hex_u64(framebytes[0] as u64);
                            klog::write_raw(b" want0=");
                            klog::write_hex_u64(chk[0] as u64);
                            klog::write_raw(b"\n");
                        }
                    }
                }
                // DIAG (debug-atexit): sentinel watch — arm EVERY
                // EOF-straddling writable file-page fill AFTER its content is
                // in place (arming pre-fill made the fill's own zeroing a
                // false [ZEROTRAP]). The zerotrap + fault-entry re-verify
                // then name whoever zeroes one of these frames in place.
                #[cfg(feature = "debug-atexit")]
                if valid < page {
                    if valid > 0 && vma.prot.contains(VmaProt::WRITE) {
                        crate::tailwatch::record(pa, hhdm_offset, self.root_pa);
                    }
                    let tag: &'static [u8] = if vma.prot.contains(VmaProt::WRITE) { b"fill-rw" } else { b"fill-ro" };
                    crate::tailwatch::log_install(tag, backing.ino(), file_off,
                        va.as_u64() & !(PAGE_SIZE_BYTES - 1), pa, 0);
                }
                // debug-cow (this arm is MAP_PRIVATE: the SHARED branch
                // returned above). `pa` is a FRESH private copy of the file
                // bytes — writes to it must never reach shared storage.
                //   * If a frame-backed file (tmpfs/memfd) exposes a cache
                //     frame for this offset, we just handed its content to a
                //     private mapper: snapshot the cache frame so a later
                //     private write that wrongly mutates it surfaces as
                //     [PC-SHARED-WRITE]. Re-verify first (an earlier private
                //     mapper may already have corrupted it). tid/cpu unknown
                //     in mm-vmm here (=0); the authoritative tid is logged at
                //     the cache frame's free in pmm `check_free`.
                //   * If this private page is installed READ-ONLY (no WRITE in
                //     prot, e.g. a private RX/RO file map), track the copy for
                //     [FILE-CORRUPT] — it must stay byte-stable until COW.
                #[cfg(feature = "debug-cow")]
                {
                    if let Ok(Some(frame)) = backing.shared_frame(file_off) {
                        crate::debug_cow::check_pagecache(frame.pa, va_page, hhdm_offset, 0, 0);
                        crate::debug_cow::record_pagecache(frame.pa, hhdm_offset);
                        if frame.map_ref_held {
                            // This diagnostic lookup did not install a PTE. Return its
                            // transient cache-frame hold immediately.
                            dec_ref(frame.pa);
                        }
                    }
                    if !vma.flags.contains(VmaFlags::SHARED) && !vma.prot.contains(VmaProt::WRITE) {
                        crate::debug_cow::record_file(pa, hhdm_offset);
                    }
                }
                // DIAG (debug-mount): log the libc lock page's VA on File-fault
                // so a spurious zap+refault (re-read of file content over ld.so's
                // memset) is correlatable with the EVICT/MUNMAP zap tracer.
                #[cfg(feature = "debug-mount")]
                #[cfg(feature = "debug-mount")]
                if file_off == 0x1e7000 && backing.ino() == 0x6e54000000062076 {
                    klog::write_raw(b"[mnt] FFAULT-LOCK root="); klog::write_hex_u64(self.root_pa);
                    klog::write_raw(b" va=");  klog::write_hex_u64(va_page);
                    klog::write_raw(b" pa=");  klog::write_hex_u64(pa);
                    klog::write_raw(b"\n");
                }
                let pte_flags = vma.prot.to_page_flags();
                // Linux `finish_fault` pte_same/!pte_none re-check (mm/memory.c):
                // `backing.read_at` above SLEEPS on the block device (ext4 ->
                // virtio-blk park_blk -> schedule()), so a PEER THREAD of this
                // same mm (CLONE_VM) can fault the SAME va while we sleep,
                // ALSO fill a frame, and install FIRST. Linux re-takes the pte
                // lock after the sleeping ->fault and, if a racer already
                // populated the slot, FREES its own page and does NOT install.
                // Oxide has no ptl; the minimal correct equivalent is: if the
                // slot is now present, back off — the racer's frame (identical
                // file content) stands, and clobbering it would (a) revert the
                // racer's retired user store and (b) free the racer's live
                // frame (the libcap `.bss` lock-byte lost-write / frame-reuse
                // bug). Only install into a still-empty slot.
                // SAFETY: privileged PT read of the running task's active root.
                if unsafe { M::translate(Va(va_page)) }.is_some() {
                    // A racer won while we slept in read_at — free our unused
                    // fill frame and adopt the racer's install (retry the
                    // faulting instruction, which will now hit the present PTE).
                    dec_ref(pa);
                    return Ok(());
                }
                // SAFETY: va_page page-aligned per find_containing; pa is fresh PMM frame; flags carry USER per `11§5`.
                // F157-A1: dec_ref any frame displaced by a stale present leaf.
                let replaced = unsafe { M::map(Va(va_page), Pa(pa), pte_flags, PageSize::P4K) };
                if replaced.is_none() { self.accounting.install_pte(&vma); }
                if let Some(old) = replaced {
                    // LOST-WRITE (kbytes/file arm, ALL ranges incl brk + ld.so
                    // .bss): a demand fault installed over a PRESENT leaf → the
                    // displaced page's live content was dropped. va identifies
                    // the range (0x1000_0000 exe/brk, 0x4003_xxxx ld.so .bss).
                    #[cfg(feature = "debug-watchdog")]
                    { klog::write_raw(b"[LOSTWRITE] demand-install displaced present va=");
                      klog::write_hex_u64(va_page); klog::write_raw(b" old_pa=");
                      klog::write_hex_u64(old.0 & !(PAGE_SIZE_BYTES - 1)); klog::write_raw(b"\n"); }
                    // GAP-1 (displaced-frame UAF): this fault displaced a
                    // present leaf; dec_ref below may free `old`. A peer CPU
                    // of the same mm with a stale TLB entry for va_page->old
                    // could touch a freed+realloc'd frame. Flush peers (this
                    // mm's cpumask only) BEFORE dropping our reference. No-op
                    // on UP / aarch64 / hosted.
                    hal::tlb::shootdown_others_va(va_page, self.cpumask());
                    dec_ref(old.0 & !(PAGE_SIZE_BYTES - 1));
                }
                Ok(())
            }
            VmaBacking::KernelFrame { pa } => {
                // SAFETY: same live-MMU and callback contracts as this fault fill path.
                unsafe { self.map_kernel_frame::<M, _, _>(va, &vma, *pa, dec_ref, inc_ref) }
            }
            VmaBacking::PhysRange { base_pa } => {
                // SAFETY: same live-MMU and callback contracts as this fault fill path.
                unsafe { self.map_phys_range::<M, _>(va, &vma, *base_pa, dec_ref) }
            }
            VmaBacking::Special => Err(Error::NotImplemented),
        }
    }
}
