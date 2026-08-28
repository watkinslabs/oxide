use alloc::sync::Arc;

use hal::{MmuOps, Pa, PageSize, UserVirtAddr, Va, PAGE_SIZE_BYTES};

use crate::vma::{FaultAccess, FileBacking, FileBackingError, Vma, VmaFlags};
#[cfg(any(feature = "debug-atexit", feature = "debug-cow"))]
use crate::vma::VmaProt;
use crate::{Error, KResult};

use super::super::AddressSpace;

impl AddressSpace {
    /// Fill a file-backed VMA page, including page-cache/direct-frame lookup,
    /// private-copy retry semantics, EOF handling, and fault-around publication.
    /// # SAFETY: caller supplies the live MMU and PMM/rmap callbacks.
    /// # C: O(page) + backing I/O
    pub(super) unsafe fn handle_file_not_present<M, A, DR, IR, MR>(
        &self,
        va: UserVirtAddr,
        access: FaultAccess,
        hhdm_offset: u64,
        wp: hal::PageFlags,
        around_ok: bool,
        vma: &Vma,
        backing: &Arc<dyn FileBacking>,
        backing_off: u64,
        alloc_frame: &mut A,
        dec_ref: &mut DR,
        inc_ref: &mut IR,
        mark_referenced: &mut MR,
    ) -> KResult<()>
    where
        M: MmuOps,
        A: FnMut() -> Option<u64>,
        DR: FnMut(u64),
        IR: FnMut(u64),
        MR: FnMut(u64),
    {
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
                // A backing whose pages ARE huge pages resolves through a single
                // block leaf. The base-page fill below would install a 4 KiB
                // leaf over a huge page and leave its other base pages to fault
                // one at a time — exactly the translation cost hugetlbfs exists
                // to avoid, and a leaf the teardown walk would then have to
                // reconcile against the huge page behind it.
                let huge_bytes = backing.huge_page_size();
                if huge_bytes != 0 {
                    // SAFETY: forwards the live MMU and the PMM refcount callback unchanged; no page-table lock is held here.
                    return unsafe { self.fill_huge_not_present::<M, _, _>(
                        va, access, &vma, backing, backing_off, huge_bytes, wp, dec_ref, inc_ref,
                    ) };
                }
                // Device mappings install their owner frame for both mapping
                // types. Page-cache frames do so only for MAP_SHARED; private
                // file mappings retain the read-copy COW path below.
                let direct = if let Some(pa) = backing.direct_frame(file_off) {
                    Some((pa, false))
                } else if vma.flags.contains(VmaFlags::SHARED) && !cfg!(feature = "debug-no-shmem") {
                    // A WRITE fault on a shared mapping tells the object so
                    // before the frame is asked for, because for a file on a
                    // medium that call is what reserves the block the frame will
                    // hold — so a hole becomes storage, ENOSPC and quota are
                    // decided while the fault can still report them, and the
                    // page is dirtied by the one event the filesystem sees for a
                    // mapped write. A read fault reserves nothing.
                    if matches!(access, FaultAccess::Write) {
                        match backing.page_mkwrite(file_off) {
                            Ok(()) => {}
                            Err(FileBackingError::NoMem) => return Err(Error::NoMem),
                            Err(FileBackingError::Again) => return Err(Error::Again),
                            Err(_) => return Err(Error::Io),
                        }
                    }
                    match backing.shared_frame(file_off) {
                        Ok(frame) => frame.map(|frame| (frame.pa, frame.map_ref_held)),
                        Err(FileBackingError::NoMem) => return Err(Error::NoMem),
                        Err(FileBackingError::Again) => return Err(Error::Again),
                        Err(_) => return Err(Error::Io),
                    }
                } else { None };
                if let Some((spa, map_ref_held)) = direct {
                    #[cfg(feature = "debug-faultdiag")]
                    {
                        klog::write_raw(b"[file frame map] va="); klog::write_hex_u64(va_page);
                        klog::write_raw(b" root="); klog::write_hex_u64(self.root_pa());
                        klog::write_raw(b" pa="); klog::write_hex_u64(spa);
                        klog::write_raw(b" ino="); klog::write_hex_u64(backing.ino());
                        klog::write_raw(b"\n");
                    }
                    if !map_ref_held { inc_ref(spa); }
                    // Linux `filemap_fault`: a resident page brought into
                    // this mapping is marked accessed, biasing it away from
                    // reclaim — UNLESS this file/VMA combination has no
                    // recency (`POSIX_FADV_NOREUSE`, `MADV_SEQUENTIAL`,
                    // `MADV_RANDOM`), in which case the page is left exactly
                    // where reclaim last put it.
                    if crate::recency::vma_has_recency(vma.flags, backing.noreuse()) {
                        mark_referenced(spa);
                    }
                    let pte_flags = vma.page_flags() | wp;
                    // SAFETY: `va_page` is page-aligned and `spa` is a resident page-cache frame
                    // this fault holds a reference on — either already held by the backing lookup
                    // or taken by the `inc_ref` above — so it stays live until the install wins.
                    let installed = unsafe {
                        self.map_if_absent::<M>(Va(va_page), Pa(spa), pte_flags, PageSize::P4K)
                    };
                    if !installed {
                        dec_ref(spa);
                        return Ok(());
                    }
                    self.accounting.install_pte(&vma);
                    if around_ok && !matches!(access, FaultAccess::Write) {
                        // SAFETY: the demand leaf is committed and the same
                        // live MMU/PMM callbacks govern adjacent PTE installs.
                        unsafe { self.map_file_fault_around::<M, _, _>(
                            &vma, va_page, backing, backing_off, dec_ref, inc_ref,
                        ); }
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
                // The reference has NO notion of a short read here: a page is
                // either uptodate or it is not, and when it is not it re-reads
                // it ONCE, synchronously, then goes back around the lookup.
                // Only a read that actually ERRORS becomes a fault; a read that
                // merely failed to produce everything is retried. Giving up on
                // the first no-progress return was the leg this path was
                // missing, and it is why a page-cache build race or an extent
                // boundary that the next read would have satisfied killed the
                // faulting process instead of resolving.
                //
                // Each attempt re-derives the valid extent, because the size can
                // move while a fault is in flight — a writer rewriting a file a
                // reader has already mapped is the ordinary case, not a rare
                // one, and judged against the size the fault STARTED with the
                // backing's correct "no more bytes" at the new end reads as an
                // unrecoverable short.
                const FILL_ATTEMPTS: u32 = 2;
                let valid0 = valid;
                let mut read_err = false;
                let mut no_mem = false;
                let mut transient = false;
                let mut filled = 0usize;
                for attempt in 0..FILL_ATTEMPTS {
                    if attempt > 0 {
                        let fsize_now = backing.size_hint();
                        valid = if file_off >= fsize_now { 0usize }
                                else { core::cmp::min(page as u64, fsize_now - file_off) as usize };
                    }
                    // SAFETY: pa is a freshly-allocated PMM frame; HHDM mirror at hhdm_offset+pa is mapped writable; full page owned exclusively until M::map below makes it user-visible.
                    let r = unsafe {
                        let dst = (hhdm_offset + pa) as *mut u8;
                        hal::zerotrap::trap((dst) as *const u8, (page) as usize);
                        core::ptr::write_bytes(dst, 0, page);
                        let slice = core::slice::from_raw_parts_mut(dst, page);
                        let mut filled = 0usize;
                        let mut err = false;
                        let mut no_mem = false;
                        while filled < valid {
                            match backing.read_at(file_off + filled as u64, &mut slice[filled..valid]) {
                                Ok(0)   => break,                 // no progress → retry or EOF
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
                                // Transient: stop this pass WITHOUT marking the
                                // read failed, so the attempt loop takes another
                                // run at it. A store being evicted under a
                                // concurrent fault answers this, and killing the
                                // faulting process for losing that race is not
                                // what the reference does. Still bounded — a
                                // transient that outlives FILL_ATTEMPTS falls
                                // through to the same short-fill verdict.
                                Err(FileBackingError::Again) => { transient = true; break; }
                                Err(_) => { err = true; break; }
                            }
                        }
                        (err, no_mem, filled)
                    };
                    read_err = r.0; no_mem = r.1; filled = r.2;
                    // An error is terminal on the spot — that is the one leg the
                    // reference answers with a fault. Anything else that filled
                    // the extent is done; anything else that did not gets the
                    // single re-read.
                    if read_err || filled >= valid { break; }
                }
                if transient && !read_err && filled < valid {
                    // Linux's filemap_fault retries a page whose cache
                    // operation was interrupted by a concurrent invalidate;
                    // it does not turn that transient into VM_FAULT_SIGBUS.
                    dec_ref(pa);
                    return Err(Error::Again);
                }
                // A desync-recovered fill legitimately stops at the BACKING's own
                // EOF mid-page (the zeroed tail is real bss).
                let mut fatal = read_err || (filled < valid && !desync);
                // The page held file bytes when the fault began and now lies
                // WHOLLY past the end: the object was truncated under the fault.
                // The reference re-checks the size after the read and answers a
                // fault there, not a zero page. A page that was past the end all
                // along is the ordinary bss tail and still zero-fills.
                if !read_err && !desync && valid0 > 0 && valid == 0 { fatal = true; }
                if fatal {
                    // Unrecoverable: the backing could not supply the full
                    // file-valid extent. Do NOT install a partially-zero page
                    // (silent corruption). Free the fresh frame and fail the
                    // fault → SIGBUS-equivalent at the dispatcher (false→fatal).
                    // Always on: this is a page the process is about to die
                    // for, and the four values here are the whole diagnosis —
                    // whether the fault was at EOF, how much the backing
                    // supplied, and which size each side believed. Gated, the
                    // log said only "bus error" and the cause took a night to
                    // find.
                    {
                        klog::write_raw(b"[SHORT-FILE-FAULT-FATAL ino="); klog::write_hex_u64(backing.ino());
                        klog::write_raw(b" off="); klog::write_hex_u64(file_off);
                        klog::write_raw(b" valid="); klog::write_hex_u64(valid as u64);
                        klog::write_raw(b" size="); klog::write_hex_u64(fsize);
                        // The two values that separate the remaining causes:
                        // how much the backing actually supplied, and whether it
                        // reported an error doing so. `filled == valid` with
                        // `err=0` cannot happen here; `filled < valid, err=0` is
                        // a clean short read (the backing stopped early of its
                        // own accord) and `err=1` is a failed one. Without them
                        // the log said a fill was fatal but not which arm ruled
                        // it so, and the two want opposite fixes.
                        klog::write_raw(b" filled="); klog::write_hex_u64(filled as u64);
                        klog::write_raw(b" err="); klog::write_dec_u64(read_err as u64);
                        klog::write_raw(b" desync="); klog::write_dec_u64(desync as u64);
                        klog::write_raw(b"]\n");
                    }
                    dec_ref(pa);
                    return Err(if no_mem { Error::NoMem } else { Error::Io });
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
                let pte_flags = vma.page_flags() | wp;
                // SAFETY: `va_page` is page-aligned and `pa` is the frame this arm just filled
                // from the backing file; the fault owns the only reference to it, and returns
                // that reference via `dec_ref` if a sibling fault won the slot instead.
                let installed = unsafe {
                    self.map_if_absent::<M>(Va(va_page), Pa(pa), pte_flags, PageSize::P4K)
                };
                if !installed {
                    dec_ref(pa);
                    return Ok(());
                }
                self.accounting.install_pte(&vma);
                if around_ok && !matches!(access, FaultAccess::Write) {
                    // SAFETY: the demand leaf is committed and the same live
                    // MMU/PMM callbacks govern adjacent PTE installs.
                    unsafe { self.map_file_fault_around::<M, _, _>(
                        &vma, va_page, backing, backing_off, dec_ref, inc_ref,
                    ); }
                }
                Ok(())
    }
}
