use hal::{MmuOps, Pa, PageSize, UserVirtAddr, Va, PAGE_SIZE_BYTES};

use crate::vma::{VmaBacking, VmaFlags, VmaProt};
use crate::{Error, KResult};

use super::super::AddressSpace;

impl AddressSpace {
    /// Resolve writable protection faults: Linux-style anonymous COW,
    /// shmem write-enable, and stale-leaf retry handling.
    /// # SAFETY: caller supplies the live MMU implementation and valid PMM/rmap callbacks.
    /// # C: O(log N_vmas) + O(page) on COW-copy.
    pub(super) unsafe fn handle_write_protection<M, A, RC, DR, SR, XR, CA, UA>(
        &self,
        va: UserVirtAddr,
        hhdm_offset: u64,
        alloc_frame: &mut A,
        frame_refcount: &mut RC,
        dec_ref: &mut DR,
        set_rmap: &mut SR,
        reuse_ok: &mut XR,
        charge_anon: &mut CA,
        uncharge_anon: &mut UA,
    ) -> KResult<()>
    where
        M:  MmuOps,
        A:  FnMut() -> Option<u64>,
        RC: FnMut(u64) -> u32,
        DR: FnMut(u64),
        SR: FnMut(u64, &alloc::sync::Arc<crate::AnonVma>, u32),
        XR: FnMut(u64) -> bool,
        CA: FnMut() -> KResult<()>,
        UA: FnMut(),
    {
            let vma = match self.vmas.read().find_containing(va) {
                Some(v) => v.clone(),
                None    => return Err(Error::Inval),
            };
            if !vma.prot.contains(VmaProt::WRITE) {
                return Err(Error::Inval);
            }
            let va_page = va.as_u64() & !(PAGE_SIZE_BYTES - 1);
            // SAFETY: va_page is in user-half; M::translate reads the active PT for the running task's CR3 / TTBR0; vma is the live snapshot for `va`.
            let cur = unsafe { M::translate(Va(va_page)) };
            // DIAG (debug-mount): trace COW write to the libc lock page. If a
            // fork-shared lock page takes the fast path (refcount<=1 → flip W
            // in place) while a peer still maps it, the write corrupts the
            // peer's lock → the wedge. Logs the refcount + fast/slow decision.
            #[cfg(feature = "debug-mount")]
            {
                if let VmaBacking::File { backing, off } = &vma.backing {
                    let foff = off.wrapping_add(va_page - vma.start.as_u64());
                    if foff == 0x1e7000 && backing.ino() == 0x6e54000000062076 {
                        let srcpa = cur.map(|(p, _)| p.0 & !(PAGE_SIZE_BYTES - 1)).unwrap_or(0);
                        let rc = if srcpa != 0 { frame_refcount(srcpa) } else { 0 };
                        // Read the actual stuck lock word (glibc .bss `lock`,
                        // page offset 0xb68 — uaddr 0x..db68) from the old COW
                        // frame. Non-zero ⇒ the page holds stale FILE bytes
                        // (ld.so's .bss memset was reverted) → glibc sees the
                        // lock held → futex_wait forever, no waker.
                        let lockw = if srcpa != 0 {
                            // SAFETY: srcpa names the old mapped frame; 0xb68 is within the page.
                            unsafe { core::ptr::read_volatile((hhdm_offset + srcpa + 0xb68) as *const u32) }
                        } else { 0 };
                        klog::write_raw(b"[mnt] COW-LOCK va="); klog::write_hex_u64(va_page);
                        klog::write_raw(b" srcpa=");             klog::write_hex_u64(srcpa);
                        klog::write_raw(b" rc=");                klog::write_dec_u64(rc as u64);
                        klog::write_raw(b" lockw=");             klog::write_hex_u64(lockw as u64);
                        klog::write_raw(if rc <= 1 { b" FAST\n" } else { b" slow\n" });
                    }
                }
            }
            // COW fast path: reuse the frame in place (flip W, no copy) ONLY
            // for an exclusively-owned ANONYMOUS page — Linux `wp_page_reuse`
            // requires `PageAnonExclusive`. A private File/KernelBytes page is
            // NEVER reused in place: it must COW-copy, because the frame can be
            // aliased through the page cache or a fork peer in ways the bare
            // struct-page refcount doesn't capture. Reusing a file page in
            // place let one process's loader-scratch write land in a fork
            // peer's still-shared libc page (the .bss lock → glibc deadlock).
            // A3 (re-enabled, Linux `wp_page_reuse`): reuse the frame in
            // place — flip W, no alloc/copy/refcount-change — iff `reuse_ok`
            // proves the page is exclusively owned. The kernel adapter
            // computes that from `PageMeta` as `is_anon && PageAnonExclusive
            // && mapcount==1`, the reliable replacement for the old
            // `frame_refcount<=1` proxy that under-counted and corrupted a
            // fork peer (random glibc-.data byte flips / "Failed to spawn
            // executor" storm / futex wedge). The exclusive bit is CLEARED on
            // every fork-share (`pmm::setup::inc_ref`), so a still-shared frame
            // never satisfies `reuse_ok` and always COW-copies below. Gated on
            // an Anonymous backing: File/KernelBytes private pages can alias
            // the page cache / fork peers in ways struct-page state misses, so
            // they must always copy.
            if matches!(vma.backing, VmaBacking::Anonymous) {
                if let Some((src_pa, _)) = cur {
                    let cur_pa = src_pa.0 & !(PAGE_SIZE_BYTES - 1);
                    if reuse_ok(cur_pa) {
                        let pte_flags = vma.prot.to_page_flags();
                        // SAFETY: va_page page-aligned per find_containing; cur_pa is the
                        // sole-owned anon frame already mapped here (mapcount==1, exclusive);
                        // flags carry USER+WRITE since vma.prot.WRITE checked above. No
                        // refcount/mapcount change: the same frame keeps its single mapping.
                        unsafe {
                            M::map(Va(va_page), Pa(cur_pa), pte_flags, PageSize::P4K);
                            M::flush_va(Va(va_page));
                        }
                        // debug-cow: the frame is now writable + exclusively
                        // owned (Linux wp_page_reuse) — it will legitimately be
                        // mutated, so drop any RO-shared snapshot to avoid a
                        // false [COW-CORRUPT] at free. No-op when feature off.
                        crate::debug_cow::forget(cur_pa);
                        return Ok(());
                    }
                }
            }
            // MAP_SHARED of a page-frame-backed file (memfd/tmpfs): a write
            // fault must make the SHARED frame itself writable in place (Linux
            // shmem dirty path) — never COW-copy, or this write diverges from
            // the file + every peer mapper (lost-write corruption). The page is
            // RO here only because a prior fork W-stripped it (or mprotect did);
            // re-install the SAME inode frame writable. No alloc, no copy, no
            // refcount change (we keep our existing reference to `cur`).
            if vma.flags.contains(VmaFlags::SHARED) && !cfg!(feature = "debug-no-shmem") {
                if let (VmaBacking::File { backing, off }, Some((src_pa, _))) = (&vma.backing, cur) {
                    let cur_pa = src_pa.0 & !(PAGE_SIZE_BYTES - 1);
                    let foff = off.wrapping_add(va_page - vma.start.as_u64());
                    let shared = match backing.shared_frame(foff) {
                        Ok(shared) => shared,
                        Err(crate::vma::FileBackingError::NoMem) => return Err(Error::NoMem),
                        Err(_) => return Err(Error::Io),
                    };
                    let matches_current = shared.map(|frame| frame.pa) == Some(cur_pa);
                    if let Some(frame) = shared.filter(|frame| frame.map_ref_held) {
                        // This is a lookup while retaining the existing PTE, not a
                        // mapping install. Return the transient page-cache hold.
                        dec_ref(frame.pa);
                    }
                    if matches_current {
                        let pte_flags = vma.prot.to_page_flags();
                        // SAFETY: va_page page-aligned per find_containing; cur_pa is the
                        // inode-owned shared frame already mapped here (refcount held);
                        // flags carry USER+WRITE since vma.prot.WRITE checked above.
                        unsafe {
                            M::map(Va(va_page), Pa(cur_pa), pte_flags, PageSize::P4K);
                            M::flush_va(Va(va_page));
                        }
                        return Ok(());
                    }
                }
            }
            // debug-cow: we are about to COW-copy this anon frame, i.e. we
            // treat it as still RO-shared (reuse_ok was false). If the
            // struct-page refcount says it is exclusively owned (rc<=1) the
            // accounting under-counted a live PTE — the residual-bug signature
            // (a peer still maps a frame we believe nobody else holds). Cheap
            // O(1) read; no walk. Anonymous-only: File/KernelBytes private
            // pages legitimately copy while rc==1.
            #[cfg(feature = "debug-cow")]
            if matches!(vma.backing, VmaBacking::Anonymous) {
                if let Some((src_pa, _)) = cur {
                    let cur_pa = src_pa.0 & !(PAGE_SIZE_BYTES - 1);
                    let rc = frame_refcount(cur_pa);
                    if rc <= 1 {
                        klog::write_raw(b"[COW-RC] under-count frame="); klog::write_hex_u64(cur_pa);
                        klog::write_raw(b" va="); klog::write_hex_u64(va_page);
                        klog::write_raw(b" rc="); klog::write_dec_u64(rc as u64);
                        klog::write_raw(b"\n");
                    }
                }
            }
            // A write-protection fault with NO present leaf is not a real CoW —
            // there is nothing to copy. Post-normalization (line ~997) it means
            // the leaf was zapped by a peer CPU of the SAME mm between the
            // normalization `translate` and the re-read `cur` above — an SMP
            // TOCTOU the single-`translate` normalization can't see. The old
            // code fell through and alloc+ZERO-filled a fresh frame, installing
            // zeros over File / KernelBytes content (the EOF-straddling
            // .data/.dynamic tail of a freshly-mapped shared library) → ld.so
            // silently skipped DT_NEEDED deps and tripped dl-version.c's
            // `needed != NULL` assert. Mirror the read/exec Protection arm
            // below: flush and let the refault take the NotPresent path, which
            // reads the correct backing bytes. NEVER zero over backing content.
            let (src_pa, _) = match cur {
                Some(c) => c,
                None => {
                    let va_page = va.as_u64() & !(PAGE_SIZE_BYTES - 1);
                    // SAFETY: privileged TLB invalidation legal at CPL=0/EL1;
                    // drops any stale entry so the refault re-reads the backing.
                    unsafe { M::flush_va(Va(va_page)); }
                    return Ok(());
                }
            };
            // Shared frame (refcount > 1): alloc fresh + copy the current bytes
            // + install writable + dec_ref the shared source below.
            let anon_vma = if matches!(vma.backing, VmaBacking::Anonymous) {
                Some(vma.anon_vma.as_ref().ok_or(Error::Inval)?)
            } else {
                None
            };
            charge_anon()?;
            let new_pa = match alloc_frame() {
                Some(pa) => pa,
                None => {
                    uncharge_anon();
                    return Err(Error::NoMem);
                }
            };
            // SAFETY: dst is the freshly-allocated PMM frame's HHDM mirror; src is the previously-mapped frame's HHDM mirror; 4 KiB non-overlapping copy.
            unsafe {
                let dst = (hhdm_offset + new_pa) as *mut u8;
                let src = (hhdm_offset + (src_pa.0 & !(PAGE_SIZE_BYTES - 1))) as *const u8;
                core::ptr::copy_nonoverlapping(src, dst, PAGE_SIZE_BYTES as usize);
            }
            let pte_flags = vma.prot.to_page_flags();
            #[cfg(feature = "debug-atexit")]
            if let VmaBacking::File { backing, off } = &vma.backing {
                let foff = off.wrapping_add(va_page - vma.start.as_u64());
                crate::tailwatch::log_install(b"cowcopy", backing.ino(), foff, va_page, new_pa, 0);
            }
            // SAFETY: va_page page-aligned in user-half; new_pa fresh PMM frame; flags carry USER + WRITE since vma.prot.WRITE checked above.
            let displaced = unsafe {
                let d = M::map(Va(va_page), Pa(new_pa), pte_flags, PageSize::P4K);
                M::flush_va(Va(va_page));
                d
            };
            // F156-rmap: bind new private page to the VMA's anon_vma
            // family with the page-offset index per Linux
            // `page_add_anon_rmap`. Caller's `set_rmap` is the kernel
            // adapter that bumps the Arc and stashes it in PageMeta.
            if let Some(av) = anon_vma {
                let idx = ((va_page - vma.start.as_u64()) / PAGE_SIZE_BYTES) as u32;
                set_rmap(new_pa, av, idx);
            }
            // SMP TLB coherence (`20§5`): this COW split rewrote the shared
            // page-table entry `va_page -> new_pa` (writable). Peer threads of
            // the SAME mm on other CPUs still cache `va_page -> old` (the
            // shared frame) and must invalidate it BEFORE we drop our
            // reference below — otherwise `old` can be freed + realloc'd while
            // a peer still reads/writes it through the stale entry. Local
            // flush already happened in `M::map`; broadcast to the others.
            // No-op on UP / aarch64 / hosted. Target only the CPUs that
            // have this mm loaded (self.cpumask), per flush_tlb_others.
            hal::tlb::shootdown_others_va(va_page, self.cpumask());
            // F157-A1: drop our reference to the displaced (formerly
            // W-stripped shared) frame. `M::map` above tore the old leaf down
            // and returned its PA; `dec_ref` chains into
            // pmm::setup::dec_and_maybe_free, freeing the frame iff no peer AS
            // still maps it. This REPLACES the previous manual `dec_ref(cur)`:
            // the displaced return is the authoritative torn-down PA (== `cur`
            // on UP), so accounting it here — and ONLY here — keeps refcount ==
            // live-PTE count. (Keeping both would double-dec → free-while-
            // mapped, the inverse RANK-1 corruption.)
            if let Some(old) = displaced {
                dec_ref(old.0 & !(PAGE_SIZE_BYTES - 1));
            }
            return Ok(());
    }
}
