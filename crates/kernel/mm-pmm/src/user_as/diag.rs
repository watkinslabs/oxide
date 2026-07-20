use super::*;
use super::fault::do_handle;

const PAGE_MASK: u64 = hal::PAGE_SIZE_BYTES - 1;
const PAGE_BYTES: u64 = hal::PAGE_SIZE_BYTES;

#[cfg(target_arch = "x86_64")]
pub fn prefault_stack(as_: &AddressSpace, top: u64, len: u64) {
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    let mut va = top.saturating_sub(len) & !PAGE_MASK;
    while va < top {
        if let Some(uva) = UserVirtAddr::new(va) {
            let _ = do_handle(as_, uva, FaultKind::NotPresent { access: FaultAccess::Write }, hhdm);
        }
        va += PAGE_BYTES;
    }
}

/// DIAG (worktree-only, do not merge): on an exit(127), while the dying
/// task's page tables are still live, compare every PRESENT page of every
/// NON-WRITABLE file-backed VMA against the backing store. The page cache is
/// proven clean ([FILLRACE]/[FRAME-CORRUPT] both zero), so any mismatch here
/// pins the corruption to the private fault frame / PTE / TLB layer and names
/// the exact ino/off/va. Writable VMAs are skipped (legit relocation writes);
/// post-RELRO pages may false-positive — exec-only diffs are definitive.
/// # C: O(mapped pages × page I/O)
#[cfg(target_arch = "x86_64")]
pub fn diag_verify_file_pages() {
    use hal::{MmuOps, Va};
    let Some(cur) = sched::live::current() else { return };
    // SAFETY: running task on this CPU; single-mutator mm slot per 13§5.
    let Some(mm) = (unsafe { cur.mm_ref() }) else { return };
    let hhdm = hhdm_offset();
    // Dump the dying process's VMA table once — overlap/aliasing shows here.
    for v in mm.snapshot_vmas() {
        if let VmaBacking::File { ref backing, off } = v.backing {
            klog::write_raw(b"[VMA] ");
            klog::write_hex_u64(v.start.as_u64());
            klog::write_raw(b"-");
            klog::write_hex_u64(v.end.as_u64());
            klog::write_raw(b" ino=");
            klog::write_hex_u64(backing.ino());
            klog::write_raw(b" off=");
            klog::write_hex_u64(off);
            klog::write_raw(b" prot=");
            klog::write_dec_u64(v.prot.bits() as u64);
            klog::write_raw(b"\n");
        }
    }
    let mut reported = 0u32;
    for vma in mm.snapshot_vmas() {
        if reported >= 8 { break; }
        // Writable VMAs (RW .data/.dynamic/GOT) legitimately diverge from the
        // file via relocations — those write POINTERS. They never zero a run
        // that had file content, so for writable pages report only [MAPZERO]:
        // a 32-byte aligned all-zero run where the backing is non-zero = a
        // lost dirty page / zero-refault (the DT_NEEDED-skip corruption).
        let writable = vma.prot.contains(VmaProt::WRITE);
        let VmaBacking::File { ref backing, off } = vma.backing else { continue };
        let mut va = vma.start.as_u64();
        while va < vma.end.as_u64() && reported < 8 {
            // SAFETY: privileged PT read of the current (dying) task's live root.
            let translated = unsafe { <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::translate(Va(va)) };
            // Raw x86 leaf (D bit6 = written-through-since-install, A bit5 =
            // accessed, W bit1). The DECISIVE discriminator: D=0 => the frame's
            // zero content arrived WITH the frame at install (some path zeroed
            // it before mapping); D=1 => a store retired through THIS mapping
            // after install (a user memset / kernel copy-to-user of zeros).
            let raw_leaf = unsafe {
                hal::pt_walker::translate_4k_at_root::<hal_x86_64::vmm::PtWalkerX86>(
                    mm.root_pa(), va, hhdm)
            }.map(|(_, leaf)| leaf).unwrap_or(0);
            if let Some((pa, fl)) = translated {
                let foff = off + (va - vma.start.as_u64());
                let fsize = backing.size_hint();
                let valid = if foff >= fsize { 0usize }
                            else { core::cmp::min(PAGE_BYTES, fsize - foff) as usize };
                if valid > 0 {
                    let mut want = alloc::vec![0u8; valid];
                    let mut filled = 0usize;
                    while filled < valid {
                        match backing.read_at(foff + filled as u64, &mut want[filled..valid]) {
                            Ok(0) => break,
                            Ok(n) => filled += n,
                            Err(_) => { filled = 0; break }
                        }
                    }
                    if filled == valid {
                        let got = (hhdm + (pa.0 & !PAGE_MASK)) as *const u8;
                        let mut first_diff: Option<usize> = None;
                        if writable {
                            // [MAPZERO] scan: aligned 32-byte run zero in memory,
                            // non-zero in the file.
                            let mut i = 0usize;
                            while i + 32 <= valid {
                                // SAFETY: HHDM mirror of a live user frame; read-only.
                                let gz = (0..4).all(|k| unsafe {
                                    core::ptr::read_volatile((got.add(i) as *const u64).add(k)) } == 0);
                                if gz {
                                    let wz = want[i..i + 32].iter().all(|&b| b == 0);
                                    if !wz { first_diff = Some(i); break }
                                }
                                i += 32;
                            }
                        } else {
                            for i in 0..valid {
                                // SAFETY: HHDM mirror of a live user frame; read-only.
                                let b = unsafe { core::ptr::read_volatile(got.add(i)) };
                                if b != want[i] { first_diff = Some(i); break }
                            }
                        }
                        if let Some(d) = first_diff {
                            if writable { klog::write_raw(b"[MAPZERO]"); }
                            // Frame provenance: the ANON PageMeta flag means the
                            // frame was installed by the ANONYMOUS fault arm
                            // (demand-zero) — proof a File page faulted through
                            // the wrong backing.
                            if let Some(meta) = crate::setup::page_meta() {
                                if let Some(f) = meta.flags(hal::Pfn((pa.0 & !PAGE_MASK) / PAGE_BYTES)) {
                                    klog::write_raw(b"[pmflags=");
                                    klog::write_hex_u64(f.bits() as u64);
                                    klog::write_raw(b"]");
                                }
                            }
                            klog::write_raw(b"[pte=");
                            klog::write_hex_u64(fl.bits() as u64);
                            klog::write_raw(b" raw=");
                            klog::write_hex_u64(raw_leaf);
                            klog::write_raw(if raw_leaf & (1 << 6) != 0 { b" D=1" } else { b" D=0" });
                            klog::write_raw(if raw_leaf & (1 << 5) != 0 { b" A=1" } else { b" A=0" });
                            klog::write_raw(b"]");
                            klog::write_raw(b"[MAPDIFF] ino=");
                            klog::write_hex_u64(backing.ino());
                            klog::write_raw(b" foff=");
                            klog::write_hex_u64(foff);
                            klog::write_raw(b" va=");
                            klog::write_hex_u64(va);
                            klog::write_raw(b" pa=");
            klog::write_hex_u64(pa.0 & !PAGE_MASK);
                            klog::write_raw(b" at=");
                            klog::write_hex_u64(d as u64);
                            klog::write_raw(b" want=");
                            for i in d..core::cmp::min(d + 8, valid) {
                                klog::write_hex_u64(want[i] as u64); klog::write_raw(b",");
                            }
                            klog::write_raw(b" got=");
                            for i in d..core::cmp::min(d + 8, valid) {
                                // SAFETY: same HHDM mirror as the compare loop above.
                                let b = unsafe { core::ptr::read_volatile(got.add(i)) };
                                klog::write_hex_u64(b as u64); klog::write_raw(b",");
                            }
                            klog::write_raw(b"\n");
                            reported += 1;
                        }
                    }
                }
            }
            va += PAGE_BYTES;
        }
    }
    if reported == 0 {
        klog::write_raw(b"[MAPDIFF] exit127: all non-writable file pages MATCH backing\n");
    }
}
