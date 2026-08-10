// `bzImage64_load`: where the four segments go, and what the purgatory is told
// about them.
//
// Ungated on purpose. Placement is the part of the file-load path that can
// silently produce an unbootable image, and the only evidence a boot leaves is
// whether the machine came back. Every input is passed in — the RAM map, the
// files, the purgatory bytes — so a hosted test can state the machine and
// assert the addresses.
//
// SEGMENT ORDER IS THE REFERENCE'S ORDER, and it is load-bearing twice over:
// placement is first-come, so a different order lands the segments at different
// addresses on a tight machine; and the digest is a hash of the segments in
// list order, so the order the purgatory recomputes must be the order the
// kernel predicted.
//
//   0 purgatory     top-down, floor 0x3000       — excluded from its own digest
//   1 boot_params   top-down, floor 0x3000, +cmdline
//   2 kernel        top-down, floor max(1 MiB, pref_address), kernel_alignment
//   3 initramfs     top-down, floor 16 MiB       — absent when there is none
//
// EVERYTHING IS PLACED TOP-DOWN. The reference sets `top_down` on both of its
// buffer templates and never clears it, which keeps low memory — where a legacy
// boot path and the real-mode trampolines live — free.

extern crate alloc;
use alloc::vec::Vec;

use super::bootparams::{self, Addrs};
use super::header::SetupHeader;
use super::uapi::*;
use crate::file_load::kbuf::{append_blob, locate_mem_hole, push_segment, KexecBuf};
use crate::file_load::purgatory;
use crate::file_load::Loaded;
use crate::uapi::{KexecSegment, PAGE_SIZE};
use crate::validate::{Error, KResult};

/// Index of the purgatory in the segment list — the one segment excluded from
/// the digest, because the digest is written into it afterwards.
pub const PURGATORY_SEG: usize = 0;

fn buf(bufsz: u64, memsz: u64, align: u64, min: u64) -> KexecBuf {
    let mut b = KexecBuf::new(bufsz, memsz);
    b.align = align;
    b.min = min;
    b.top_down = true;
    b
}

/// Lay out a `bzImage64` image over `ram`.
///
/// `purg` is the architecture's purgatory blob; it is placed first and patched
/// last, once every other segment's destination is known.
/// # C: O(kernel + initrd)
pub fn plan(
    kernel: &[u8], initrd: &[u8], cmdline: &[u8], ram: &[(u64, u64)], purg: &[u8],
) -> KResult<Loaded> {
    let h = SetupHeader::parse(kernel)?;
    let kern16 = h.kern16_size();
    if (kernel.len() as u64) < kern16 { return Err(Error::NoExec); }
    h.cmdline_fits(cmdline.len() + 1)?;
    if purg.len() != purgatory::BLOB_LEN { return Err(Error::Inval); }

    let mut segs: Vec<KexecSegment> = Vec::new();

    let pb = buf(purg.len() as u64, purg.len() as u64, PAGE_SIZE, MIN_PURGATORY_ADDR);
    let purg_at = locate_mem_hole(&pb, ram, &segs)?;
    push_segment(&mut segs, 0, &pb, purg_at);

    let bp_len = bootparams::buffer_len(cmdline.len() + 1) as u64;
    let bb = buf(bp_len, bp_len, BOOTPARAM_ALIGN, MIN_BOOTPARAM_ADDR);
    let bp_at = locate_mem_hole(&bb, ram, &segs)?;
    push_segment(&mut segs, 0, &bb, bp_at);

    let kb = buf(kernel.len() as u64 - kern16, h.init_size.div_ceil(PAGE_SIZE) * PAGE_SIZE,
                 h.kernel_alignment, h.kernel_min());
    let kern_at = locate_mem_hole(&kb, ram, &segs)?;
    push_segment(&mut segs, 0, &kb, kern_at);

    let mut initrd_at = 0u64;
    if !initrd.is_empty() {
        let ib = buf(initrd.len() as u64, initrd.len() as u64, PAGE_SIZE, MIN_INITRD_LOAD_ADDR);
        initrd_at = locate_mem_hole(&ib, ram, &segs)?;
        push_segment(&mut segs, 0, &ib, initrd_at);
    }

    let at = Addrs { bootparam: bp_at, initrd: initrd_at, initrd_len: initrd.len() as u64 };
    let params = bootparams::build(kernel, &h, cmdline, &at, ram)?;

    // The blob is accumulated in segment order, so a reader of either list sees
    // the same sequence; the `buf` fields are the offsets it hands back.
    let mut blob: Vec<u8> = Vec::new();
    segs[0].buf = append_blob(&mut blob, purg);
    segs[1].buf = append_blob(&mut blob, &params);
    segs[2].buf = append_blob(&mut blob, &kernel[kern16 as usize..]);
    if !initrd.is_empty() { segs[3].buf = append_blob(&mut blob, initrd); }

    // Everything the purgatory checks, written into the copy that will be
    // staged — never into the blob the running kernel was linked with.
    let (digest, regions) = purgatory::calculate(&segs, &blob, PURGATORY_SEG)?;
    let po = segs[PURGATORY_SEG].buf as usize;
    let copy = blob.get_mut(po..po + purgatory::BLOB_LEN).ok_or(Error::Inval)?;
    purgatory::patch_sha_regions(copy, &regions)?;
    purgatory::patch_digest(copy, &digest)?;
    purgatory::patch_entry_regs(copy, &purgatory::EntryRegs {
        // Bootstrap processor.
        rbx: 0,
        // The stack the purgatory carries for the kernel it starts.
        rsp: purg_at + purgatory::OFF_NEW_STACK_END as u64,
        // The 64-bit entry point's one argument.
        rsi: bp_at,
        // The kernel's 64-bit entry, 0x200 past its segment.
        rip: kern_at + ENTRY64_OFFSET,
    })?;

    Ok(Loaded {
        segments: segs,
        entry: purg_at + purgatory::OFF_CODE as u64,
        blob,
        boot_arg: bp_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use crate::file_load::purgatory::layout::{OFF_DIGEST, OFF_ENTRY_REGS, OFF_SHA_REGIONS,
        REG_RBX, REG_RIP, REG_RSI, REG_RSP, SHA_REGION_SIZE};

    const RAM: [(u64, u64); 2] = [(0x1000, 0x9f000), (0x100000, 0x2_0000_0000)];

    fn kernel_file(len: usize) -> Vec<u8> {
        let mut k = vec![0x33u8; len];
        k[HDR_SETUP_SECTS] = 4;
        k[HDR_JUMP_OFFSET] = 0x6a;
        k[HDR_BOOT_FLAG..HDR_BOOT_FLAG + 2].copy_from_slice(&BOOT_FLAG.to_le_bytes());
        k[HDR_MAGIC..HDR_MAGIC + 4].copy_from_slice(&MAGIC);
        k[HDR_VERSION..HDR_VERSION + 2].copy_from_slice(&0x020fu16.to_le_bytes());
        k[HDR_LOADFLAGS] = LOADED_HIGH;
        k[HDR_XLOADFLAGS..HDR_XLOADFLAGS + 2]
            .copy_from_slice(&(XLF_KERNEL_64 | XLF_CAN_BE_LOADED_ABOVE_4G).to_le_bytes());
        k[HDR_CMDLINE_SIZE..HDR_CMDLINE_SIZE + 4].copy_from_slice(&0x7ffu32.to_le_bytes());
        k[HDR_KERNEL_ALIGNMENT..HDR_KERNEL_ALIGNMENT + 4]
            .copy_from_slice(&0x200000u32.to_le_bytes());
        k[HDR_PREF_ADDRESS..HDR_PREF_ADDRESS + 8].copy_from_slice(&0x1000000u64.to_le_bytes());
        k[HDR_INIT_SIZE..HDR_INIT_SIZE + 4].copy_from_slice(&0x0400_0000u32.to_le_bytes());
        // The first bytes of the protected-mode half, so a segment that
        // carried the real-mode stub as well is visibly a different segment.
        if len > 5 * 512 + 8 {
            for (i, b) in k[5 * 512..5 * 512 + 8].iter_mut().enumerate() { *b = 0xC0 + i as u8; }
        }
        k
    }

    fn purg() -> Vec<u8> { vec![0u8; purgatory::BLOB_LEN] }

    fn planned() -> Loaded {
        plan(&kernel_file(0x40000), &vec![0x77u8; 0x8000], b"quiet", &RAM, &purg())
            .expect("a well formed image over ample RAM")
    }

    fn rd64(b: &[u8], o: usize) -> u64 { u64::from_le_bytes(b[o..o + 8].try_into().unwrap()) }

    #[test]
    fn the_four_segments_are_placed_in_the_reference_order() {
        let l = planned();
        assert_eq!(l.segments.len(), 4);
        assert_eq!(l.segments[PURGATORY_SEG].memsz, purgatory::BLOB_LEN as u64);
        assert_eq!(l.boot_arg, l.segments[1].mem);
        assert_eq!(l.entry, l.segments[0].mem + purgatory::OFF_CODE as u64);
    }

    #[test]
    fn no_two_destinations_overlap() {
        // The one failure staging cannot report: two segments whose ranges
        // intersect relocate over each other and the machine boots into rubble.
        let l = planned();
        for (i, a) in l.segments.iter().enumerate() {
            for b in &l.segments[..i] {
                assert!(a.mem + a.memsz <= b.mem || b.mem + b.memsz <= a.mem,
                        "{a:?} overlaps {b:?}");
            }
        }
    }

    #[test]
    fn every_segment_honours_its_floor_and_the_kernels_alignment() {
        let l = planned();
        assert!(l.segments[0].mem >= MIN_PURGATORY_ADDR);
        assert!(l.segments[1].mem >= MIN_BOOTPARAM_ADDR);
        assert!(l.segments[2].mem >= 0x1000000, "the kernel's own pref_address");
        assert_eq!(l.segments[2].mem % 0x200000, 0, "kernel_alignment");
        assert!(l.segments[3].mem >= MIN_INITRD_LOAD_ADDR);
    }

    #[test]
    fn placement_is_top_down_so_low_memory_stays_free() {
        // Bottom-up still produces a valid image on a large machine and fails
        // only on a small one, which is why the direction is asserted here
        // rather than left to be discovered by a boot.
        let l = planned();
        for s in &l.segments {
            assert!(s.mem > 0x1_0000_0000, "{s:?} landed in low memory");
        }
    }

    #[test]
    fn the_real_mode_stub_is_not_carried_and_the_entry_is_the_purgatorys() {
        // The kernel segment starts `(setup_sects + 1) * 512` into the file.
        // Carrying the stub shifts every byte and the 64-bit entry at +0x200
        // lands inside 16-bit code.
        let k = kernel_file(0x40000);
        let l = plan(&k, &[], b"", &RAM, &purg()).expect("wf");
        let seg = l.segments[2];
        assert_eq!(seg.bufsz, k.len() as u64 - 5 * 512);
        assert_eq!(&l.blob[seg.buf as usize..seg.buf as usize + 8], &k[5 * 512..5 * 512 + 8]);
        // `entry` is the purgatory, NOT the kernel: control reaches the kernel
        // only through the verification.
        assert_ne!(l.entry, seg.mem + ENTRY64_OFFSET);
        assert_eq!(l.entry, l.segments[0].mem + purgatory::OFF_CODE as u64);
    }

    #[test]
    fn the_kernel_reserves_init_size_rounded_up_not_its_file_length() {
        // `init_size` is what the kernel needs while it unpacks itself; a
        // segment sized to the file lets the next segment be placed inside the
        // region the kernel is about to write.
        let l = planned();
        assert_eq!(l.segments[2].memsz, 0x0400_0000);
        assert!(l.segments[2].memsz > l.segments[2].bufsz);
    }

    #[test]
    fn the_purgatory_is_told_the_kernel_entry_the_boot_page_and_its_own_stack() {
        let l = planned();
        let po = l.segments[PURGATORY_SEG].buf as usize;
        let regs = &l.blob[po + OFF_ENTRY_REGS..];
        assert_eq!(rd64(regs, REG_RBX * 8), 0, "bootstrap processor");
        assert_eq!(rd64(regs, REG_RSI * 8), l.segments[1].mem, "boot_params");
        assert_eq!(rd64(regs, REG_RIP * 8), l.segments[2].mem + ENTRY64_OFFSET);
        assert_eq!(rd64(regs, REG_RSP * 8),
                   l.segments[0].mem + purgatory::OFF_NEW_STACK_END as u64);
    }

    #[test]
    fn the_region_table_names_every_segment_but_the_purgatory() {
        let l = planned();
        let po = l.segments[PURGATORY_SEG].buf as usize;
        let tbl = &l.blob[po + OFF_SHA_REGIONS..];
        for (i, s) in l.segments.iter().skip(1).enumerate() {
            assert_eq!(rd64(tbl, i * SHA_REGION_SIZE), s.mem);
            assert_eq!(rd64(tbl, i * SHA_REGION_SIZE + 8), s.memsz);
        }
        // The purgatory's own destination appears nowhere in the table.
        for i in 0..purgatory::layout::SHA_REGIONS_MAX {
            assert_ne!(rd64(tbl, i * SHA_REGION_SIZE), l.segments[0].mem);
        }
    }

    #[test]
    fn the_digest_is_the_one_the_purgatory_will_recompute_at_the_destination() {
        // The whole point of the stage: hash the bytes staging will deliver,
        // in the order the purgatory reads them, with the memsz tail as zeros.
        let l = planned();
        let po = l.segments[PURGATORY_SEG].buf as usize;
        let mut h = crypt::Sha256::new();
        for s in l.segments.iter().skip(1) {
            let from = s.buf as usize;
            h.update(&l.blob[from..from + s.bufsz as usize]);
            h.update(&vec![0u8; (s.memsz - s.bufsz) as usize]);
        }
        assert_eq!(&l.blob[po + OFF_DIGEST..po + OFF_DIGEST + 32], &h.finish()[..]);
    }

    #[test]
    fn changing_one_byte_of_the_kernel_changes_the_digest() {
        // A digest that did not cover the kernel would still be a digest.
        let a = plan(&kernel_file(0x40000), &[], b"", &RAM, &purg()).expect("wf");
        let mut k = kernel_file(0x40000);
        k[0x30000] ^= 0xFF;
        let b = plan(&k, &[], b"", &RAM, &purg()).expect("wf");
        let ao = a.segments[PURGATORY_SEG].buf as usize + OFF_DIGEST;
        let bo = b.segments[PURGATORY_SEG].buf as usize + OFF_DIGEST;
        assert_ne!(&a.blob[ao..ao + 32], &b.blob[bo..bo + 32]);
    }

    #[test]
    fn an_image_with_no_initramfs_places_three_segments() {
        let l = plan(&kernel_file(0x20000), &[], b"", &RAM, &purg()).expect("wf");
        assert_eq!(l.segments.len(), 3);
    }

    #[test]
    fn a_machine_with_no_room_reports_eaddrnotavail_rather_than_a_bad_address() {
        let tiny = [(0x100000u64, 0x120000u64)];
        assert_eq!(plan(&kernel_file(0x40000), &[], b"", &tiny, &purg()).err(),
                   Some(Error::AddrNotAvail));
    }

    #[test]
    fn a_truncated_bzimage_is_enoexec_and_an_over_long_command_line_is_einval() {
        let short = kernel_file(0x800);
        assert_eq!(plan(&short, &[], b"", &RAM, &purg()).err(), Some(Error::NoExec));
        let long = vec![b'x'; 0x800];
        assert_eq!(plan(&kernel_file(0x40000), &[], &long, &RAM, &purg()).err(),
                   Some(Error::Inval));
    }

    #[test]
    fn a_purgatory_that_is_not_the_expected_blob_is_refused() {
        // The patch offsets are only meaningful for the blob they were written
        // for. A shorter one would be patched partly out of bounds; a LONGER
        // one would be patched successfully and staged with a tail nothing
        // accounts for, which is the case a bounds check alone would miss.
        assert_eq!(plan(&kernel_file(0x20000), &[], b"", &RAM, &vec![0u8; 0x1000]).err(),
                   Some(Error::Inval));
        assert_eq!(plan(&kernel_file(0x20000), &[], b"", &RAM,
                        &vec![0u8; purgatory::BLOB_LEN + 0x1000]).err(),
                   Some(Error::Inval));
    }

    #[test]
    fn a_real_fedora_bzimage_lays_out_over_a_stated_machine() {
        let dir = "/home/nd/oxide/images/build/lite-x86_64-root/boot";
        let mut real: Option<Vec<u8>> = None;
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries.flatten() {
                if e.file_name().to_string_lossy().starts_with("vmlinuz-") {
                    real = std::fs::read(e.path()).ok();
                    break;
                }
            }
        }
        let Some(k) = real else {
            std::eprintln!("SKIPPED: no vmlinuz- fixture on this machine");
            return;
        };
        let initrd = vec![0xABu8; 0x100000];
        let l = plan(&k, &initrd, b"root=/dev/vda1 ro", &RAM, &purg())
            .expect("a shipping Fedora kernel lays out");
        assert_eq!(l.segments.len(), 4);
        let h = SetupHeader::parse(&k).expect("wf");
        assert_eq!(l.segments[2].bufsz, k.len() as u64 - h.kern16_size());
        assert_eq!(l.segments[2].memsz, h.init_size.div_ceil(PAGE_SIZE) * PAGE_SIZE);
        assert_eq!(l.segments[2].mem % h.kernel_alignment, 0);
        assert_eq!(l.segments[3].bufsz, initrd.len() as u64);
        for (i, a) in l.segments.iter().enumerate() {
            for b in &l.segments[..i] {
                assert!(a.mem + a.memsz <= b.mem || b.mem + b.memsz <= a.mem);
            }
            assert_eq!(a.mem % PAGE_SIZE, 0);
            assert!(a.bufsz <= a.memsz);
            assert!(a.buf + a.bufsz <= l.blob.len() as u64);
        }
    }
}
