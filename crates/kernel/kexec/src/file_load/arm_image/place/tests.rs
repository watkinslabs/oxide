// Placement provenance. Every test states the machine's RAM map, so the
// arrangement is checked rather than the fact that some arrangement was found.

use super::*;

const MIB: u64 = 1024 * 1024;

/// A generous machine: one range from 1 MiB to 2 GiB.
const BIG: [(u64, u64); 1] = [(MIB, 2 * SZ_1G)];

fn kind(p: &Placement, k: BufKind) -> Option<&PlacedBuf> {
    p.bufs.iter().find(|b| b.kind == k)
}

#[test]
fn the_kernel_lands_at_the_lowest_two_megabyte_aligned_hole_and_the_rest_above_it() {
    let p = place(&BIG, 64 * MIB, 0, 60 * MIB, 8 * MIB, 0x1000)
        .expect("a 2 GiB machine fits everything");
    let k = kind(&p, BufKind::Kernel).expect("kernel placed");
    assert_eq!(k.mem % MIN_KIMG_ALIGN, 0);
    assert_eq!(k.mem, 2 * MIB, "the first 2 MiB-aligned address inside RAM");
    assert_eq!(p.entry, k.mem);
    let i = kind(&p, BufKind::Initrd).expect("initrd placed");
    let d = kind(&p, BufKind::Dtb).expect("dtb placed");
    assert!(i.mem >= k.mem + k.kb.memsz, "initrd {:#x} is below the kernel", i.mem);
    assert!(d.mem >= k.mem + k.kb.memsz, "dtb {:#x} is below the kernel", d.mem);
    assert_eq!(d.mem % DTB_ALIGN, 0);
    assert_eq!(p.dtb_mem, d.mem);
    assert_eq!(p.initrd_mem, i.mem);
}

#[test]
fn the_device_tree_is_searched_from_the_top_and_the_initramfs_from_the_bottom() {
    // Opposite directions are not cosmetic: the initramfs must stay inside a
    // window anchored on the kernel, and the tree must stay out of the way of
    // everything the new kernel will want to allocate low.
    let p = place(&BIG, 16 * MIB, 0, 16 * MIB, MIB, 0x1000).expect("fits");
    let k = kind(&p, BufKind::Kernel).unwrap();
    let i = kind(&p, BufKind::Initrd).unwrap();
    let d = kind(&p, BufKind::Dtb).unwrap();
    // The initramfs takes the first hole above the kernel.
    assert_eq!(i.mem, k.mem + k.kb.memsz);
    // The tree takes the last one in the machine.
    assert!(d.mem > SZ_1G, "dtb at {:#x} was not searched top-down", d.mem);
}

#[test]
fn a_kernel_hole_that_leaves_no_room_for_the_rest_is_abandoned_for_the_next_one() {
    // THE RETRY. The kernel fits in the low range and the initramfs does not
    // fit anywhere the low range's window reaches — the only room for it is
    // 40 GiB up, outside the window anchored on a low kernel. Moving the
    // KERNEL there is what makes the arrangement possible, and a one-shot
    // placement never discovers that.
    let ram = [(MIB, 32 * MIB), (40 * SZ_1G, 41 * SZ_1G)];
    let p = place(&ram, 8 * MIB, 0, 8 * MIB, 48 * MIB, 0x1000)
        .expect("the far range fits everything once the kernel moves there");
    let k = kind(&p, BufKind::Kernel).unwrap();
    assert!(k.mem >= 40 * SZ_1G,
            "the kernel stayed low at {:#x}, so the initramfs cannot be in its window",
            k.mem);
    let i = kind(&p, BufKind::Initrd).unwrap();
    let d = kind(&p, BufKind::Dtb).unwrap();
    assert!(i.mem >= k.mem + k.kb.memsz);
    assert!(d.mem >= k.mem + k.kb.memsz);
}

#[test]
fn the_retry_walks_upward_and_stops_rather_than_probing_the_same_hole_forever() {
    // Eight low ranges, each big enough for the kernel alone. The search has
    // to abandon every one of them — and each abandonment must raise the
    // floor, or the same hole is probed forever and this test hangs.
    let mut ram = alloc::vec::Vec::new();
    for n in 0..8u64 {
        let base = (2 + n * 16) * MIB;
        ram.push((base, base + 10 * MIB));
    }
    ram.push((40 * SZ_1G, 41 * SZ_1G));
    let p = place(&ram, 8 * MIB, 0, 8 * MIB, 48 * MIB, 0x1000).expect("fits high up");
    assert!(kind(&p, BufKind::Kernel).unwrap().mem >= 40 * SZ_1G);
}

#[test]
fn a_machine_with_no_arrangement_reports_no_address_rather_than_looping() {
    // The same shape as the retry above, with the far range too small to hold
    // the kernel AND the initramfs. Every hole is tried, every arrangement
    // fails, and the answer is the kernel placement's error rather than a
    // hang or a partial layout.
    let ram = [(MIB, 32 * MIB), (40 * SZ_1G, 40 * SZ_1G + 40 * MIB)];
    assert_eq!(place(&ram, 8 * MIB, 0, 8 * MIB, 48 * MIB, 0x1000).err(),
               Some(Error::AddrNotAvail));
}

#[test]
fn the_text_offset_moves_the_entry_up_and_shrinks_the_reservation_by_the_same_amount() {
    // The classic slip: adding `text_offset` to the reservation and forgetting
    // to take it back off, so the kernel claims 512 KiB it does not own — or
    // moving `mem` without moving `memsz`, so the reservation runs past the
    // image's end and the next segment is pushed out of a machine that fits.
    let text_offset = 512 * 1024;
    let image_size = 16 * MIB;
    let with = place(&BIG, image_size, text_offset, 16 * MIB, 0, 0x1000).expect("fits");
    let without = place(&BIG, image_size, 0, 16 * MIB, 0, 0x1000).expect("fits");
    let k = kind(&with, BufKind::Kernel).unwrap();
    let k0 = kind(&without, BufKind::Kernel).unwrap();
    assert_eq!(k.mem, k0.mem + text_offset);
    // The reservation is exactly the image in BOTH cases — the offset moved
    // the base, it did not enlarge what the kernel claims.
    assert_eq!(k.kb.memsz, image_size);
    assert_eq!(k0.kb.memsz, image_size);
    assert_eq!(with.entry, k.mem);
}

#[test]
fn the_initramfs_stays_inside_the_window_the_new_kernel_can_map() {
    // A 32 MiB low range and a 26 MiB range 64 GiB up. The initramfs fits in
    // the far range and NOWHERE else, but 64 GiB is outside the window
    // anchored on any kernel placement in the low range — and the far range
    // is too small to hold the kernel and the initramfs together.
    //
    // Without the ceiling this arrangement SUCCEEDS, with the initramfs 64 GiB
    // from the kernel: a device tree that advertises an initramfs the new
    // kernel drops on the floor, and a root filesystem that is not there.
    let ram = [(MIB, 32 * MIB), (64 * SZ_1G, 64 * SZ_1G + 26 * MIB)];
    assert_eq!(place(&ram, 8 * MIB, 0, 8 * MIB, 24 * MIB, 0x1000).err(),
               Some(Error::AddrNotAvail));
    // The same machine with no initramfs to place has an answer, so the
    // refusal above is the window and not the machine being too small.
    assert!(place(&ram, 8 * MIB, 0, 8 * MIB, 0, 0x1000).is_ok());
}

#[test]
fn no_two_segments_overlap_in_any_arrangement() {
    let p = place(&BIG, 64 * MIB, 512 * 1024, 60 * MIB, 8 * MIB, 0x4000).expect("fits");
    for a in 0..p.bufs.len() {
        for b in (a + 1)..p.bufs.len() {
            let (x, y) = (&p.bufs[a], &p.bufs[b]);
            let xr = x.mem..x.mem + x.kb.memsz.div_ceil(PAGE_SIZE) * PAGE_SIZE;
            let yr = y.mem..y.mem + y.kb.memsz.div_ceil(PAGE_SIZE) * PAGE_SIZE;
            assert!(xr.end <= yr.start || yr.end <= xr.start,
                    "{:?} {:#x?} overlaps {:?} {:#x?}", x.kind, xr, y.kind, yr);
        }
    }
}

#[test]
fn nothing_is_placed_below_the_kernel_even_where_there_is_room() {
    // The kernel's base is 2 MiB-aligned, so a machine whose RAM starts at
    // 1 MiB has a hole UNDER it. Nothing may go there: the new kernel's image
    // is the bottom of the world it knows about, and a buffer beneath it is
    // one it will not know to preserve. A collision test alone does not catch
    // this — the hole does not overlap anything.
    let p = place(&BIG, 16 * MIB, 0, 16 * MIB, 0x1000, 0x1000).expect("fits");
    let k = kind(&p, BufKind::Kernel).unwrap();
    assert!(k.mem > BIG[0].0, "the test map has no room under the kernel");
    for b in &p.bufs {
        assert!(b.mem >= k.mem, "{:?} at {:#x} is below the kernel at {:#x}",
                b.kind, b.mem, k.mem);
    }
}

#[test]
fn a_zero_image_size_is_a_malformed_header_and_not_a_placement_failure() {
    assert_eq!(place(&BIG, 0, 0, 16 * MIB, 0, 0x1000).err(), Some(Error::Inval));
}

#[test]
fn there_is_always_a_device_tree_segment_because_the_boot_argument_is_its_address() {
    let p = place(&BIG, 16 * MIB, 0, 16 * MIB, 0, 0x1000).expect("fits");
    assert_eq!(p.bufs.len(), 2, "kernel and tree, no initramfs");
    assert_eq!(p.initrd_mem, 0);
    assert_ne!(p.dtb_mem, 0);
}
