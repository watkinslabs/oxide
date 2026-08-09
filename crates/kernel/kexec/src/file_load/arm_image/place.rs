// Where the three arm64 segments land: the kernel, the initramfs and the
// device tree.
//
// THE ITERATIVE PROBE IS THE ALGORITHM, not an optimisation. The kernel is
// placed first and bottom-up, and everything else must sit ABOVE it; on a
// machine whose lowest usable range is barely larger than the kernel, the
// first hole that fits the kernel leaves no room for the rest. The reference
// therefore erases the kernel placement, raises the floor past it and probes
// again, and keeps doing so until either everything fits or no hole is left.
//
// A one-shot placement passes every test written on a machine with gigabytes
// above the kernel and fails only where the failure is unrecoverable: a small
// board, at reboot time, with the old kernel already quiesced.

extern crate alloc;
use alloc::vec::Vec;

use crate::file_load::kbuf::{locate_mem_hole, push_segment, KexecBuf};
use crate::uapi::{KexecSegment, PAGE_SIZE};
use crate::validate::{Error, KResult};

/// Alignment the arm64 boot protocol requires of the image base.
///
/// The image's own 2 MiB block mappings are cut relative to this base; a base
/// aligned less than that cannot be described by the tables the new kernel
/// builds for itself before it has an allocator.
pub const MIN_KIMG_ALIGN: u64 = 2 * 1024 * 1024;

/// One gibibyte, the granularity the initramfs window is anchored on.
pub const SZ_1G: u64 = 1024 * 1024 * 1024;

/// Alignment the device tree is placed at, so the blob never straddles a
/// 2 MiB boundary the new kernel has not mapped yet: it reads the tree
/// through a single early block mapping.
pub const DTB_ALIGN: u64 = 2 * 1024 * 1024;

/// Size of the window the initramfs must fall inside, anchored at the 1 GiB
/// -aligned base of the kernel image.
///
/// The new kernel can only linear-map an initramfs within this distance of the
/// start of its own DRAM for every granule and page-table depth combination.
/// Outside it, the new kernel does not fail — it silently DROPS the initramfs
/// and continues with a device tree that still advertises one, which surfaces
/// as a root filesystem that is not there.
pub const INITRD_WINDOW: u64 = 32 * SZ_1G;

/// Which of the three buffers a placement describes.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BufKind {
    /// The kernel image itself.
    Kernel,
    /// The initramfs, when there is one.
    Initrd,
    /// The device tree handed to the new kernel.
    Dtb,
}

/// A buffer, its constraints, and the address the search chose for it.
#[derive(Clone, Debug)]
pub struct PlacedBuf {
    /// Which buffer this is.
    pub kind: BufKind,
    /// The constraints the search satisfied, carrying the sizes the segment
    /// is built from.
    pub kb: KexecBuf,
    /// Chosen destination.
    pub mem: u64,
}

/// The whole layout, in segment order.
#[derive(Clone, Debug)]
pub struct Placement {
    /// Kernel, then initramfs when present, then the device tree.
    pub bufs: Vec<PlacedBuf>,
    /// Physical address the new kernel is entered at.
    pub entry: u64,
    /// Physical address of the device tree, handed over in `x0`.
    pub dtb_mem: u64,
    /// Physical address of the initramfs, or 0 when there is none. Zero is
    /// the reference's own "no initramfs" spelling — it is never a legal
    /// destination, so it cannot be confused with a placement.
    pub initrd_mem: u64,
}

/// `image_load`'s placement loop plus `load_other_segments`.
///
/// `image_size` and `text_offset` come from the header; the three lengths are
/// the bytes each buffer occupies in the file. `EADDRNOTAVAIL` when no
/// arrangement fits, which is the kernel placement's error and not the
/// initramfs's — the last thing that failed is the thing that ran out of room.
/// # C: O(N_ranges^2) worst case
pub fn place(
    ram: &[(u64, u64)], image_size: u64, text_offset: u64,
    kernel_len: u64, initrd_len: u64, dtb_len: u64,
) -> KResult<Placement> {
    if image_size == 0 || dtb_len == 0 { return Err(Error::Inval); }

    let mut kb = KexecBuf::new(kernel_len, image_size + text_offset);
    kb.align = MIN_KIMG_ALIGN;
    kb.min = 0;
    kb.max = u64::MAX;
    kb.top_down = false;

    loop {
        let kmem = locate_mem_hole(&kb, ram, &[])?;
        // The kernel's own segment, as the collision test will see it: the
        // page-rounded reservation, not the file length.
        let mut placed: Vec<KexecSegment> = Vec::new();
        push_segment(&mut placed, 0, &kb, kmem);
        let kernel_memsz = placed[0].memsz;

        match load_other(ram, &mut placed, kmem, kernel_memsz, initrd_len, dtb_len) {
            Ok((initrd, dtb)) => {
                // The file bytes start at `text_offset` into the reservation;
                // the reservation itself shrinks by the same amount, so the
                // bytes below the entry point stay claimed by nobody and the
                // new kernel's own image is exactly what is reserved.
                let mut kkb = kb.clone();
                kkb.memsz = kernel_memsz - text_offset;
                let kernel_mem = kmem + text_offset;

                let mut bufs = Vec::new();
                bufs.push(PlacedBuf { kind: BufKind::Kernel, kb: kkb, mem: kernel_mem });
                let initrd_mem = match initrd {
                    Some((ikb, imem)) => {
                        bufs.push(PlacedBuf { kind: BufKind::Initrd, kb: ikb, mem: imem });
                        imem
                    }
                    None => 0,
                };
                let (dkb, dmem) = dtb;
                bufs.push(PlacedBuf { kind: BufKind::Dtb, kb: dkb, mem: dmem });
                return Ok(Placement { bufs, entry: kernel_mem, dtb_mem: dmem, initrd_mem });
            }
            Err(_) => {
                // Erase the kernel placement and probe the next hole up. The
                // floor is the END of the reservation just tried, so the
                // search cannot return the same address twice and the loop
                // terminates at the top of RAM.
                kb.min = kmem + kernel_memsz;
            }
        }
    }
}

type Other = (Option<(KexecBuf, u64)>, (KexecBuf, u64));

/// `load_other_segments`: the initramfs and the device tree, both above the
/// kernel, and neither overlapping it or each other.
fn load_other(
    ram: &[(u64, u64)], placed: &mut Vec<KexecSegment>,
    kernel_mem: u64, kernel_memsz: u64, initrd_len: u64, dtb_len: u64,
) -> KResult<Other> {
    // Nothing is allocated below the kernel: the new kernel's image is the
    // bottom of its own world, and a buffer beneath it is one the new kernel
    // will not know to preserve.
    let floor = kernel_mem.saturating_add(kernel_memsz);

    let initrd = if initrd_len > 0 {
        let mut ib = KexecBuf::new(initrd_len, initrd_len);
        ib.align = PAGE_SIZE;
        ib.min = floor;
        ib.max = (kernel_mem / SZ_1G) * SZ_1G + INITRD_WINDOW;
        ib.top_down = false;
        let at = locate_mem_hole(&ib, ram, placed)?;
        push_segment(placed, 0, &ib, at);
        Some((ib, at))
    } else {
        None
    };

    let mut db = KexecBuf::new(dtb_len, dtb_len);
    db.align = DTB_ALIGN;
    db.min = floor;
    db.max = u64::MAX;
    db.top_down = true;
    let dat = locate_mem_hole(&db, ram, placed)?;
    push_segment(placed, 0, &db, dat);

    Ok((initrd, (db, dat)))
}

#[cfg(test)]
mod tests;
