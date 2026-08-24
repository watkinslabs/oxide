// The load itself: header, tree, placement, segments.
//
// TWO PASSES OVER THE TREE, AND WHY THAT IS SOUND. The reference builds the
// device tree INSIDE its placement step, after the initramfs has an address,
// because the tree records that address. The tree's SIZE, though, does not
// depend on the address's value — `linux,initrd-start` is eight bytes whatever
// it holds, and the reservation entry is sixteen — so the tree can be built
// once with a placeholder address to learn its length, placed, and then built
// again with the real one. The second build's length is CHECKED against the
// first rather than assumed: if that invariant ever stopped holding, the
// segment would reserve the wrong number of bytes, and a silent one.

extern crate alloc;
use alloc::vec::Vec;

use super::{caps, handover, header, place};
use crate::file_load::kbuf::{append_blob, push_segment};
use crate::file_load::{LoadCtx, Loaded};
use crate::uapi::KexecSegment;
use crate::validate::{Error, KResult};

/// Stand-in initramfs address for the sizing pass.
///
/// Any non-zero value produces the same tree LENGTH as the real one; a zero
/// would take the no-initramfs branch and size a tree with two properties and
/// a reservation entry fewer.
pub const SIZING_INITRD_ADDR: u64 = 1 << 40;

/// `image_load`.
/// # C: O(file size + tree size)
pub fn load(ctx: &LoadCtx) -> KResult<Loaded> {
    let h = header::decode(&ctx.img.kernel)?;
    if h.magic != header::IMAGE_MAGIC { return Err(Error::Inval); }
    header::check_features(&h, &caps::host_caps())?;

    let initrd_len = ctx.img.initrd.len() as u64;
    let seeds = handover::collect_seeds();
    let usable_memory_range = ctx.crash.then_some(ctx.system);
    let ho = |initrd_mem: u64| handover::Handover {
        initrd_mem,
        initrd_len,
        cmdline: ctx.img.cmdline_str(),
        old_fdt_pa: ctx.fdt_pa,
        old_fdt_len: ctx.fdt.len() as u64,
        seeds: seeds.clone(),
        reserve: ctx.reserve,
        usable_memory_range,
    };

    let sizing_addr = if initrd_len > 0 { SIZING_INITRD_ADDR } else { 0 };
    let sizing = handover::setup_fdt(ctx.fdt, &ho(sizing_addr))?;

    let p = place::place(ctx.place, h.image_size, h.text_offset,
                         ctx.img.kernel.len() as u64, initrd_len, sizing.len() as u64)?;

    let dtb = handover::setup_fdt(ctx.fdt, &ho(p.initrd_mem))?;
    if dtb.len() != sizing.len() { return Err(Error::Inval); }

    let mut blob: Vec<u8> = Vec::new();
    let mut segments: Vec<KexecSegment> = Vec::new();
    for b in &p.bufs {
        let bytes: &[u8] = match b.kind {
            place::BufKind::Kernel => &ctx.img.kernel,
            place::BufKind::Initrd => &ctx.img.initrd,
            place::BufKind::Dtb => &dtb,
        };
        let off = append_blob(&mut blob, bytes);
        push_segment(&mut segments, off, &b.kb, b.mem);
    }

    Ok(Loaded { segments, entry: p.entry, blob, boot_arg: p.dtb_mem })
}

#[cfg(test)]
mod tests;
