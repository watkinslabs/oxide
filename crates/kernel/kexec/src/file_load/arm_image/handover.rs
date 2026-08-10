// The device tree the new kernel is handed.
//
// `of_kexec_alloc_and_setup_fdt`: the running kernel's own tree, with
// everything that describes THIS boot replaced by what describes the next one.
// The order below is the reference's order, and it matters in one place —
// the OLD initramfs reservation is dropped by reading the OLD
// `linux,initrd-start` / `linux,initrd-end`, so it has to happen before those
// properties are overwritten with the new addresses.
//
// Ungated. A property written at the wrong width, or a reservation left
// behind, produces a kernel that boots and then cannot find its root
// filesystem — a failure with no message anywhere naming the tree.

extern crate alloc;
use alloc::vec::Vec;

use super::fdt;
use crate::uapi::PAGE_SIZE;
use crate::validate::{Error, KResult};

/// `/chosen`, where the boot-time handover properties live.
pub const CHOSEN_PATH: &[u8] = b"/chosen";
/// Physical address of the initramfs.
pub const P_INITRD_START: &[u8] = b"linux,initrd-start";
/// Physical address one past the end of the initramfs.
pub const P_INITRD_END: &[u8] = b"linux,initrd-end";
/// Command line for the new kernel.
pub const P_BOOTARGS: &[u8] = b"bootargs";
/// Crash-dump ELF core header location — this boot's, never the next one's.
pub const P_ELFCOREHDR: &[u8] = b"linux,elfcorehdr";
/// Memory a crash kernel may use — this boot's, never the next one's.
pub const P_USABLE_MEMORY_RANGE: &[u8] = b"linux,usable-memory-range";
/// Entropy for the new kernel's KASLR offset.
pub const P_KASLR_SEED: &[u8] = b"kaslr-seed";
/// Entropy for the new kernel's random pool.
pub const P_RNG_SEED: &[u8] = b"rng-seed";
/// Empty marker telling the new kernel it was started by kexec.
pub const P_BOOTED_FROM_KEXEC: &[u8] = b"linux,booted-from-kexec";

/// Bytes of `rng-seed` the reference emits.
pub const RNG_SEED_SIZE: usize = 128;

/// Entropy for the new kernel, when this kernel has any to give.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Seeds {
    /// `kaslr-seed`.
    pub kaslr: u64,
    /// `rng-seed`.
    pub rng: [u8; RNG_SEED_SIZE],
}

/// What the handover writes into the tree.
#[derive(Clone, Debug)]
pub struct Handover<'a> {
    /// Physical address of the placed initramfs, or 0 when there is none.
    pub initrd_mem: u64,
    /// Length of the initramfs.
    pub initrd_len: u64,
    /// Command line without its terminating NUL; empty deletes `bootargs`.
    pub cmdline: &'a [u8],
    /// Physical address of the RUNNING kernel's tree, whose reservation this
    /// tree must not carry forward, or 0 when it is not known.
    pub old_fdt_pa: u64,
    /// Length of the running kernel's tree.
    pub old_fdt_len: u64,
    /// Entropy, or `None` when this kernel's pool is not yet seeded — in
    /// which case both seed properties are OMITTED rather than filled with
    /// something that merely looks random.
    pub seeds: Option<Seeds>,
}

/// Derive the new kernel's tree from `base`.
/// # C: O(tree size)
pub fn setup_fdt(base: &[u8], h: &Handover) -> KResult<Vec<u8>> {
    let mut t = fdt::parse(base)?;

    // This tree's own blob is reserved in the tree it came from. The new
    // kernel is handed a DIFFERENT blob at a different address, so carrying
    // the reservation forward would reserve memory nothing occupies.
    if h.old_fdt_pa != 0 { t.del_mem_rsv(h.old_fdt_pa, h.old_fdt_len); }

    let chosen = t.node_or_add(CHOSEN_PATH);

    // Both describe THIS boot's crash arrangements. A stale
    // `linux,usable-memory-range` confines the new kernel to the crash
    // reservation and it boots with almost no memory.
    chosen.del_prop(P_ELFCOREHDR);
    chosen.del_prop(P_USABLE_MEMORY_RANGE);

    // Drop the reservation belonging to the initramfs THIS boot used, read
    // from the properties before they are overwritten.
    let old = old_initrd(chosen)?;

    if h.initrd_mem != 0 {
        chosen.set_prop_u64(P_INITRD_START, h.initrd_mem);
        chosen.set_prop_u64(P_INITRD_END, h.initrd_mem + h.initrd_len);
    } else {
        // Not "leave the old ones alone": a tree that still advertises an
        // initramfs at an address now occupied by the new kernel's segments
        // makes the new kernel mount rubble as its root.
        chosen.del_prop(P_INITRD_START);
        chosen.del_prop(P_INITRD_END);
    }

    if h.cmdline.is_empty() {
        chosen.del_prop(P_BOOTARGS);
    } else {
        chosen.set_prop_string(P_BOOTARGS, h.cmdline);
    }

    // Deleted unconditionally first: a seed carried over from this boot is a
    // seed an attacker who saw this boot already knows.
    chosen.del_prop(P_KASLR_SEED);
    chosen.del_prop(P_RNG_SEED);
    match &h.seeds {
        Some(s) => {
            chosen.set_prop_u64(P_KASLR_SEED, s.kaslr);
            chosen.set_prop(P_RNG_SEED, &s.rng);
        }
        None => {}
    }

    chosen.set_prop_empty(P_BOOTED_FROM_KEXEC);

    if let Some((start, size)) = old {
        // Firmware reserves a page-rounded extent where kexec reserves the
        // exact length, so both spellings are tried.
        if !t.del_mem_rsv(start, size) {
            t.del_mem_rsv(start, size.div_ceil(PAGE_SIZE) * PAGE_SIZE);
        }
    }
    if h.initrd_mem != 0 { t.add_mem_rsv(h.initrd_mem, h.initrd_len); }

    Ok(t.to_blob())
}

/// The extent of the initramfs the RUNNING kernel booted with, from the
/// properties still in the tree.
///
/// `EINVAL` when a start is present without an end: the tree is describing an
/// initramfs whose extent cannot be computed, and guessing one would drop the
/// wrong reservation.
fn old_initrd(chosen: &fdt::Node) -> KResult<Option<(u64, u64)>> {
    let Some(sv) = chosen.prop(P_INITRD_START) else { return Ok(None) };
    let Some(ev) = chosen.prop(P_INITRD_END) else { return Err(Error::Inval) };
    let start = read_number(sv).ok_or(Error::Inval)?;
    let end = read_number(ev).ok_or(Error::Inval)?;
    Ok(Some((start, end.saturating_sub(start))))
}

/// Read a device-tree number: `len / 4` big-endian 32-bit cells, most
/// significant first.
///
/// Firmware writes these one cell wide, kexec writes them two. A reader that
/// assumed eight bytes would read a four-byte property together with whatever
/// follows it; one that assumed four would truncate every address above
/// 4 GiB — which is where a server's initramfs lives.
/// # C: O(cells)
pub fn read_number(v: &[u8]) -> Option<u64> {
    if v.is_empty() || v.len() % 4 != 0 || v.len() > 8 { return None; }
    let mut n = 0u64;
    for c in v.chunks_exact(4) {
        n = (n << 32) | u32::from_be_bytes([c[0], c[1], c[2], c[3]]) as u64;
    }
    Some(n)
}

/// The entropy this kernel can honestly give the next one.
///
/// `None` until the pool is seeded, which is the reference's own condition —
/// emitting a constant, a counter or an unseeded pool's output would hand the
/// new kernel a KASLR offset an observer of THIS boot can predict, while
/// looking in every dump exactly like real entropy.
/// # C: O(RNG_SEED_SIZE)
pub fn collect_seeds() -> Option<Seeds> {
    if !crng::is_initialized() { return None; }
    let mut rng = [0u8; RNG_SEED_SIZE];
    crng::fill(&mut rng);
    Some(Seeds { kaslr: crng::next_u64(), rng })
}

#[cfg(test)]
mod tests;
