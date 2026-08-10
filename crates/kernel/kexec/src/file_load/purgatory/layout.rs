// The purgatory blob's internal layout, and the three things the kernel writes
// into a copy of it before that copy becomes a segment.
//
// Ungated on purpose. Every offset here is a contract between hand-written
// assembly and the Rust that patches it; a slip is not a compile error and not
// a boot failure either — the purgatory would hash the wrong bytes, decide the
// image is corrupt and halt the machine forever, with no diagnostic anywhere.
// So the offsets live where a hosted test can assert them, and the assembly
// asserts the same numbers at assembly time (`blob.rs`).
//
// THE DATA AREA COMES FIRST, and its size is fixed. The reference resolves
// `entry64_regs` / `purgatory_sha_regions` / `purgatory_sha256_digest` as ELF
// symbols out of a relocatable object it relocates at load time. This port has
// no second compilation unit to relocate, so the same three objects sit at
// offsets the blob's own layout fixes. Same three patches, same observable
// behaviour, no ELF relocation pass.

use crate::validate::{Error, KResult};

/// `entry64_regs`: the general-purpose register block the purgatory loads
/// before jumping to the new kernel.
pub const OFF_ENTRY_REGS: usize = 0x0000;
/// Registers in the block, in the order the 64-bit entry contract fixes.
pub const REGS_COUNT: usize = 17;
/// Bytes `entry64_regs` occupies.
pub const ENTRY_REGS_SIZE: usize = REGS_COUNT * 8;

/// Index of `rbx` in the register block.
pub const REG_RBX: usize = 3;
/// Index of `rsp`.
pub const REG_RSP: usize = 4;
/// Index of `rsi`.
pub const REG_RSI: usize = 6;
/// Index of `rip`, LAST — the jump is an indirect jump through this slot.
pub const REG_RIP: usize = 16;

/// `purgatory_sha256_digest`: the expected digest over every hashed region.
pub const OFF_DIGEST: usize = 0x0088;
/// SHA-256 digest length.
pub const DIGEST_SIZE: usize = 32;

/// `purgatory_sha_regions`: the `(start, len)` table the purgatory hashes.
pub const OFF_SHA_REGIONS: usize = 0x00B0;
/// Table entries, one per possible segment (`KEXEC_SEGMENT_MAX`).
pub const SHA_REGIONS_MAX: usize = 16;
/// Bytes one `(start, len)` pair occupies.
pub const SHA_REGION_SIZE: usize = 16;

/// The blob's own GDT — four 8-byte descriptors: null, unused, 64-bit code at
/// selector `CODE_SEL`, flat data at `DATA_SEL`.
pub const OFF_GDT: usize = 0x01B0;
/// Bytes the GDT occupies.
pub const GDT_SIZE: usize = 32;
/// The `lgdt` operand the entry code fills in with the GDT's runtime address.
pub const OFF_GDTR: usize = 0x01D0;
/// SHA-256 initial chaining values.
pub const OFF_H0: usize = 0x01E0;
/// SHA-256 round constants.
pub const OFF_K: usize = 0x0200;

/// First instruction — the address `Loaded::entry` names.
pub const OFF_CODE: usize = 0x0300;
/// The purgatory's own stack; it runs with `rsp` at the end of this page.
pub const OFF_PURG_STACK: usize = 0x1000;
/// End of the purgatory's stack (exclusive), which is where `rsp` starts.
pub const OFF_PURG_STACK_END: usize = OFF_PURG_STACK + 0x1000;
/// The stack handed to the NEW kernel; `entry64_regs.rsp` names its end.
pub const OFF_NEW_STACK: usize = 0x2000;
/// End of the new kernel's stack (exclusive) — the value written to `rsp`.
pub const OFF_NEW_STACK_END: usize = OFF_NEW_STACK + 0x1000;

/// Bytes the whole blob occupies, code and both stacks included.
///
/// `bufsz == memsz` for the purgatory segment: the stacks are carried as real
/// zero bytes rather than left to a zeroed tail, so the segment's content does
/// not depend on the staging path clearing anything.
pub const BLOB_LEN: usize = 0x3000;

/// Selector of the 64-bit code descriptor in the blob's GDT.
pub const CODE_SEL: u16 = 0x10;
/// Selector of the flat data descriptor.
pub const DATA_SEL: u16 = 0x18;

/// One `(start, len)` row of the region table the purgatory hashes.
///
/// `len` is the segment's `memsz`, not its `bufsz`: the purgatory reads the
/// destination AFTER relocation, where the bytes past `bufsz` are zero, and the
/// kernel-side digest hashes those zeros to match.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ShaRegion {
    /// Destination physical address.
    pub start: u64,
    /// Bytes at `start`, `memsz`.
    pub len: u64,
}

/// The four registers the loader chooses; the other thirteen are zero.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct EntryRegs {
    /// Bootstrap-processor marker: zero.
    pub rbx: u64,
    /// Stack the new kernel starts on.
    pub rsp: u64,
    /// Physical address of the boot-parameter page.
    pub rsi: u64,
    /// The new kernel's 64-bit entry point.
    pub rip: u64,
}

fn slot(blob: &mut [u8], off: usize, len: usize) -> KResult<&mut [u8]> {
    blob.get_mut(off..off + len).ok_or(Error::Inval)
}

/// Write `entry64_regs`. Every slot is written, so a blob patched twice cannot
/// carry a register from the previous image.
/// # C: O(1)
pub fn patch_entry_regs(blob: &mut [u8], r: &EntryRegs) -> KResult<()> {
    let regs = slot(blob, OFF_ENTRY_REGS, ENTRY_REGS_SIZE)?;
    for b in regs.iter_mut() { *b = 0; }
    let mut put = |i: usize, v: u64| regs[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    put(REG_RBX, r.rbx);
    put(REG_RSP, r.rsp);
    put(REG_RSI, r.rsi);
    put(REG_RIP, r.rip);
    Ok(())
}

/// Write `purgatory_sha_regions`, zeroing every row the image does not use.
///
/// A stale row would be hashed as if it were live — the purgatory walks all
/// `SHA_REGIONS_MAX` rows and a `len` of zero is what makes a row contribute
/// nothing.
/// # C: O(SHA_REGIONS_MAX)
pub fn patch_sha_regions(blob: &mut [u8], regions: &[ShaRegion]) -> KResult<()> {
    if regions.len() > SHA_REGIONS_MAX { return Err(Error::Inval); }
    let tbl = slot(blob, OFF_SHA_REGIONS, SHA_REGIONS_MAX * SHA_REGION_SIZE)?;
    for b in tbl.iter_mut() { *b = 0; }
    for (i, r) in regions.iter().enumerate() {
        let o = i * SHA_REGION_SIZE;
        tbl[o..o + 8].copy_from_slice(&r.start.to_le_bytes());
        tbl[o + 8..o + 16].copy_from_slice(&r.len.to_le_bytes());
    }
    Ok(())
}

/// Write `purgatory_sha256_digest`.
/// # C: O(1)
pub fn patch_digest(blob: &mut [u8], digest: &[u8; DIGEST_SIZE]) -> KResult<()> {
    slot(blob, OFF_DIGEST, DIGEST_SIZE)?.copy_from_slice(digest);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec;

    fn blank() -> alloc::vec::Vec<u8> { vec![0xAAu8; BLOB_LEN] }

    #[test]
    fn the_data_area_regions_do_not_overlap_and_end_where_the_code_starts() {
        // The one property a hand-laid data area can silently lose. If the
        // region table overran into the GDT, the purgatory would `lgdt` a
        // segment descriptor made of segment addresses and triple-fault.
        assert!(OFF_ENTRY_REGS + ENTRY_REGS_SIZE <= OFF_DIGEST);
        assert!(OFF_DIGEST + DIGEST_SIZE <= OFF_SHA_REGIONS);
        assert!(OFF_SHA_REGIONS + SHA_REGIONS_MAX * SHA_REGION_SIZE <= OFF_GDT);
        assert!(OFF_GDT + GDT_SIZE <= OFF_GDTR);
        assert!(OFF_GDTR + 16 <= OFF_H0);
        assert!(OFF_H0 + 32 <= OFF_K);
        assert!(OFF_K + 256 <= OFF_CODE);
        assert!(OFF_CODE < OFF_PURG_STACK);
        assert_eq!(OFF_NEW_STACK_END, BLOB_LEN);
    }

    #[test]
    fn the_register_block_places_rip_last_and_rbx_rsp_rsi_where_the_asm_reads_them() {
        // The 64-bit entry contract fixes the order rax,rcx,rdx,rbx,rsp,rbp,
        // rsi,rdi,r8..r15,rip. Getting rsi and rsp the wrong way round hands
        // the new kernel its boot parameters as a stack pointer.
        let mut b = blank();
        patch_entry_regs(&mut b, &EntryRegs { rbx: 0, rsp: 0x1111, rsi: 0x2222, rip: 0x3333 })
            .expect("the blob is long enough");
        let rd = |i: usize| u64::from_le_bytes(
            b[OFF_ENTRY_REGS + i * 8..OFF_ENTRY_REGS + i * 8 + 8].try_into().unwrap());
        // LITERAL slot numbers, not the constants the writer used: the order
        // rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi,r8..r15,rip is the ABI, and a test
        // written in terms of the same constants it is checking cannot see a
        // constant that moved.
        assert_eq!(rd(3), 0, "rbx");
        assert_eq!(rd(4), 0x1111, "rsp");
        assert_eq!(rd(6), 0x2222, "rsi");
        assert_eq!(rd(16), 0x3333, "rip");
        assert_eq!(REGS_COUNT, 17);
        assert_eq!(REG_RIP, REGS_COUNT - 1, "rip is loaded by an indirect jump through the last slot");
        // Every other slot is zero, including the ones the fill byte occupied.
        for i in 0..REGS_COUNT {
            if [REG_RBX, REG_RSP, REG_RSI, REG_RIP].contains(&i) { continue; }
            assert_eq!(rd(i), 0, "slot {i} was not cleared");
        }
    }

    #[test]
    fn unused_region_rows_are_zeroed_so_they_hash_nothing() {
        let mut b = blank();
        patch_sha_regions(&mut b, &[ShaRegion { start: 0x100000, len: 0x2000 }])
            .expect("the blob is long enough");
        let rd = |o: usize| u64::from_le_bytes(
            b[OFF_SHA_REGIONS + o..OFF_SHA_REGIONS + o + 8].try_into().unwrap());
        assert_eq!(rd(0), 0x100000);
        assert_eq!(rd(8), 0x2000);
        for i in 1..SHA_REGIONS_MAX {
            assert_eq!(rd(i * SHA_REGION_SIZE), 0);
            assert_eq!(rd(i * SHA_REGION_SIZE + 8), 0, "row {i} kept a length");
        }
    }

    #[test]
    fn more_regions_than_the_table_holds_is_refused_rather_than_truncated() {
        let mut b = blank();
        let many = [ShaRegion { start: 1, len: 1 }; SHA_REGIONS_MAX + 1];
        assert_eq!(patch_sha_regions(&mut b, &many), Err(Error::Inval));
    }

    #[test]
    fn the_digest_lands_where_the_comparison_reads_it() {
        let mut b = blank();
        let d = [7u8; DIGEST_SIZE];
        patch_digest(&mut b, &d).expect("the blob is long enough");
        assert_eq!(&b[OFF_DIGEST..OFF_DIGEST + DIGEST_SIZE], &d[..]);
        assert_eq!(b[OFF_DIGEST - 1], 0xAA, "the write ran backwards");
        assert_eq!(b[OFF_DIGEST + DIGEST_SIZE], 0xAA, "the write ran long");
    }

    #[test]
    fn a_short_blob_is_refused_rather_than_patched_out_of_bounds() {
        let mut short = vec![0u8; OFF_SHA_REGIONS];
        assert_eq!(patch_digest(&mut short, &[0u8; DIGEST_SIZE]), Ok(()));
        assert_eq!(patch_sha_regions(&mut short, &[]), Err(Error::Inval));
    }
}
