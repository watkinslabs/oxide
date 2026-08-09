// The boot-parameter page the new kernel is entered with, built as bytes.
//
// Ungated on purpose. Every write here lands at a fixed offset in a 4 KiB ABI
// page; a wrong offset is not a compile error and not a staging error either —
// the new kernel reads a plausible value out of the wrong field and dies in its
// own early setup, after the machine that could have reported it is gone.
//
// ONE SEGMENT, TWO OBJECTS. The page and the command line share a buffer, as
// the reference shares them, so the loader places one segment rather than two:
// `boot_params` occupies `[0, BP_SIZE)` and the command line starts at exactly
// `BP_SIZE`, which is what makes `cmd_line_ptr` a fixed offset from the
// segment's own address.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use super::header::SetupHeader;
use super::uapi::*;
use crate::validate::{Error, KResult};

/// The addresses the loader chose, as the page must report them.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Addrs {
    /// Where this very page lands.
    pub bootparam: u64,
    /// Where the initramfs lands; ignored when `initrd_len` is zero.
    pub initrd: u64,
    /// Initramfs length; zero means the image carries none.
    pub initrd_len: u64,
}

fn put32(buf: &mut [u8], off: usize, v: u32) { buf[off..off + 4].copy_from_slice(&v.to_le_bytes()); }
fn put16(buf: &mut [u8], off: usize, v: u16) { buf[off..off + 2].copy_from_slice(&v.to_le_bytes()); }

/// Bytes the combined page-plus-command-line buffer occupies.
///
/// `cmdline_len` counts the terminating NUL. The `elfcorehdr=` reservation is
/// unconditional, matching the reference, so a default image and a crash image
/// place the same sized segment.
/// # C: O(1)
pub fn buffer_len(cmdline_len: usize) -> usize {
    let raw = BP_SIZE + cmdline_len + MAX_ELFCOREHDR_STR_LEN;
    let a = BOOTPARAM_ALIGN as usize;
    raw.div_ceil(a) * a
}

/// Build the page. `cmdline` is the command line WITHOUT its terminating NUL.
/// # C: O(cmdline + N_ram_ranges)
pub fn build(
    kernel: &[u8], h: &SetupHeader, cmdline: &[u8], at: &Addrs, ram: &[(u64, u64)],
) -> KResult<Vec<u8>> {
    let mut buf = vec![0u8; buffer_len(cmdline.len() + 1)];

    // The setup header is taken from the FILE, not synthesised: it carries the
    // kernel's own description of itself (alignment, init_size, protocol
    // version) and the new kernel reads its own values back out of it.
    let src = kernel.get(BP_HDR..BP_HDR + h.header_size).ok_or(Error::NoExec)?;
    let dst_end = BP_HDR + h.header_size;
    if dst_end > BP_SIZE { return Err(Error::NoExec); }
    buf[BP_HDR..dst_end].copy_from_slice(src);

    // Who loaded this, and: none of the previous loader's flags survive.
    buf[HDR_TYPE_OF_LOADER] = TYPE_OF_LOADER;
    buf[HDR_LOADFLAGS] = LOADFLAGS;

    if at.initrd_len != 0 {
        put32(&mut buf, HDR_RAMDISK_IMAGE, at.initrd as u32);
        put32(&mut buf, HDR_RAMDISK_SIZE, at.initrd_len as u32);
        put32(&mut buf, BP_EXT_RAMDISK_IMAGE, (at.initrd >> 32) as u32);
        put32(&mut buf, BP_EXT_RAMDISK_SIZE, (at.initrd_len >> 32) as u32);
    }

    buf[BP_SIZE..BP_SIZE + cmdline.len()].copy_from_slice(cmdline);
    buf[BP_SIZE + cmdline.len()] = 0;
    let cmdline_phys = at.bootparam + BP_SIZE as u64;
    put32(&mut buf, HDR_CMD_LINE_PTR, cmdline_phys as u32);
    // The reference writes the high half only when it is non-zero, so a page
    // placed below 4 GiB leaves the field exactly as the setup header had it.
    if (cmdline_phys >> 32) != 0 { put32(&mut buf, BP_EXT_CMD_LINE_PTR, (cmdline_phys >> 32) as u32); }

    fill_e820(&mut buf, ram);
    fill_mem_k(&mut buf, ram);
    Ok(buf)
}

/// Copy usable RAM into `e820_table`, capped at what the page holds.
///
/// Every range is `E820_TYPE_RAM`: this is the map of memory the machine may
/// use, and the ranges kexec is handed are exactly that. Ranges past the cap
/// are dropped rather than reported through a `setup_data` chain, which is what
/// the reference does.
/// # C: O(N_ram_ranges)
fn fill_e820(buf: &mut [u8], ram: &[(u64, u64)]) {
    let n = core::cmp::min(ram.len(), E820_MAX_ENTRIES_ZEROPAGE);
    buf[BP_E820_ENTRIES] = n as u8;
    for (i, &(start, end)) in ram.iter().take(n).enumerate() {
        let o = BP_E820_TABLE + i * E820_ENTRY_SIZE;
        buf[o..o + 8].copy_from_slice(&start.to_le_bytes());
        buf[o + 8..o + 16].copy_from_slice(&end.saturating_sub(start).to_le_bytes());
        put32(buf, o + 16, E820_TYPE_RAM);
    }
}

/// `alt_mem_k` and `screen_info.ext_mem_k`: memory above 1 MiB, in KiB.
///
/// Both are legacy fields a kernel falls back on when it distrusts the E820
/// map, and both saturate — 16 bits and 32 bits respectively — so a machine
/// with more memory than they can express reports the ceiling rather than a
/// wrapped value that reads as a tiny machine.
/// # C: O(N_ram_ranges)
fn fill_mem_k(buf: &mut [u8], ram: &[(u64, u64)]) {
    for &(start, end) in ram {
        if end <= LOW_MEMORY_TOP || start > LOW_MEMORY_TOP { continue; }
        let mem_k = ((end - 1) >> 10) - (LOW_MEMORY_TOP >> 10);
        put16(buf, BP_EXT_MEM_K, core::cmp::min(mem_k, EXT_MEM_K_MAX) as u16);
        put32(buf, BP_ALT_MEM_K, core::cmp::min(mem_k, ALT_MEM_K_MAX) as u32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_load::x86_bzimage::header::probe;

    fn hdr_file() -> Vec<u8> {
        let mut k = vec![0u8; 0x1000];
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
        k[HDR_INIT_SIZE..HDR_INIT_SIZE + 4].copy_from_slice(&0x4aea000u32.to_le_bytes());
        // A marker inside the header body, to prove the copy lands at 0x1F1.
        k[HDR_KERNEL_ALIGNMENT] = 0x00;
        k
    }

    fn head() -> SetupHeader { SetupHeader::parse(&hdr_file()).expect("well formed") }

    const RAM: [(u64, u64); 2] = [(0x1000, 0x9f000), (0x100000, 0x8000_0000)];

    fn rd32(b: &[u8], o: usize) -> u32 { u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) }
    fn rd64(b: &[u8], o: usize) -> u64 { u64::from_le_bytes(b[o..o + 8].try_into().unwrap()) }

    #[test]
    fn the_setup_header_is_copied_from_the_file_to_offset_0x1f1() {
        // Copied, not synthesised: the new kernel reads its own alignment,
        // init_size and protocol version back out of this page.
        let k = hdr_file();
        let b = build(&k, &head(), b"quiet", &Addrs::default(), &RAM).expect("well formed");
        assert_eq!(&b[HDR_MAGIC..HDR_MAGIC + 4], &MAGIC[..]);
        assert_eq!(rd64(&b, HDR_PREF_ADDRESS), 0x1000000);
        assert_eq!(rd32(&b, HDR_INIT_SIZE), 0x4aea000);
        // The copy writes nothing before 0x1F1; the only earlier bytes any
        // other step touches are `ext_mem_k` and `alt_mem_k`.
        assert!(b[BP_EXT_MEM_K + 2..BP_ALT_MEM_K].iter().all(|&x| x == 0));
        // The signature and the boot flag survive the copy; `probe` would
        // still refuse the page, because `loadflags` is deliberately cleared
        // below — the field describes how THIS load happened, not the file.
        assert_eq!(u16::from_le_bytes(b[HDR_BOOT_FLAG..HDR_BOOT_FLAG + 2].try_into().unwrap()),
                   BOOT_FLAG);
        assert_eq!(probe(&b), Err(Error::NoExec));
    }

    #[test]
    fn the_loader_id_is_stamped_and_the_previous_boots_loadflags_are_cleared() {
        // `LOADED_HIGH` came out of the file and must NOT survive into the new
        // kernel's view: the flags describe how THIS load was performed.
        let k = hdr_file();
        assert_eq!(k[HDR_LOADFLAGS], LOADED_HIGH);
        let b = build(&k, &head(), b"", &Addrs::default(), &RAM).expect("wf");
        assert_eq!(b[HDR_TYPE_OF_LOADER], 0xD0);
        assert_eq!(b[HDR_LOADFLAGS], 0);
    }

    #[test]
    fn the_command_line_follows_the_page_and_is_nul_terminated_where_it_says() {
        let k = hdr_file();
        let at = Addrs { bootparam: 0x7000_0000, initrd: 0, initrd_len: 0 };
        let b = build(&k, &head(), b"console=ttyS0", &at, &RAM).expect("wf");
        assert_eq!(&b[BP_SIZE..BP_SIZE + 13], b"console=ttyS0");
        assert_eq!(b[BP_SIZE + 13], 0);
        assert_eq!(rd32(&b, HDR_CMD_LINE_PTR) as u64, at.bootparam + BP_SIZE as u64);
        assert_eq!(rd32(&b, BP_EXT_CMD_LINE_PTR), 0, "a low page writes no high half");
    }

    #[test]
    fn a_page_above_four_gib_reports_the_high_half_of_the_command_line_pointer() {
        // The whole reason this loader demands `XLF_CAN_BE_LOADED_ABOVE_4G`.
        // Dropping the high half points the new kernel at a truncated address
        // in low memory, where it reads whatever happens to be there as its
        // command line.
        let k = hdr_file();
        let at = Addrs { bootparam: 0x1_8000_0000, initrd: 0, initrd_len: 0 };
        let b = build(&k, &head(), b"x", &at, &RAM).expect("wf");
        assert_eq!(rd32(&b, HDR_CMD_LINE_PTR), 0x8000_1000);
        assert_eq!(rd32(&b, BP_EXT_CMD_LINE_PTR), 1);
    }

    #[test]
    fn the_initramfs_address_and_length_are_split_across_both_halves() {
        let k = hdr_file();
        let at = Addrs { bootparam: 0x1000, initrd: 0x2_0000_1000, initrd_len: 0x1_0000_0004 };
        let b = build(&k, &head(), b"", &at, &RAM).expect("wf");
        assert_eq!(rd32(&b, HDR_RAMDISK_IMAGE), 0x0000_1000);
        assert_eq!(rd32(&b, BP_EXT_RAMDISK_IMAGE), 2);
        assert_eq!(rd32(&b, HDR_RAMDISK_SIZE), 4);
        assert_eq!(rd32(&b, BP_EXT_RAMDISK_SIZE), 1);
    }

    #[test]
    fn an_image_with_no_initramfs_leaves_the_ramdisk_fields_alone() {
        let k = hdr_file();
        let at = Addrs { bootparam: 0x1000, initrd: 0xdead_beef, initrd_len: 0 };
        let b = build(&k, &head(), b"", &at, &RAM).expect("wf");
        assert_eq!(rd32(&b, HDR_RAMDISK_IMAGE), 0);
        assert_eq!(rd32(&b, BP_EXT_RAMDISK_IMAGE), 0);
    }

    #[test]
    fn the_e820_table_carries_every_range_as_usable_ram_in_twenty_byte_entries() {
        // 20 bytes, packed: addr, size, type. A 24-byte stride — what a
        // naturally aligned struct would produce — shifts every entry after
        // the first and the new kernel sees garbage ranges.
        let k = hdr_file();
        let b = build(&k, &head(), b"", &Addrs::default(), &RAM).expect("wf");
        assert_eq!(b[BP_E820_ENTRIES], 2);
        assert_eq!(rd64(&b, BP_E820_TABLE), 0x1000);
        assert_eq!(rd64(&b, BP_E820_TABLE + 8), 0x9f000 - 0x1000);
        assert_eq!(rd32(&b, BP_E820_TABLE + 16), E820_TYPE_RAM);
        assert_eq!(rd64(&b, BP_E820_TABLE + E820_ENTRY_SIZE), 0x100000);
        assert_eq!(rd64(&b, BP_E820_TABLE + E820_ENTRY_SIZE + 8), 0x8000_0000 - 0x100000);
        assert_eq!(rd32(&b, BP_E820_TABLE + E820_ENTRY_SIZE + 16), E820_TYPE_RAM);
        // The table ends inside the page, which is what fixes the 20-byte size.
        assert!(BP_E820_TABLE + E820_MAX_ENTRIES_ZEROPAGE * E820_ENTRY_SIZE <= BP_SIZE);
    }

    #[test]
    fn more_ranges_than_the_page_holds_are_capped_not_wrapped() {
        let k = hdr_file();
        let mut many: Vec<(u64, u64)> = Vec::new();
        for i in 0..E820_MAX_ENTRIES_ZEROPAGE + 10 {
            let s = 0x100000 + (i as u64) * 0x2000;
            many.push((s, s + 0x1000));
        }
        let b = build(&k, &head(), b"", &Addrs::default(), &many).expect("wf");
        assert_eq!(b[BP_E820_ENTRIES] as usize, E820_MAX_ENTRIES_ZEROPAGE);
        // The last entry that fits is written; nothing past the table is.
        let last = BP_E820_TABLE + (E820_MAX_ENTRIES_ZEROPAGE - 1) * E820_ENTRY_SIZE;
        assert_ne!(rd64(&b, last), 0);
        assert_eq!(&b[last + E820_ENTRY_SIZE..BP_SIZE], &vec![0u8; BP_SIZE - last - E820_ENTRY_SIZE][..]);
    }

    #[test]
    fn the_legacy_memory_size_fields_saturate_rather_than_wrap() {
        // 16 bits and 32 bits. A machine with 2 GiB above 1 MiB does not have
        // 0x1FC00 KiB expressible in `ext_mem_k`; wrapping reports a tiny
        // machine to a kernel that distrusts its E820 map.
        let k = hdr_file();
        let b = build(&k, &head(), b"", &Addrs::default(), &RAM).expect("wf");
        assert_eq!(u16::from_le_bytes(b[BP_EXT_MEM_K..BP_EXT_MEM_K + 2].try_into().unwrap()),
                   EXT_MEM_K_MAX as u16);
        assert_eq!(rd32(&b, BP_ALT_MEM_K), ((0x8000_0000u64 - 1) >> 10) as u32 - 0x400);
    }

    #[test]
    fn the_buffer_is_the_page_plus_the_command_line_plus_the_elfcorehdr_reserve() {
        assert_eq!(buffer_len(1), BP_SIZE + 32, "1 + 30 rounded up to 16");
        assert_eq!(buffer_len(16), BP_SIZE + 48);
        assert_eq!(buffer_len(0) % BOOTPARAM_ALIGN as usize, 0);
        let k = hdr_file();
        let b = build(&k, &head(), b"a b c", &Addrs::default(), &RAM).expect("wf");
        assert_eq!(b.len(), buffer_len(6));
    }
}
