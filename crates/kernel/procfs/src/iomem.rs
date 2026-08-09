// /proc/iomem — the physical address map, as `kexec-tools` reads it.
//
// This is not a decorative dump. `kexec_load(2)` makes the CALLER choose every
// destination address, and the only way userspace learns which physical
// addresses exist is this file: `kexec-tools` parses it, keeps the ranges whose
// label it recognises, and places the new kernel, its initramfs and its
// purgatory inside them. With no `/proc/iomem` there is no memory map, and
// `kexec -l` fails before it ever reaches the syscall — so the syscall's whole
// contract is unreachable from the program that exists to drive it.
//
// The rendering decision is ungated so it is checkable without a boot; only the
// fetch from the live PMM is kernel-only. A format slip here is invisible to
// every kernel-side test and shows up as a loader that silently sees no memory.

extern crate alloc;
use alloc::vec::Vec;

/// Label Linux gives a range of ordinary usable memory. `kexec-tools` matches
/// this string exactly; any other spelling makes the range invisible to it.
pub const SYSTEM_RAM: &str = "System RAM";

/// Hex digits each address is printed with when every address in the map fits
/// in 32 bits, and when it does not. Linux picks the width from the largest
/// address in the map and pads both ends of every line to it, so the columns
/// line up; a parser reading `%lx-%lx` accepts either, but a machine with
/// memory above 4 GiB whose lines were printed 8 wide would truncate.
pub const NARROW_WIDTH: usize = 8;
/// See [`NARROW_WIDTH`].
pub const WIDE_WIDTH: usize = 16;

/// Address-field width for a map whose highest address is `max_addr`.
/// # C: O(1)
pub fn width_for(max_addr: u64) -> usize {
    if max_addr > u32::MAX as u64 { WIDE_WIDTH } else { NARROW_WIDTH }
}

/// Render `ranges` — each `(start, end_exclusive, label)` — in the reference's
/// `/proc/iomem` form.
///
/// The printed end is INCLUSIVE (`end - 1`): a resource in the reference is a
/// closed interval, and a parser that read an exclusive end would believe every
/// range reached one byte into the next one. Empty ranges are dropped rather
/// than printed as an inverted interval.
/// # C: O(N ranges)
pub fn render(ranges: &[(u64, u64, &str)]) -> Vec<u8> {
    let max = ranges.iter().filter(|r| r.1 > r.0).map(|r| r.1 - 1).max().unwrap_or(0);
    let w = width_for(max);
    let mut out: Vec<u8> = Vec::with_capacity(ranges.len() * 48);
    for &(start, end, label) in ranges {
        if end <= start { continue; }
        push_hex(&mut out, start, w);
        out.push(b'-');
        push_hex(&mut out, end - 1, w);
        out.extend_from_slice(b" : ");
        out.extend_from_slice(label.as_bytes());
        out.push(b'\n');
    }
    out
}

/// Zero-padded lower-case hex, `w` digits wide, without a formatter — the
/// width is chosen at run time and `write!` cannot take a dynamic one without
/// pulling in the full formatting machinery for a five-line file.
fn push_hex(out: &mut Vec<u8>, v: u64, w: usize) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [b'0'; WIDE_WIDTH];
    for i in 0..w {
        buf[w - 1 - i] = DIGITS[((v >> (4 * i)) & 0xf) as usize];
    }
    out.extend_from_slice(&buf[..w]);
}

/// The live map: every region the PMM manages, labelled as usable memory.
///
/// Only usable RAM is reported, because only usable RAM is what this kernel
/// retains past boot — the reserved, ACPI and firmware entries of the boot
/// memory map are consumed and dropped by PMM bring-up. Printing a range this
/// kernel cannot vouch for would be worse than omitting it: a loader believes
/// what it reads here, and a fabricated `reserved` entry steers a placement
/// away from memory that is fine, while a fabricated `System RAM` entry steers
/// one into memory that is not.
/// # C: O(N regions)
#[cfg(target_os = "oxide-kernel")]
pub fn body() -> Vec<u8> {
    let regions = pmm::setup::usable_regions();
    let mut ranges: Vec<(u64, u64, &str)> = Vec::with_capacity(regions.len());
    for r in regions {
        let start = r.start.0 * hal::PAGE_SIZE_BYTES;
        ranges.push((start, start + r.len_pfn * hal::PAGE_SIZE_BYTES, SYSTEM_RAM));
    }
    render(&ranges)
}

/// `/proc/iomem` inode.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn make_proc_iomem() -> vfs::InodeRef {
    crate::dyn_file::make_gen_file(crate::ids::IOMEM as vfs::Ino, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::string::String;

    fn s(v: &[u8]) -> String { String::from_utf8_lossy(v).into_owned() }

    #[test]
    fn a_range_is_printed_with_an_inclusive_end() {
        // The whole file is consumed by a parser that treats the second number
        // as the LAST byte of the range. Printing the exclusive end makes every
        // range appear one byte longer, and two adjacent ranges appear to
        // overlap — which is how a loader decides a perfectly good hole is
        // already occupied.
        let out = render(&[(0x10_0000, 0x20_0000, SYSTEM_RAM)]);
        assert_eq!(s(&out), "00100000-001fffff : System RAM\n");
    }

    #[test]
    fn the_label_is_the_exact_string_a_loader_matches() {
        let out = render(&[(0x1000, 0x2000, SYSTEM_RAM)]);
        assert!(s(&out).ends_with(" : System RAM\n"));
        assert_eq!(SYSTEM_RAM, "System RAM");
    }

    #[test]
    fn a_map_reaching_above_four_gigabytes_is_printed_sixteen_wide() {
        // Truncating a high address to eight digits does not fail to parse — it
        // parses as a DIFFERENT, low address, and the loader places a segment
        // into memory that is not there.
        let out = render(&[(0x1_0000_0000, 0x1_0001_0000, SYSTEM_RAM)]);
        assert_eq!(s(&out), "0000000100000000-000000010000ffff : System RAM\n");
        assert_eq!(width_for(u32::MAX as u64), NARROW_WIDTH);
        assert_eq!(width_for(u32::MAX as u64 + 1), WIDE_WIDTH);
    }

    #[test]
    fn one_high_range_widens_every_line_in_the_map() {
        // The width is a property of the MAP, not of each line: the reference
        // pads all of them to the same column so the file is a table.
        let out = render(&[(0x1000, 0x2000, SYSTEM_RAM),
                           (0x1_0000_0000, 0x1_0000_1000, SYSTEM_RAM)]);
        let text = s(&out);
        assert_eq!(text.lines().count(), 2);
        for line in text.lines() {
            let addr = line.split('-').next().expect("an address");
            assert_eq!(addr.len(), WIDE_WIDTH, "{line} is not padded to the map's width");
        }
    }

    #[test]
    fn an_empty_range_is_omitted_rather_than_inverted() {
        assert!(render(&[(0x1000, 0x1000, SYSTEM_RAM)]).is_empty());
        assert!(render(&[(0x2000, 0x1000, SYSTEM_RAM)]).is_empty());
    }

    #[test]
    fn an_empty_map_renders_to_nothing_and_not_to_a_blank_line() {
        assert!(render(&[]).is_empty());
    }
}
