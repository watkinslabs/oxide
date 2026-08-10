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

/// Label the reserved crash-kernel window carries. `kexec -p` looks this
/// string up before it will stage anything: with no line carrying it, the
/// loader concludes no crash region was reserved and refuses, whatever
/// `crashkernel=` actually did at boot.
pub const CRASH_KERNEL: &str = "Crash kernel";

/// Spaces one nesting level indents a resource line by.
pub const INDENT: usize = 2;

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

/// One resource line: a half-open physical range, its label, and how deeply it
/// nests inside the resource above it.
///
/// Depth is not decoration. A region carved out of usable memory is a CHILD of
/// the `System RAM` line that contains it, and the reserved crash window is
/// exactly that; a loader walking the file tracks the nesting to decide which
/// ranges it may place into and which are already claimed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Res<'a> {
    pub start: u64,
    /// Exclusive. The rendered end is `end - 1`.
    pub end: u64,
    pub label: &'a str,
    pub depth: u8,
}

/// Render `ranges` — each `(start, end_exclusive, label)` — at the top level.
/// # C: O(N ranges)
pub fn render(ranges: &[(u64, u64, &str)]) -> Vec<u8> {
    let rs: Vec<Res> = ranges.iter().map(|&(start, end, label)| Res { start, end, label, depth: 0 }).collect();
    render_tree(&rs)
}

/// Render a resource tree in the reference's `/proc/iomem` form.
///
/// The printed end is INCLUSIVE (`end - 1`): a resource in the reference is a
/// closed interval, and a parser that read an exclusive end would believe every
/// range reached one byte into the next one. Empty ranges are dropped rather
/// than printed as an inverted interval. The address field is padded to one
/// width for the whole map and the indent goes BEFORE it, so the columns stay
/// a table.
/// # C: O(N ranges)
pub fn render_tree(ranges: &[Res]) -> Vec<u8> {
    let max = ranges.iter().filter(|r| r.end > r.start).map(|r| r.end - 1).max().unwrap_or(0);
    let w = width_for(max);
    let mut out: Vec<u8> = Vec::with_capacity(ranges.len() * 48);
    for r in ranges {
        if r.end <= r.start { continue; }
        for _ in 0..(r.depth as usize * INDENT) { out.push(b' '); }
        push_hex(&mut out, r.start, w);
        out.push(b'-');
        push_hex(&mut out, r.end - 1, w);
        out.extend_from_slice(b" : ");
        out.extend_from_slice(r.label.as_bytes());
        out.push(b'\n');
    }
    out
}

/// Splice the reserved crash window into `ram` as a child of whichever usable
/// range contains it, preserving address order.
///
/// A window that no reported range contains is dropped rather than printed at
/// the top level: the only way that happens is the reservation and the map
/// disagreeing, and a `Crash kernel` line floating outside every `System RAM`
/// line would send a loader to place segments into memory this kernel cannot
/// vouch for. Nothing reserved (`size == 0`) leaves the map untouched, which is
/// what a machine booted without `crashkernel=` must show.
/// # C: O(N ranges)
pub fn with_crash_kernel(ram: &[(u64, u64)], base: u64, size: u64) -> Vec<Res<'static>> {
    let mut out: Vec<Res<'static>> = Vec::with_capacity(ram.len() + 1);
    let end = base.saturating_add(size);
    for &(start, stop) in ram {
        out.push(Res { start, end: stop, label: SYSTEM_RAM, depth: 0 });
        if size != 0 && base >= start && end <= stop {
            out.push(Res { start: base, end, label: CRASH_KERNEL, depth: 1 });
        }
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
    let mut ram: Vec<(u64, u64)> = Vec::with_capacity(regions.len());
    for r in regions {
        let start = r.start.0 * hal::PAGE_SIZE_BYTES;
        ram.push((start, start + r.len_pfn * hal::PAGE_SIZE_BYTES));
    }
    render_tree(&with_crash_kernel(&ram, kexec::crashk::crash_base(), kexec::crashk::crash_size()))
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

    #[test]
    fn the_reserved_crash_window_is_a_child_of_the_range_that_contains_it() {
        // A crash load reads this file to learn where it may place segments.
        // Without the line the loader concludes nothing was reserved and
        // refuses, on a machine whose boot line reserved 256 MiB.
        let out = render_tree(&with_crash_kernel(&[(0x10_0000, 0x8000_0000)], 0x3000_0000, 0x1000_0000));
        assert_eq!(s(&out),
            "00100000-7fffffff : System RAM\n  \
             30000000-3fffffff : Crash kernel\n");
        assert_eq!(CRASH_KERNEL, "Crash kernel");
    }

    #[test]
    fn nothing_reserved_leaves_the_map_exactly_as_it_was() {
        let ram = [(0x10_0000u64, 0x8000_0000u64)];
        assert_eq!(render_tree(&with_crash_kernel(&ram, 0, 0)),
                   render(&[(0x10_0000, 0x8000_0000, SYSTEM_RAM)]));
    }

    #[test]
    fn a_window_outside_every_reported_range_is_dropped_rather_than_floated() {
        // The reservation and the map disagreeing is the only way this
        // happens, and a top-level `Crash kernel` line would send a loader to
        // place segments into memory this kernel cannot vouch for.
        let out = render_tree(&with_crash_kernel(&[(0x10_0000, 0x2000_0000)], 0x3000_0000, 0x1000_0000));
        assert!(!s(&out).contains(CRASH_KERNEL), "{}", s(&out));
    }

    #[test]
    fn the_child_lands_inside_its_own_parent_and_not_the_first_range() {
        let out = render_tree(&with_crash_kernel(
            &[(0x1000, 0x2000), (0x1_0000_0000, 0x2_0000_0000)], 0x1_1000_0000, 0x1000_0000));
        let text = s(&out);
        let lines: std::vec::Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[2].trim_start().starts_with("0000000110000000-"), "{:?}", lines);
        assert!(lines[2].starts_with("  "), "the child must be indented: {:?}", lines);
    }

    #[test]
    fn the_indent_precedes_the_address_so_the_columns_stay_a_table() {
        // The reference prints the indent, then pads the address to the map's
        // width. Padding first and indenting after would push every child's
        // address out of the column a parser reads.
        let out = render_tree(&[Res { start: 0x1000, end: 0x2000, label: CRASH_KERNEL, depth: 1 }]);
        assert_eq!(s(&out), "  00001000-00001fff : Crash kernel\n");
    }
}
