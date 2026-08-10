use alloc::string::String;
use alloc::vec::Vec;

use crate::build::{uefi_stub_tree, Builder, EfiFirmware, UefiHandoff};
use crate::uapi::{OF_EFI_MMAP_DESC_SIZE, OF_EFI_MMAP_DESC_VER, OF_EFI_MMAP_SIZE,
                  OF_EFI_MMAP_START, OF_EFI_SYSTAB};
use crate::props::chosen_bootargs;
use crate::walk::{find_prop, walk, Event, Flow};

/// RAM as the EFI memory map reports it on this machine: several blocks, not
/// one — which is the case a single-region writer would silently truncate.
const RAM: [(u64, u64); 3] = [
    (0x4000_0000, 0x4000_0000),
    (0x8000_0000, 0x1000_0000),
    (0x1_0000_0000, 0x2000_0000),
];

/// The firmware handoff this boot retained, as the stub records it.
const FW: EfiFirmware = EfiFirmware {
    systab_pa: 0x0000_0000_bfbf_9018,
    mmap_pa: 0x0000_0000_4021_a000,
    mmap_size: 0x1518,
    desc_size: 48,
    desc_ver: 1,
};

/// The tree a boot that retained NO handoff synthesizes: RAM is all it has to
/// say, so it says it.
fn no_handoff_tree(buf: &mut [u8]) -> usize {
    uefi_stub_tree(buf, &UefiHandoff {
        bootargs: b"console=ttyAMA0 root=/dev/oxide0",
        memory: &RAM,
        firmware: None,
    }).expect("build")
}

/// The tree the arm64 UEFI stub synthesizes when firmware publishes none.
fn stub_tree(buf: &mut [u8]) -> usize {
    uefi_stub_tree(buf, &UefiHandoff {
        bootargs: b"console=ttyAMA0 root=/dev/oxide0",
        memory: &RAM,
        firmware: Some(FW),
    }).expect("build")
}

/// The whole point: what the builder writes, this crate's own reader reads
/// back. A writer tested only against itself proves nothing.
#[test]
fn the_synthesized_tree_parses_with_this_crates_reader() {
    let mut buf = [0u8; 4096];
    let n = stub_tree(&mut buf);
    let blob = &buf[..n];
    let h = crate::parse_header(blob).expect("header");
    assert_eq!(h.totalsize as usize, n, "totalsize must be the blob length");
    assert_eq!(crate::totalsize_from_prefix(&blob[..8]), Some(n));
    assert_eq!(chosen_bootargs(blob), Some(&b"console=ttyAMA0 root=/dev/oxide0"[..]));
}

#[test]
fn the_root_carries_the_standard_cell_counts() {
    let mut buf = [0u8; 4096];
    let n = stub_tree(&mut buf);
    let blob = &buf[..n];
    let root = |_n: &[u8], d: u32| d == 0;
    assert_eq!(find_prop(blob, root, b"#address-cells"), Some(&2u32.to_be_bytes()[..]));
    assert_eq!(find_prop(blob, root, b"#size-cells"), Some(&2u32.to_be_bytes()[..]));
}

/// A tree with no handoff to offer must describe RAM. A kernel handed one
/// without `/memory` — and without the EFI handoff that would substitute for
/// it — panics in early page-table setup before it can say why, which is what
/// a relocated kernel did when this node was left out.
#[test]
fn every_memory_region_reaches_the_memory_node() {
    let mut buf = [0u8; 4096];
    let n = no_handoff_tree(&mut buf);
    let blob = &buf[..n];
    let mut out = [(0u64, 0u64); 8];
    assert_eq!(crate::memory_regions(blob, &mut out), RAM.len());
    assert_eq!(&out[..RAM.len()], &RAM[..]);
    // …and the single-region reader agrees with the first of them.
    assert_eq!(crate::first_memory_region(blob), Some(RAM[0]));
}

/// A TREE CARRYING THE HANDOFF CARRIES NOTHING ELSE.
///
/// A kernel chooses between the tree and the firmware tables by asking whether
/// the tree is a stub, and any node beside `/chosen` decides it for the tree.
/// A tree holding both therefore gets the worst of the two: the firmware
/// tables ignored, and a winner that describes RAM and nothing else — no
/// processors, no interrupt controller, no timer. Measured: a relocated kernel
/// found and reported the handoff and still died with no processor to assign
/// memory to.
#[test]
fn a_tree_carrying_the_firmware_handoff_has_no_node_beside_chosen() {
    let mut buf = [0u8; 4096];
    let n = stub_tree(&mut buf);
    let mut depth1: Vec<Vec<u8>> = Vec::new();
    crate::walk(&buf[..n], |ev| {
        if let Event::BeginNode { name, depth } = ev {
            if depth == 1 { depth1.push(Vec::from(name)); }
        }
        Flow::Continue
    }).expect("walk");
    assert_eq!(depth1, alloc::vec![b"chosen".to_vec()]);
    assert_eq!(crate::first_memory_region(&buf[..n]), None,
               "the firmware map is the memory description, not this");
}

#[test]
fn the_memory_node_is_named_and_typed_the_way_a_reader_expects() {
    let mut buf = [0u8; 4096];
    let n = no_handoff_tree(&mut buf);
    let blob = &buf[..n];
    let mut name: Vec<u8> = Vec::new();
    crate::walk(blob, |ev| {
        if let Event::BeginNode { name: nm, depth } = ev {
            if depth == 1 && nm.starts_with(b"memory") { name = Vec::from(nm); }
        }
        Flow::Continue
    }).expect("walk");
    assert_eq!(name, b"memory@40000000", "unit address is lower-case hex, no leading zeros");
    let mem = |nm: &[u8], d: u32| d == 1 && nm.starts_with(b"memory");
    assert_eq!(find_prop(blob, mem, b"device_type"), Some(&b"memory\0"[..]));
}

/// The firmware handoff, at the widths a reader of these properties expects:
/// addresses two cells, sizes one. Without them the tree describes no
/// processors, no interrupt controller and no timer — everything this machine
/// puts in ACPI — and a kernel handed it dies building its zone lists.
#[test]
fn the_firmware_handoff_reaches_chosen_at_the_widths_a_reader_expects() {
    let mut buf = [0u8; 4096];
    let n = stub_tree(&mut buf);
    let blob = &buf[..n];
    let chosen = |name: &[u8], d: u32| d == 1 && name == b"chosen";
    assert_eq!(find_prop(blob, chosen, OF_EFI_SYSTAB), Some(&FW.systab_pa.to_be_bytes()[..]));
    assert_eq!(find_prop(blob, chosen, OF_EFI_MMAP_START), Some(&FW.mmap_pa.to_be_bytes()[..]));
    assert_eq!(find_prop(blob, chosen, OF_EFI_MMAP_SIZE), Some(&FW.mmap_size.to_be_bytes()[..]));
    assert_eq!(find_prop(blob, chosen, OF_EFI_MMAP_DESC_SIZE),
               Some(&FW.desc_size.to_be_bytes()[..]));
    assert_eq!(find_prop(blob, chosen, OF_EFI_MMAP_DESC_VER),
               Some(&FW.desc_ver.to_be_bytes()[..]));
    // Widths, stated as such: a size written two cells wide reads back as its
    // own high half, which is zero.
    assert_eq!(find_prop(blob, chosen, OF_EFI_SYSTAB).map(<[u8]>::len), Some(8));
    assert_eq!(find_prop(blob, chosen, OF_EFI_MMAP_SIZE).map(<[u8]>::len), Some(4));
}

/// ALL FIVE OR NONE. A tree advertising the system table without the map makes
/// the next kernel take the firmware path and then demand a map that is not
/// there; measured, it panicked in early page-table setup. A boot that
/// retained nothing writes none of the five rather than the ones it happens to
/// know.
#[test]
fn a_boot_that_retained_no_handoff_advertises_none_of_it() {
    let mut buf = [0u8; 4096];
    let n = uefi_stub_tree(&mut buf, &UefiHandoff {
        bootargs: b"console=ttyAMA0", memory: &RAM, firmware: None,
    }).expect("build");
    let blob = &buf[..n];
    let chosen = |name: &[u8], d: u32| d == 1 && name == b"chosen";
    for p in [OF_EFI_SYSTAB, OF_EFI_MMAP_START, OF_EFI_MMAP_SIZE,
              OF_EFI_MMAP_DESC_SIZE, OF_EFI_MMAP_DESC_VER] {
        assert_eq!(find_prop(blob, chosen, p), None, "{}", String::from_utf8_lossy(p));
    }
    // …and the tree is still a tree, with the command line it was given.
    assert_eq!(chosen_bootargs(blob), Some(&b"console=ttyAMA0"[..]));
}

#[test]
fn a_machine_with_no_reported_ram_gets_no_memory_node() {
    let mut buf = [0u8; 4096];
    let n = uefi_stub_tree(&mut buf, &UefiHandoff { bootargs: b"x", memory: &[], firmware: None })
        .expect("build");
    assert_eq!(crate::first_memory_region(&buf[..n]), None);
}

#[test]
fn a_buffer_too_small_yields_nothing_rather_than_a_partial_blob() {
    for size in [0usize, 8, 40, 48, 64] {
        let mut buf = alloc::vec![0u8; size];
        assert!(uefi_stub_tree(&mut buf, &UefiHandoff {
            bootargs: b"console=ttyAMA0", memory: &RAM, firmware: None,
        }).is_none(), "size {size}");
    }
}

#[test]
fn an_unclosed_node_is_refused() {
    let mut buf = [0u8; 256];
    let mut b = Builder::new(&mut buf);
    b.begin_node(b"").begin_node(b"kid").end_node();
    assert!(b.finish().is_none(), "the root is still open");
}

#[test]
fn a_repeated_property_name_reuses_one_strings_entry() {
    let mut buf = [0u8; 512];
    let n = {
        let mut b = Builder::new(&mut buf);
        b.begin_node(b"");
        b.prop_u32(b"reg", 1);
        b.begin_node(b"a").prop_u32(b"reg", 2).end_node();
        b.begin_node(b"c").prop_u32(b"reg", 3).end_node();
        b.end_node();
        b.finish().expect("build")
    };
    let h = crate::parse_header(&buf[..n]).expect("header");
    assert_eq!(h.size_dt_strings, 4, "\"reg\\0\" stored once, not three times");
    // …and all three values still read back distinctly.
    let mut seen: Vec<u32> = Vec::new();
    walk(&buf[..n], |ev| {
        if let Event::Prop { name, data, .. } = ev {
            if name == b"reg" { seen.push(u32::from_be_bytes(data.try_into().unwrap())); }
        }
        Flow::Continue
    }).expect("walk");
    assert_eq!(seen, alloc::vec![1, 2, 3]);
}

/// Names must not run into each other in the scratch: overflowing it has to
/// fail the build rather than silently rename a property.
#[test]
fn overflowing_the_string_scratch_fails_the_build() {
    let mut buf = [0u8; 8192];
    let mut b = Builder::new(&mut buf);
    b.begin_node(b"");
    for i in 0..64u32 {
        let name = alloc::format!("property-name-number-{i:03}");
        b.prop_u32(name.as_bytes(), i);
    }
    b.end_node();
    assert!(b.finish().is_none());
}

/// The memory reservation block is mandatory even when it reserves nothing.
/// A header pointing at offset 0 parses under a lenient reader and is refused
/// by a strict one — which is exactly how a synthesized tree looked healthy
/// inside this kernel and made the kexec loader refuse it two layers away.
#[test]
fn the_blob_carries_a_terminated_memory_reservation_block() {
    let mut buf = [0u8; 4096];
    let n = stub_tree(&mut buf);
    let h = crate::parse_header(&buf[..n]).expect("header");
    assert_eq!(h.off_mem_rsvmap as usize, crate::FDT_HEADER_LEN,
        "the block sits immediately after the header");
    assert!(h.off_mem_rsvmap >= crate::FDT_HEADER_LEN as u32,
        "a stricter reader requires the block not to overlap the header");
    let rsv = h.off_mem_rsvmap as usize;
    assert_eq!(&buf[rsv..rsv + crate::FDT_RSVMAP_ENTRY_LEN], &[0u8; 16],
        "one all-zero entry terminates an empty block");
    assert_eq!(h.off_dt_struct as usize, rsv + crate::FDT_RSVMAP_ENTRY_LEN,
        "the struct block starts after the reservation block");
}
