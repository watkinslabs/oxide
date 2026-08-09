// Handover provenance: what `/chosen` says to the new kernel, and what it no
// longer says about this one.

use super::*;
use crate::file_load::arm_image::fdt::{parse, Fdt, Node, Prop};
use alloc::vec;

/// A tree shaped like one a running kernel booted from: a `/chosen` carrying
/// this boot's initramfs, command line, crash properties and seeds, plus the
/// reservations that go with them.
fn booted_tree() -> Fdt {
    let mut chosen = Node::new(b"chosen");
    chosen.props.push(Prop { name: P_INITRD_START.to_vec(), val: 0x4800_0000u64.to_be_bytes().to_vec() });
    chosen.props.push(Prop { name: P_INITRD_END.to_vec(), val: 0x4801_0000u64.to_be_bytes().to_vec() });
    chosen.props.push(Prop { name: P_BOOTARGS.to_vec(), val: b"console=ttyAMA0 old\0".to_vec() });
    chosen.props.push(Prop { name: P_ELFCOREHDR.to_vec(), val: vec![0; 16] });
    chosen.props.push(Prop { name: P_USABLE_MEMORY_RANGE.to_vec(), val: vec![0; 16] });
    chosen.props.push(Prop { name: P_KASLR_SEED.to_vec(), val: 0xdead_beefu64.to_be_bytes().to_vec() });
    chosen.props.push(Prop { name: P_RNG_SEED.to_vec(), val: vec![0xa5; RNG_SEED_SIZE] });

    let mut root = Node::new(b"");
    root.children.push(chosen);
    Fdt {
        boot_cpuid_phys: 0,
        // The running tree's own reservation, and this boot's initramfs.
        rsv: vec![(0x4000_0000, 0x2000), (0x4800_0000, 0x1_0000)],
        root,
    }
}

fn base() -> alloc::vec::Vec<u8> { booted_tree().to_blob() }

fn ho<'a>(initrd_mem: u64, initrd_len: u64, cmdline: &'a [u8]) -> Handover<'a> {
    Handover { initrd_mem, initrd_len, cmdline, old_fdt_pa: 0, old_fdt_len: 0, seeds: None }
}

fn chosen_of(blob: &[u8]) -> Node {
    parse(blob).expect("parses").node(CHOSEN_PATH).expect("/chosen").clone()
}

#[test]
fn the_new_initramfs_is_written_as_a_start_and_an_end_both_eight_bytes_wide() {
    // The end is start PLUS LENGTH, not the length: a tree that put the
    // length in `linux,initrd-end` hands the new kernel an initramfs that
    // starts after it ends, and the new kernel drops it silently.
    let out = setup_fdt(&base(), &ho(0x9000_0000, 0x20_0000, b"quiet")).expect("built");
    let c = chosen_of(&out);
    assert_eq!(c.prop(P_INITRD_START), Some(&0x9000_0000u64.to_be_bytes()[..]));
    assert_eq!(c.prop(P_INITRD_END), Some(&0x9020_0000u64.to_be_bytes()[..]));
    assert_eq!(c.prop(P_INITRD_START).unwrap().len(), 8);
}

#[test]
fn a_load_with_no_initramfs_deletes_both_properties_rather_than_leaving_this_boots() {
    // Leaving them is the dangerous outcome: the addresses name memory the new
    // kernel's own segments now occupy.
    let out = setup_fdt(&base(), &ho(0, 0, b"quiet")).expect("built");
    let c = chosen_of(&out);
    assert_eq!(c.prop(P_INITRD_START), None);
    assert_eq!(c.prop(P_INITRD_END), None);
}

#[test]
fn the_initramfs_reservation_follows_the_initramfs() {
    let out = setup_fdt(&base(), &ho(0x9000_0000, 0x20_0000, b"quiet")).expect("built");
    let t = parse(&out).expect("parses");
    assert!(t.rsv.contains(&(0x9000_0000, 0x20_0000)), "the new initramfs is not reserved");
    assert!(!t.rsv.contains(&(0x4800_0000, 0x1_0000)),
            "this boot's initramfs reservation was carried forward");
    // With no initramfs, the old reservation still goes and no new one comes.
    let out = setup_fdt(&base(), &ho(0, 0, b"quiet")).expect("built");
    let t = parse(&out).expect("parses");
    assert!(!t.rsv.iter().any(|&(a, _)| a == 0x4800_0000));
}

#[test]
fn a_firmware_reservation_rounded_to_a_page_is_still_found() {
    // Firmware reserves the page-rounded extent; kexec reserves the exact
    // length. A handover that only tried the exact spelling leaves a stale
    // reservation over memory the new kernel then refuses to use.
    let mut t = booted_tree();
    // An extent that is not a whole number of pages, reserved page-rounded.
    let exact = 0x1_0001u64;
    let rounded = exact.div_ceil(crate::uapi::PAGE_SIZE) * crate::uapi::PAGE_SIZE;
    assert_ne!(exact, rounded);
    t.node_or_add(CHOSEN_PATH).set_prop_u64(P_INITRD_END, 0x4800_0000 + exact);
    t.rsv = vec![(0x4800_0000, rounded)];
    let out = setup_fdt(&t.to_blob(), &ho(0, 0, b"")).expect("built");
    assert!(parse(&out).expect("parses").rsv.is_empty(),
            "the page-rounded reservation survived");
}

#[test]
fn the_command_line_is_a_nul_terminated_string_and_an_empty_one_deletes_the_property() {
    let out = setup_fdt(&base(), &ho(0, 0, b"root=/dev/vda1 ro")).expect("built");
    assert_eq!(chosen_of(&out).prop(P_BOOTARGS), Some(&b"root=/dev/vda1 ro\0"[..]));
    // Empty means "the caller gave no command line", which deletes rather
    // than inheriting this boot's — the new kernel must not silently run with
    // arguments meant for the old one.
    let out = setup_fdt(&base(), &ho(0, 0, b"")).expect("built");
    assert_eq!(chosen_of(&out).prop(P_BOOTARGS), None);
}

#[test]
fn this_boots_crash_properties_are_deleted() {
    let out = setup_fdt(&base(), &ho(0, 0, b"quiet")).expect("built");
    let c = chosen_of(&out);
    assert_eq!(c.prop(P_ELFCOREHDR), None);
    assert_eq!(c.prop(P_USABLE_MEMORY_RANGE), None);
}

#[test]
fn the_kexec_marker_is_present_and_empty() {
    let out = setup_fdt(&base(), &ho(0, 0, b"quiet")).expect("built");
    let c = chosen_of(&out);
    assert_eq!(c.prop(P_BOOTED_FROM_KEXEC), Some(&b""[..]));
}

#[test]
fn a_stale_seed_is_removed_and_a_fresh_one_written_only_when_there_is_one() {
    // Carrying this boot's seed forward is worse than having none: the new
    // kernel's KASLR offset becomes predictable to anyone who saw this boot.
    let out = setup_fdt(&base(), &ho(0, 0, b"quiet")).expect("built");
    let c = chosen_of(&out);
    assert_eq!(c.prop(P_KASLR_SEED), None);
    assert_eq!(c.prop(P_RNG_SEED), None);

    let mut h = ho(0, 0, b"quiet");
    h.seeds = Some(Seeds { kaslr: 0x0102_0304_0506_0708, rng: [7u8; RNG_SEED_SIZE] });
    let out = setup_fdt(&base(), &h).expect("built");
    let c = chosen_of(&out);
    assert_eq!(c.prop(P_KASLR_SEED), Some(&0x0102_0304_0506_0708u64.to_be_bytes()[..]));
    assert_eq!(c.prop(P_RNG_SEED).map(|v| v.len()), Some(RNG_SEED_SIZE));
    assert_ne!(c.prop(P_RNG_SEED), Some(&[0xa5u8; RNG_SEED_SIZE][..]));
}

#[test]
fn a_tree_with_no_chosen_node_gets_one() {
    let mut t = booted_tree();
    t.root.children.clear();
    let out = setup_fdt(&t.to_blob(), &ho(0x9000_0000, 0x1000, b"quiet")).expect("built");
    let c = chosen_of(&out);
    assert_eq!(c.prop(P_INITRD_START), Some(&0x9000_0000u64.to_be_bytes()[..]));
}

#[test]
fn the_running_trees_own_reservation_is_dropped_when_its_address_is_known() {
    let mut h = ho(0, 0, b"quiet");
    h.old_fdt_pa = 0x4000_0000;
    h.old_fdt_len = 0x2000;
    let out = setup_fdt(&base(), &h).expect("built");
    assert!(!parse(&out).expect("parses").rsv.contains(&(0x4000_0000, 0x2000)));
    // Without the address it stays — which is a gap, not a decision, and the
    // one `running_fdt` names.
    let out = setup_fdt(&base(), &ho(0, 0, b"quiet")).expect("built");
    assert!(parse(&out).expect("parses").rsv.contains(&(0x4000_0000, 0x2000)));
}

#[test]
fn a_start_without_an_end_is_a_tree_whose_initramfs_extent_cannot_be_computed() {
    let mut t = booted_tree();
    t.node_or_add(CHOSEN_PATH).del_prop(P_INITRD_END);
    assert_eq!(setup_fdt(&t.to_blob(), &ho(0, 0, b"")).err(), Some(Error::Inval));
}

#[test]
fn a_number_is_read_as_however_many_cells_the_property_holds() {
    // Firmware writes one cell, kexec writes two. Assuming either width reads
    // the wrong address on the other kind of tree.
    assert_eq!(read_number(&0x1234_5678u32.to_be_bytes()), Some(0x1234_5678));
    assert_eq!(read_number(&0x1_0000_0000u64.to_be_bytes()), Some(0x1_0000_0000));
    assert_eq!(read_number(&[]), None);
    assert_eq!(read_number(&[1, 2, 3]), None);
    assert_eq!(read_number(&[0u8; 12]), None);
}

#[test]
fn the_tree_length_does_not_depend_on_the_initramfs_address() {
    // The sizing pass in `assemble` rests on this: an address is eight bytes
    // whatever it holds, so a tree built with a placeholder is the same LENGTH
    // as the one built with the real placement. If this ever stopped being
    // true, the device-tree segment would reserve the wrong byte count.
    let a = setup_fdt(&base(), &ho(1 << 40, 0x20_0000, b"quiet")).expect("built");
    let b = setup_fdt(&base(), &ho(0x9000_0000, 0x20_0000, b"quiet")).expect("built");
    assert_eq!(a.len(), b.len());
    // And it DOES depend on whether there is an initramfs at all, which is
    // why the placeholder must be non-zero.
    let none = setup_fdt(&base(), &ho(0, 0, b"quiet")).expect("built");
    assert_ne!(none.len(), a.len());
}

#[test]
fn a_base_that_is_not_a_device_tree_is_refused() {
    assert_eq!(setup_fdt(&[], &ho(0, 0, b"")).err(), Some(Error::Inval));
    assert_eq!(setup_fdt(b"not a tree at all, not even close....", &ho(0, 0, b"")).err(),
               Some(Error::Inval));
}
