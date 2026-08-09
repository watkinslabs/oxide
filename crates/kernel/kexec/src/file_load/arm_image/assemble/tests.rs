// End-to-end load provenance: the segment list, the blob it cuts from, and
// the tree the new kernel is actually handed.

use super::*;
use crate::file_load::arm_image::fdt::{parse, Fdt, Node};
use crate::file_load::arm_image::handover::{P_BOOTARGS, P_INITRD_END, P_INITRD_START,
                                            CHOSEN_PATH};
use crate::file_load::arm_image::place::MIN_KIMG_ALIGN;
use crate::file_load::FileImage;
use alloc::vec;
use alloc::vec::Vec;

const MIB: u64 = 1024 * 1024;
const IMAGE_SIZE: u64 = 8 * MIB;
const TEXT_OFFSET: u64 = 0;

fn image_bytes(len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len.max(header::HDR_SIZE)];
    b[header::OFF_TEXT_OFFSET..header::OFF_TEXT_OFFSET + 8]
        .copy_from_slice(&TEXT_OFFSET.to_le_bytes());
    b[header::OFF_IMAGE_SIZE..header::OFF_IMAGE_SIZE + 8]
        .copy_from_slice(&IMAGE_SIZE.to_le_bytes());
    b[header::OFF_FLAGS..header::OFF_FLAGS + 8]
        .copy_from_slice(&(header::FLAG_PAGE_SIZE_4K << header::FLAG_PAGE_SIZE_SHIFT)
                         .to_le_bytes());
    b[header::OFF_MAGIC..header::OFF_MAGIC + 4].copy_from_slice(&header::IMAGE_MAGIC);
    // A byte pattern past the header, so a segment that copied the wrong
    // bytes is visible rather than merely the right length.
    for (i, x) in b.iter_mut().enumerate().skip(header::HDR_SIZE) { *x = (i % 251) as u8; }
    b
}

fn base_tree() -> Vec<u8> {
    let mut root = Node::new(b"");
    root.children.push(Node::new(b"chosen"));
    Fdt { boot_cpuid_phys: 0, rsv: Vec::new(), root }.to_blob()
}

fn img(initrd: Vec<u8>, cmdline: &[u8]) -> FileImage {
    let mut c = cmdline.to_vec();
    c.push(0);
    FileImage { kernel: image_bytes(4 * MIB as usize), initrd, cmdline: c }
}

const RAM: [(u64, u64); 1] = [(MIB, 2 * 1024 * MIB)];

#[test]
fn a_load_produces_a_kernel_an_initramfs_and_a_tree_and_nothing_else() {
    // NO PURGATORY. arm64's file load enters the new kernel directly, so a
    // fourth segment here would be a stage nothing starts.
    let i = img(vec![0x5au8; 1024 * 1024], b"console=ttyAMA0");
    let tree = base_tree();
    let ctx = LoadCtx { img: &i, ram: &RAM, fdt: &tree };
    let l = load(&ctx).expect("a 2 GiB machine fits everything");
    assert_eq!(l.segments.len(), 3);
    assert_eq!(l.entry % MIN_KIMG_ALIGN, 0);
    assert_eq!(l.entry, l.segments[0].mem);
    assert_ne!(l.boot_arg, 0);
    assert_eq!(l.boot_arg, l.segments[2].mem);
}

#[test]
fn every_segments_bytes_are_the_bytes_it_names_at_the_offset_it_names() {
    // `buf` is an offset into `blob`; an offset that is one segment out
    // produces an image that stages cleanly and boots into the initramfs.
    let initrd = vec![0x5au8; 4096 * 3 + 7];
    let i = img(initrd.clone(), b"quiet");
    let tree = base_tree();
    let ctx = LoadCtx { img: &i, ram: &RAM, fdt: &tree };
    let l = load(&ctx).expect("fits");
    let cut = |n: usize| -> &[u8] {
        let s = &l.segments[n];
        &l.blob[s.buf as usize..s.buf as usize + s.bufsz as usize]
    };
    assert_eq!(cut(0), &i.kernel[..]);
    assert_eq!(cut(1), &initrd[..]);
    let dtb = cut(2);
    assert_eq!(parse(dtb).expect("the third segment is a tree").node(CHOSEN_PATH)
                   .and_then(|c| c.prop(P_BOOTARGS)),
               Some(&b"quiet\0"[..]));
}

#[test]
fn the_tree_names_the_address_the_initramfs_was_actually_placed_at() {
    // The two-pass build is where this goes wrong: a tree built with the
    // sizing placeholder and never rebuilt points the new kernel at an
    // address 1 TiB up, which is not memory.
    let i = img(vec![0x11u8; 64 * 1024], b"quiet");
    let tree = base_tree();
    let ctx = LoadCtx { img: &i, ram: &RAM, fdt: &tree };
    let l = load(&ctx).expect("fits");
    let s = &l.segments[2];
    let t = parse(&l.blob[s.buf as usize..s.buf as usize + s.bufsz as usize]).expect("a tree");
    let c = t.node(CHOSEN_PATH).expect("/chosen");
    let start = u64::from_be_bytes(c.prop(P_INITRD_START).expect("start").try_into().unwrap());
    let end = u64::from_be_bytes(c.prop(P_INITRD_END).expect("end").try_into().unwrap());
    assert_ne!(start, SIZING_INITRD_ADDR, "the sizing placeholder reached the new kernel");
    assert_eq!(start, l.segments[1].mem);
    assert_eq!(end - start, i.initrd.len() as u64);
    assert!(t.rsv.contains(&(start, i.initrd.len() as u64)));
}

#[test]
fn a_load_with_no_initramfs_has_two_segments_and_a_tree_that_says_so() {
    let i = img(Vec::new(), b"quiet");
    let tree = base_tree();
    let ctx = LoadCtx { img: &i, ram: &RAM, fdt: &tree };
    let l = load(&ctx).expect("fits");
    assert_eq!(l.segments.len(), 2);
    assert_eq!(l.boot_arg, l.segments[1].mem);
    let s = &l.segments[1];
    let t = parse(&l.blob[s.buf as usize..s.buf as usize + s.bufsz as usize]).expect("a tree");
    assert!(t.node(CHOSEN_PATH).unwrap().prop(P_INITRD_START).is_none());
}

#[test]
fn a_machine_with_no_device_tree_refuses_rather_than_inventing_one() {
    // This is the state this port is in today: nothing publishes the boot
    // DTB, so `running_fdt` is empty and the load cannot proceed. Refusing is
    // the reference's own answer when it cannot build a tree.
    let i = img(Vec::new(), b"quiet");
    let ctx = LoadCtx { img: &i, ram: &RAM, fdt: &[] };
    assert_eq!(load(&ctx).err(), Some(Error::Inval));
}

#[test]
fn a_file_that_is_not_an_image_is_refused_before_anything_is_placed() {
    let mut i = img(Vec::new(), b"quiet");
    i.kernel[header::OFF_MAGIC] ^= 0xff;
    let tree = base_tree();
    let ctx = LoadCtx { img: &i, ram: &RAM, fdt: &tree };
    assert_eq!(load(&ctx).err(), Some(Error::Inval));
}

#[test]
fn a_machine_too_small_for_the_image_reports_no_address() {
    let i = img(Vec::new(), b"quiet");
    let tree = base_tree();
    let small = [(MIB, 4 * MIB)];
    let ctx = LoadCtx { img: &i, ram: &small, fdt: &tree };
    assert_eq!(load(&ctx).err(), Some(Error::AddrNotAvail));
}
