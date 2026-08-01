// Which mappings a dump contains. Each rung of the ladder is pinned here,
// including the order between rungs: an earlier rule that matches settles the
// question, so a reordering that changes which pages reach a debugger fails a
// test rather than shipping quietly.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use vmm::coredump_filter::CoredumpFilter as F;
use hal::UserVirtAddr;
use vmm::{FileBacking, FileBackingError, SharedFrame, Vma, VmaBacking, VmaFlags, VmaProt};

use crate::coredump::filter::{
    describe_vma, dump_size, resolve_elf_probe, vma_dump_verdict, VmaDumpDesc, VmaDumpVerdict, ELF_MAGIC,
    PAGE_BYTES,
};

use VmaDumpVerdict::{ElfProbe, FirstPage, Skipped, Whole};

const VMA_START: u64 = 0x1000_0000;
const VMA_LEN: u64 = 4 * PAGE_BYTES;

fn desc() -> VmaDumpDesc {
    VmaDumpDesc { start: VMA_START, end: VMA_START + VMA_LEN, ..VmaDumpDesc::default() }
}

/// Private, file-backed, never written to, mapped from offset zero and
/// readable: the mapping the header-page rules apply to.
fn mapped_head() -> VmaDumpDesc {
    VmaDumpDesc { file_backed: true, pgoff_zero: true, readable: true, ..desc() }
}

// --- one bit at a time -------------------------------------------------

#[test]
fn anon_private_bit_gates_a_written_anonymous_mapping() {
    let d = VmaDumpDesc { anon_vma: true, ..desc() };
    assert_eq!(vma_dump_verdict(&d, F::empty()), Skipped);
    assert_eq!(vma_dump_verdict(&d, F::ANON_PRIVATE), Whole);
}

#[test]
fn anon_shared_bit_gates_a_shared_mapping_with_no_directory_entry() {
    let d = VmaDumpDesc { shared: true, unlinked_backing: true, ..desc() };
    assert_eq!(vma_dump_verdict(&d, F::empty()), Skipped);
    assert_eq!(vma_dump_verdict(&d, F::ANON_SHARED), Whole);
    // The other shared bit does not reach it.
    assert_eq!(vma_dump_verdict(&d, F::MAPPED_SHARED), Skipped);
}

#[test]
fn mapped_shared_bit_gates_a_shared_mapping_of_a_named_object() {
    let d = VmaDumpDesc { shared: true, file_backed: true, unlinked_backing: false, ..desc() };
    assert_eq!(vma_dump_verdict(&d, F::empty()), Skipped);
    assert_eq!(vma_dump_verdict(&d, F::MAPPED_SHARED), Whole);
    assert_eq!(vma_dump_verdict(&d, F::ANON_SHARED), Skipped);
}

#[test]
fn mapped_private_bit_gates_a_whole_private_file_mapping() {
    let d = mapped_head();
    assert_eq!(vma_dump_verdict(&d, F::empty()), Skipped);
    assert_eq!(vma_dump_verdict(&d, F::MAPPED_PRIVATE), Whole);
}

#[test]
fn elf_headers_bit_alone_yields_only_the_identifying_page() {
    let exe = VmaDumpDesc { backing_executable: true, ..mapped_head() };
    assert_eq!(vma_dump_verdict(&exe, F::empty()), Skipped);
    assert_eq!(vma_dump_verdict(&exe, F::ELF_HEADERS), FirstPage);
}

#[test]
fn hugetlb_bits_gate_huge_mappings_by_sharing() {
    let private = VmaDumpDesc { hugetlb: true, ..desc() };
    let shared = VmaDumpDesc { hugetlb: true, shared: true, ..desc() };
    assert_eq!(vma_dump_verdict(&private, F::HUGETLB_PRIVATE), Whole);
    assert_eq!(vma_dump_verdict(&private, F::HUGETLB_SHARED), Skipped);
    assert_eq!(vma_dump_verdict(&shared, F::HUGETLB_SHARED), Whole);
    assert_eq!(vma_dump_verdict(&shared, F::HUGETLB_PRIVATE), Skipped);
}

#[test]
fn dax_bits_gate_persistent_memory_mappings_by_sharing() {
    let private = VmaDumpDesc { dax: true, ..desc() };
    let shared = VmaDumpDesc { dax: true, shared: true, ..desc() };
    assert_eq!(vma_dump_verdict(&private, F::DAX_PRIVATE), Whole);
    assert_eq!(vma_dump_verdict(&private, F::DAX_SHARED), Skipped);
    assert_eq!(vma_dump_verdict(&shared, F::DAX_SHARED), Whole);
    assert_eq!(vma_dump_verdict(&shared, F::DAX_PRIVATE), Skipped);
}

/// Persistent memory and huge pages answer only to their own pair. A filter
/// with every ordinary bit set must still leave them out.
#[test]
fn special_memory_kinds_ignore_the_ordinary_class_bits() {
    let every_ordinary = F::ANON_PRIVATE | F::ANON_SHARED | F::MAPPED_PRIVATE | F::MAPPED_SHARED | F::ELF_HEADERS;
    for base in [VmaDumpDesc { dax: true, ..desc() }, VmaDumpDesc { hugetlb: true, ..desc() }] {
        for shared in [false, true] {
            let d = VmaDumpDesc { shared, anon_vma: true, file_backed: true, ..base };
            assert_eq!(vma_dump_verdict(&d, every_ordinary), Skipped);
        }
    }
}

// --- the default filter ------------------------------------------------

#[test]
fn the_default_filter_takes_anonymous_memory_and_leaves_file_images_behind() {
    let f = F::DEFAULT;
    assert_eq!(vma_dump_verdict(&VmaDumpDesc { anon_vma: true, ..desc() }, f), Whole);
    assert_eq!(vma_dump_verdict(&VmaDumpDesc { shared: true, unlinked_backing: true, ..desc() }, f), Whole);
    assert_eq!(vma_dump_verdict(&VmaDumpDesc { hugetlb: true, ..desc() }, f), Whole);
    assert_eq!(vma_dump_verdict(&VmaDumpDesc { hugetlb: true, shared: true, ..desc() }, f), Skipped);
    // A named shared file mapping is somebody else's data, still on disk.
    assert_eq!(
        vma_dump_verdict(&VmaDumpDesc { shared: true, file_backed: true, ..desc() }, f), Skipped);
    // A private file mapping contributes its identifying page, not its image.
    assert_eq!(vma_dump_verdict(&VmaDumpDesc { backing_executable: true, ..mapped_head() }, f), FirstPage);
    assert_eq!(vma_dump_verdict(&mapped_head(), f), ElfProbe);
}

// --- exclusions --------------------------------------------------------

#[test]
fn a_mapping_the_process_excluded_is_left_out_whatever_the_filter_says() {
    let every_bit = F::all();
    for base in [
        VmaDumpDesc { anon_vma: true, ..desc() },
        VmaDumpDesc { shared: true, unlinked_backing: true, ..desc() },
        VmaDumpDesc { shared: true, file_backed: true, ..desc() },
        VmaDumpDesc { dax: true, ..desc() },
        VmaDumpDesc { hugetlb: true, ..desc() },
        VmaDumpDesc { backing_executable: true, ..mapped_head() },
    ] {
        assert_eq!(vma_dump_verdict(&base, every_bit), Whole, "control");
        assert_eq!(vma_dump_verdict(&VmaDumpDesc { dontdump: true, ..base }, every_bit), Skipped);
    }
}

/// The exclusion loses to the kernel-provided mappings, which come first: a
/// process cannot drop the vDSO out of its own dump.
#[test]
fn a_kernel_provided_mapping_outranks_the_exclusion_and_an_empty_filter() {
    let d = VmaDumpDesc { always_dump: true, dontdump: true, io: true, ..desc() };
    assert_eq!(vma_dump_verdict(&d, F::empty()), Whole);
}

#[test]
fn device_memory_is_never_copied_into_a_dump() {
    let d = VmaDumpDesc { io: true, anon_vma: true, file_backed: true, shared: true, ..desc() };
    assert_eq!(vma_dump_verdict(&d, F::all()), Skipped);
}

#[test]
fn a_private_mapping_with_nothing_behind_it_contributes_nothing() {
    let d = VmaDumpDesc { anon_vma: false, file_backed: false, ..desc() };
    assert_eq!(vma_dump_verdict(&d, F::all()), Skipped);
}

// --- ordering between rungs --------------------------------------------

/// The written-to test runs before the whole-file-mapping test, so a private
/// file mapping that has been modified is dumped in full on the anonymous bit
/// alone, without the file-mapping bit.
#[test]
fn a_modified_private_file_mapping_rides_the_anonymous_bit() {
    let d = VmaDumpDesc { anon_vma: true, ..mapped_head() };
    assert_eq!(vma_dump_verdict(&d, F::ANON_PRIVATE), Whole);
}

/// The whole-file-mapping test runs before the header-page test, so the two
/// bits together give the whole mapping rather than one page.
#[test]
fn the_file_mapping_bit_outranks_the_header_page_bit() {
    let d = VmaDumpDesc { backing_executable: true, ..mapped_head() };
    assert_eq!(vma_dump_verdict(&d, F::MAPPED_PRIVATE | F::ELF_HEADERS), Whole);
}

/// Sharing is tested before the private ladder, so a shared mapping never
/// reaches the header-page rule even when it looks like a program image.
#[test]
fn a_shared_mapping_never_reaches_the_header_page_rule() {
    let d = VmaDumpDesc { shared: true, backing_executable: true, ..mapped_head() };
    assert_eq!(vma_dump_verdict(&d, F::ELF_HEADERS), Skipped);
}

// --- the header page ---------------------------------------------------

#[test]
fn the_header_page_rule_needs_a_readable_mapping_of_an_object_head() {
    let base = VmaDumpDesc { backing_executable: true, ..mapped_head() };
    assert_eq!(vma_dump_verdict(&base, F::ELF_HEADERS), FirstPage);
    assert_eq!(vma_dump_verdict(&VmaDumpDesc { readable: false, ..base }, F::ELF_HEADERS), Skipped);
    assert_eq!(vma_dump_verdict(&VmaDumpDesc { pgoff_zero: false, ..base }, F::ELF_HEADERS), Skipped);
}

/// An executable object is a program image with certainty; anything else has to
/// be checked against the object's first bytes, and a library that is not
/// marked executable is exactly that case.
#[test]
fn a_non_executable_object_head_defers_to_its_first_bytes() {
    assert_eq!(vma_dump_verdict(&mapped_head(), F::ELF_HEADERS), ElfProbe);

    let mut head = [0u8; 8];
    head[..ELF_MAGIC.len()].copy_from_slice(&ELF_MAGIC);
    assert_eq!(resolve_elf_probe(ElfProbe, &head), FirstPage);
    assert_eq!(resolve_elf_probe(ElfProbe, b"#!/bin/sh"), Skipped);
    assert_eq!(resolve_elf_probe(ElfProbe, b"\x7fEL"), Skipped);
    assert_eq!(resolve_elf_probe(ElfProbe, b""), Skipped);
}

#[test]
fn resolving_leaves_every_settled_verdict_alone() {
    for v in [Whole, FirstPage, Skipped] {
        assert_eq!(resolve_elf_probe(v, b"#!/bin/sh"), v);
    }
}

// --- byte counts -------------------------------------------------------

#[test]
fn dump_size_follows_the_verdict() {
    let d = desc();
    assert_eq!(dump_size(Skipped, &d, PAGE_BYTES), 0);
    assert_eq!(dump_size(Whole, &d, PAGE_BYTES), VMA_LEN);
    assert_eq!(dump_size(FirstPage, &d, PAGE_BYTES), PAGE_BYTES);
    assert_eq!(dump_size(ElfProbe, &d, PAGE_BYTES), PAGE_BYTES);
}

#[test]
fn a_mapping_shorter_than_a_page_never_reports_more_than_it_holds() {
    let short = VmaDumpDesc { end: VMA_START + 0x100, ..desc() };
    assert_eq!(dump_size(FirstPage, &short, PAGE_BYTES), 0x100);
    assert_eq!(dump_size(Whole, &short, PAGE_BYTES), 0x100);
}

// --- the live-mapping adapter ------------------------------------------

struct Obj { nlink: u32, mode: u16 }

impl FileBacking for Obj {
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, FileBackingError> { Ok(0) }
    fn size_hint(&self) -> u64 { VMA_LEN }
    fn i_nlink(&self) -> u32 { self.nlink }
    fn i_mode(&self) -> u16 { self.mode }
    fn shared_frame(&self, _off: u64) -> Result<Option<SharedFrame>, FileBackingError> { Ok(None) }
}

fn va(a: u64) -> UserVirtAddr { UserVirtAddr::new(a).expect("user address") }

fn vma(flags: VmaFlags, backing: VmaBacking) -> Vma {
    Vma::new(va(VMA_START), va(VMA_START + VMA_LEN), VmaProt::READ, flags, backing)
}

fn file(nlink: u32, mode: u16, off: u64) -> VmaBacking {
    VmaBacking::File { backing: Arc::new(Obj { nlink, mode }), off }
}

const REGULAR_EXEC: u16 = 0o100755;
const REGULAR_DATA: u16 = 0o100644;

#[test]
fn the_adapter_reads_the_exclusion_flag_off_a_live_mapping() {
    let plain = vma(VmaFlags::PRIVATE, VmaBacking::Anonymous);
    assert!(!describe_vma(&plain, 0).dontdump);
    let excluded = vma(VmaFlags::PRIVATE | VmaFlags::DONTDUMP, VmaBacking::Anonymous);
    assert!(describe_vma(&excluded, 0).dontdump);
    assert_eq!(vma_dump_verdict(&describe_vma(&excluded, 0), F::all()), Skipped);
}

#[test]
fn the_adapter_reports_an_anonymous_mapping_as_written_only_once_it_has_pages() {
    let v = vma(VmaFlags::PRIVATE, VmaBacking::Anonymous);
    assert!(!describe_vma(&v, 0).anon_vma);
    assert_eq!(vma_dump_verdict(&describe_vma(&v, 0), F::DEFAULT), Skipped);
    v.rss.store(1, Ordering::Relaxed);
    assert!(describe_vma(&v, 0).anon_vma);
    assert_eq!(vma_dump_verdict(&describe_vma(&v, 0), F::DEFAULT), Whole);
}

#[test]
fn the_adapter_classes_a_shared_mapping_by_whether_its_object_has_a_name() {
    let named = vma(VmaFlags::SHARED, file(1, REGULAR_DATA, 0));
    assert!(!describe_vma(&named, 0).unlinked_backing);
    assert_eq!(vma_dump_verdict(&describe_vma(&named, 0), F::MAPPED_SHARED), Whole);

    let nameless = vma(VmaFlags::SHARED, file(0, REGULAR_DATA, 0));
    assert!(describe_vma(&nameless, 0).unlinked_backing);
    assert_eq!(vma_dump_verdict(&describe_vma(&nameless, 0), F::ANON_SHARED), Whole);

    // A shared mapping with no object at all is anonymous shared memory.
    let anon = vma(VmaFlags::SHARED, VmaBacking::Anonymous);
    assert!(describe_vma(&anon, 0).unlinked_backing);
    assert_eq!(vma_dump_verdict(&describe_vma(&anon, 0), F::ANON_SHARED), Whole);
}

#[test]
fn the_adapter_reads_the_object_head_and_execute_bit_off_the_backing() {
    let exe = describe_vma(&vma(VmaFlags::PRIVATE, file(1, REGULAR_EXEC, 0)), 0);
    assert!(exe.pgoff_zero && exe.backing_executable && exe.readable);
    assert_eq!(vma_dump_verdict(&exe, F::ELF_HEADERS), FirstPage);

    let lib = describe_vma(&vma(VmaFlags::PRIVATE, file(1, REGULAR_DATA, 0)), 0);
    assert!(!lib.backing_executable);
    assert_eq!(vma_dump_verdict(&lib, F::ELF_HEADERS), ElfProbe);

    let tail = describe_vma(&vma(VmaFlags::PRIVATE, file(1, REGULAR_EXEC, PAGE_BYTES)), 0);
    assert!(!tail.pgoff_zero);
    assert_eq!(vma_dump_verdict(&tail, F::ELF_HEADERS), Skipped);
}

#[test]
fn the_adapter_treats_a_directly_mapped_physical_range_as_device_memory() {
    let d = describe_vma(&vma(VmaFlags::SHARED, VmaBacking::PhysRange { base_pa: 0xfd00_0000 }), 0);
    assert!(d.io);
    assert_eq!(vma_dump_verdict(&d, F::all()), Skipped);
}

#[test]
fn the_adapter_always_dumps_the_vdso_image_and_the_data_page_below_it() {
    let image = vma(VmaFlags::PRIVATE, VmaBacking::Anonymous);
    // The image itself.
    assert!(describe_vma(&image, VMA_START).always_dump);
    // The data page sits immediately below the image, in its own mapping.
    assert!(describe_vma(&image, VMA_START + VMA_LEN).always_dump);
    // An unrelated mapping is not swept in, and neither is a process with no
    // vDSO mapped at all.
    assert!(!describe_vma(&image, VMA_START + 0x1_0000_0000).always_dump);
    assert!(!describe_vma(&image, 0).always_dump);
}
