// Integration: drive the REAL loader against a REAL `AddressSpace` and assert
// what stands behind each PT_LOAD it maps.
//
// The property under test is the one everything that classifies a mapping by
// its backing reads — `/proc/<pid>/maps`, the core-dump filter's file-backed
// private class and its header-page rule, the `NT_FILE` note. A program whose
// text is private memory with nothing behind it is invisible to all three, so
// a core dump of a crash in that text names no executable mapping at all.

use alloc::sync::Arc;
use alloc::vec::Vec;

use aslr::ExecRnd;
use hal::UserVirtAddr;
use vmm::{AddressSpace, FileBacking, FileBackingError, VmaBacking, VmaProt};

use crate::{load_image, load_image_reporting, load_static_blob, Image};

const PAGE: u64 = 0x1000;
const EHDR: usize = 64;
const PHENT: usize = 56;
const BASE: u64 = 0x4000_0000;

/// Text: one page-plus of code, no `.bss`.
const TEXT_OFF: u64 = 0;
const TEXT_FILE_SZ: u64 = 0x1abc;
/// Data: file content then `.bss`, so its boundary page is part file, part zero.
const DATA_OFF: u64 = 0x2000;
const DATA_VA: u64 = BASE + 0x2000;
const DATA_FILE_SZ: u64 = 0x1234;
const DATA_MEM_SZ: u64 = 0x3000;

/// A file whose bytes are `off as u8` — every offset distinguishable, so a
/// mapping that lands at the wrong offset is caught by content, not only by
/// bounds.
struct RampFile {
    len: u64,
    ino: u64,
    mode: u16,
}

impl FileBacking for RampFile {
    fn read_at(&self, off: u64, dst: &mut [u8]) -> Result<usize, FileBackingError> {
        let mut n = 0usize;
        while n < dst.len() && off + (n as u64) < self.len {
            dst[n] = (off + n as u64) as u8;
            n += 1;
        }
        Ok(n)
    }
    fn size_hint(&self) -> u64 { self.len }
    fn ino(&self) -> u64 { self.ino }
    fn i_mode(&self) -> u16 { self.mode }
    fn map_path(&self) -> Option<&[u8]> { Some(b"/bin/ramp") }
}

/// ET_EXEC with an RX segment and an RW segment that ends in `.bss`. ET_EXEC
/// keeps the placement fixed, so the assertions can name absolute addresses.
fn two_segment_elf(et_dyn: bool) -> Vec<u8> {
    let phoff = EHDR;
    let total = (DATA_OFF + DATA_FILE_SZ) as usize;
    let mut v = alloc::vec![0u8; total];
    for (i, b) in v.iter_mut().enumerate() { *b = i as u8; }
    v[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    v[4] = 2;
    v[5] = 1;
    v[6] = 1;
    v[16..18].copy_from_slice(&(if et_dyn { 3u16 } else { 2u16 }).to_le_bytes());
    v[18..20].copy_from_slice(&crate::ARCH_MACHINE.to_le_bytes());
    v[20..24].copy_from_slice(&1u32.to_le_bytes());
    v[24..32].copy_from_slice(&(BASE + 0x100).to_le_bytes());
    v[32..40].copy_from_slice(&(phoff as u64).to_le_bytes());
    v[52..54].copy_from_slice(&(EHDR as u16).to_le_bytes());
    v[54..56].copy_from_slice(&(PHENT as u16).to_le_bytes());
    v[56..58].copy_from_slice(&2u16.to_le_bytes());

    let mut ph = |i: usize, flags: u32, off: u64, va: u64, fsz: u64, msz: u64| {
        let b = phoff + i * PHENT;
        v[b..b + 4].copy_from_slice(&1u32.to_le_bytes());   // PT_LOAD
        v[b + 4..b + 8].copy_from_slice(&flags.to_le_bytes());
        v[b + 8..b + 16].copy_from_slice(&off.to_le_bytes());
        v[b + 16..b + 24].copy_from_slice(&va.to_le_bytes());
        v[b + 24..b + 32].copy_from_slice(&va.to_le_bytes());
        v[b + 32..b + 40].copy_from_slice(&fsz.to_le_bytes());
        v[b + 40..b + 48].copy_from_slice(&msz.to_le_bytes());
        v[b + 48..b + 56].copy_from_slice(&PAGE.to_le_bytes());
    };
    ph(0, 5, TEXT_OFF, BASE, TEXT_FILE_SZ, TEXT_FILE_SZ);
    ph(1, 6, DATA_OFF, DATA_VA, DATA_FILE_SZ, DATA_MEM_SZ);
    v
}

fn ramp() -> Arc<dyn FileBacking> {
    ramp_with_len(DATA_OFF + DATA_FILE_SZ)
}

fn ramp_with_len(len: u64) -> Arc<dyn FileBacking> {
    Arc::new(RampFile { len, ino: 4242, mode: 0o755 })
}

fn fresh_as() -> Arc<AddressSpace> {
    let rnd = ExecRnd::draw_with(aslr::Mode::Full, true, aslr::CURRENT, aslr::CURRENT.mmap_rnd_bits);
    let as_ = AddressSpace::new(0x1_0000).expect("AS::new");
    as_.set_mmap_layout(rnd.mmap_base(8 << 20), true);
    as_
}

fn rnd_fixed() -> ExecRnd {
    ExecRnd::draw_with(aslr::Mode::Full, true, aslr::CURRENT, aslr::CURRENT.mmap_rnd_bits)
}

/// `(backing, end VA)` of the mapping covering `va`.
fn at(as_: &AddressSpace, va: u64) -> (VmaBacking, u64) {
    let t = as_.vmas_for_test();
    let v = t.find_containing(UserVirtAddr::new(va).expect("user VA")).expect("no VMA");
    (v.backing.clone(), v.end.as_u64())
}

/// The defect: a program's own text mapped with nothing behind it. Loading the
/// same image with its file present must put that file behind the text.
#[test]
fn text_is_a_mapping_of_the_file_it_was_loaded_from() {
    let blob = two_segment_elf(false);
    let as_ = fresh_as();
    load_image(Image { blob: &blob, file: Some(ramp()), dev: 0 }, None, &as_, &rnd_fixed()).expect("load");

    let (backing, end) = at(&as_, BASE);
    match backing {
        VmaBacking::File { backing, off } => {
            assert_eq!(off, TEXT_OFF, "text maps from the wrong file offset");
            assert_eq!(backing.ino(), 4242, "text names a different file");
        }
        other => panic!("text is not file-backed: {other:?}"),
    }
    // No `.bss`, so the segment is a mapping of the file to its last page.
    assert_eq!(end, BASE + 0x2000);
}

/// ET_DYN without PT_INTERP chooses an unmapped bias, but its entry code
/// performs any required relocation itself. The kernel therefore still maps
/// the executable's original file bytes.
#[test]
fn a_no_interpreter_pie_keeps_its_file_backed_text() {
    let blob = two_segment_elf(true);
    let as_ = fresh_as();
    let img = load_image(Image { blob: &blob, file: Some(ramp()), dev: 0 }, None, &as_, &rnd_fixed())
        .expect("load");

    match at(&as_, img.load_base + BASE).0 {
        VmaBacking::File { backing, off } => {
            assert_eq!(off, TEXT_OFF);
            assert_eq!(backing.ino(), 4242);
        }
        other => panic!("PIE text is not file-backed: {other:?}"),
    }
}

/// Control: the same load with no file behind it keeps the kernel-owned
/// backing, which is what makes the assertion above able to fail.
#[test]
fn an_image_the_kernel_carries_has_no_file_behind_its_text() {
    let blob = two_segment_elf(false);
    let as_ = fresh_as();
    load_static_blob(&blob, &as_, &rnd_fixed()).expect("load");
    assert!(matches!(at(&as_, BASE).0, VmaBacking::KernelBytes { .. }));
}

/// A segment that ends in `.bss` keeps its boundary page file-backed; its
/// mapping supplies zeroes beyond the file portion.
#[test]
fn a_data_segment_keeps_its_file_backed_boundary_page() {
    let blob = two_segment_elf(false);
    let as_ = fresh_as();
    load_image(Image { blob: &blob, file: Some(ramp()), dev: 0 }, None, &as_, &rnd_fixed()).expect("load");

    let (backing, end) = at(&as_, DATA_VA);
    match backing {
        VmaBacking::File { off, .. } => assert_eq!(off, DATA_OFF),
        other => panic!("data head is not file-backed: {other:?}"),
    }
    assert_eq!(end, DATA_VA + 2 * PAGE, "the boundary page was not mapped from the file");
    assert!(matches!(at(&as_, DATA_VA + 2 * PAGE).0, VmaBacking::KernelBytes { .. }));
    let VmaBacking::File { backing, .. } = at(&as_, DATA_VA).0 else { unreachable!() };
    let mut page = [0u8; 16];
    backing.read_at(DATA_OFF + DATA_FILE_SZ - 8, &mut page).expect("read boundary");
    for i in 0..8 { assert_eq!(page[i], (DATA_OFF + DATA_FILE_SZ - 8 + i as u64) as u8); }
    assert_eq!(&page[8..], &[0; 8]);
}


/// A file-backed segment costs no kernel copy of the program's bytes at all,
/// where the same load without a file copies every page of it.
#[test]
fn a_file_backed_segment_keeps_no_kernel_copy_of_its_bytes() {
    let blob = two_segment_elf(false);
    let as_ = fresh_as();
    load_image(Image { blob: &blob, file: Some(ramp()), dev: 0 }, None, &as_, &rnd_fixed()).expect("load");
    // Text has no kernel-owned mapping anywhere in its range.
    let t = as_.vmas_for_test();
    let copies = t.iter()
        .filter(|v| v.start.as_u64() >= BASE && v.start.as_u64() < DATA_VA)
        .filter(|v| matches!(v.backing, VmaBacking::KernelBytes { .. }))
        .count();
    assert_eq!(copies, 0, "text still carries a kernel copy");
}

/// The loader REPORTS every mapping it installed, so the exec shim can emit
/// `perf_event_mmap(vma)` for each.
///
/// The reference gets this from the VMA layer: `elf_map()` goes through
/// `do_mmap()`, which emits. oxide's emitter sits above that layer, so a
/// silently-empty report means an `execve`'d binary's own text is never
/// described to a consumer and every sampled IP inside it resolves to nothing —
/// the dynamic linker's DSOs go through `mmap(2)` and were never affected,
/// which is exactly why the gap was invisible.
#[test]
fn the_loader_reports_the_text_segment_it_mapped() {
    let as_ = fresh_as();
    let blob = two_segment_elf(false);
    let mut maps = Vec::new();
    load_image_reporting(Image { blob: &blob, file: Some(ramp()), dev: 0x0803 },
                         None, &as_, &rnd_fixed(), &mut maps).expect("load");

    let text = maps.iter().find(|m| m.addr == BASE)
        .expect("the RX PT_LOAD is reported");
    assert!(text.prot.contains(vmm::VmaProt::EXEC), "reported as a code mapping");
    assert_eq!(text.pgoff, TEXT_OFF, "file offset the consumer needs for symbols");
    assert_eq!(text.dev, 0x0803, "the image's st_dev reaches the report");
    let f = text.file.as_ref().expect("a file-backed segment names its file");
    assert_eq!(f.map_path(), Some(&b"/bin/ramp"[..]));
    assert_eq!(f.ino(), 4242);

    // The RW segment is reported too, and is NOT a code mapping.
    let data = maps.iter().find(|m| m.addr == DATA_VA).expect("the RW PT_LOAD is reported");
    assert!(!data.prot.contains(vmm::VmaProt::EXEC));

    // Every reported mapping is one that actually exists in the address space.
    let live = as_.vmas_for_test();
    for m in &maps {
        assert!(live.iter().any(|v| v.start.as_u64() == m.addr),
                "reported mapping {:#x} is a real VMA", m.addr);
    }
}

/// The `.bss` tail and the heap window are reported as anonymous mappings —
/// nameless, but still VMAs a sample can land in, which is how the reference
/// treats them.
#[test]
fn the_bss_tail_and_heap_window_are_reported_without_a_file() {
    let as_ = fresh_as();
    let blob = two_segment_elf(false);
    let mut maps = Vec::new();
    load_image_reporting(Image { blob: &blob, file: Some(ramp()), dev: 0 },
                         None, &as_, &rnd_fixed(), &mut maps).expect("load");
    let anon: Vec<_> = maps.iter().filter(|m| m.file.is_none()).collect();
    assert!(anon.len() >= 2, "the bss tail and the heap window, at least: {}", anon.len());
    for m in anon { assert_eq!(m.pgoff, 0, "an anonymous mapping has no file offset"); }
}

/// A load that maps nothing reports nothing — the report tracks the mappings
/// rather than being a fixed list.
#[test]
fn the_report_counts_the_mappings_actually_installed() {
    let as_ = fresh_as();
    let blob = two_segment_elf(false);
    let mut maps = Vec::new();
    load_image_reporting(Image { blob: &blob, file: Some(ramp()), dev: 0 },
                         None, &as_, &rnd_fixed(), &mut maps).expect("load");
    let file_backed = maps.iter().filter(|m| m.file.is_some()).count();
    assert_eq!(file_backed, 2, "one per PT_LOAD with file content");
}

/// A real PIE's final PT_LOAD can start in the middle of a page and carry a
/// short `.bss` tail.  The dynamic linker immediately changes the containing
/// RELRO page to read-only.  Keep that page live across both loader mapping
/// and `mprotect`: losing it makes the first writable global access fault as
/// an unmapped address, exactly the failure an ELF loader must never create.
#[test]
fn remount_style_data_survives_relro_protection() {
    const DATA_PAGE: u64 = BASE + 0x4000;
    const DATA_BYTE: u64 = BASE + 0x4d48;
    let phoff = EHDR;
    let mut blob = alloc::vec![0u8; 0x4010];
    for (i, byte) in blob.iter_mut().enumerate() { *byte = i as u8; }
    blob[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    blob[4] = 2;
    blob[5] = 1;
    blob[6] = 1;
    blob[16..18].copy_from_slice(&2u16.to_le_bytes());
    blob[18..20].copy_from_slice(&crate::ARCH_MACHINE.to_le_bytes());
    blob[20..24].copy_from_slice(&1u32.to_le_bytes());
    blob[24..32].copy_from_slice(&(BASE + 0xfc0).to_le_bytes());
    blob[32..40].copy_from_slice(&(phoff as u64).to_le_bytes());
    blob[52..54].copy_from_slice(&(EHDR as u16).to_le_bytes());
    blob[54..56].copy_from_slice(&(PHENT as u16).to_le_bytes());
    blob[56..58].copy_from_slice(&3u16.to_le_bytes());
    let mut ph = |i: usize, flags: u32, off: u64, va: u64, fsz: u64, msz: u64| {
        let p = phoff + i * PHENT;
        blob[p..p + 4].copy_from_slice(&1u32.to_le_bytes());
        blob[p + 4..p + 8].copy_from_slice(&flags.to_le_bytes());
        blob[p + 8..p + 16].copy_from_slice(&off.to_le_bytes());
        blob[p + 16..p + 24].copy_from_slice(&va.to_le_bytes());
        blob[p + 24..p + 32].copy_from_slice(&va.to_le_bytes());
        blob[p + 32..p + 40].copy_from_slice(&fsz.to_le_bytes());
        blob[p + 40..p + 48].copy_from_slice(&msz.to_le_bytes());
        blob[p + 48..p + 56].copy_from_slice(&PAGE.to_le_bytes());
    };
    ph(0, 5, 0, BASE, 0x13dd, 0x13dd);
    ph(1, 4, 0x2000, BASE + 0x2000, 0x1424, 0x1424);
    ph(2, 6, 0x3c10, BASE + 0x4c10, 0x3f8, 0x410);

    let as_ = fresh_as();
    let img = load_image(
        Image { blob: &blob, file: Some(ramp_with_len(blob.len() as u64)), dev: 0 },
        None, &as_, &rnd_fixed(),
    ).expect("load remount-shaped ELF");
    assert!(matches!(at(&as_, DATA_BYTE).0, VmaBacking::File { .. }));
    assert!(matches!(at(&as_, img.brk.as_u64()).0, VmaBacking::Anonymous));

    as_.mprotect(
        UserVirtAddr::new(DATA_PAGE).expect("data page"), PAGE as usize, VmaProt::READ,
    ).expect("protect RELRO page");
    let (backing, end) = at(&as_, DATA_BYTE);
    assert!(matches!(backing, VmaBacking::File { .. }));
    assert_eq!(end, DATA_PAGE + PAGE, "RELRO is the protected first data page");
}
