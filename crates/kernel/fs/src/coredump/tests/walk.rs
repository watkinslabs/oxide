// Walking a live VMA tree into the mapping list of a dump, and the image that
// list produces.
//
// The end this whole subsystem exists for is the last case here: a crashed
// program's text reaching a debugger as the contents of a `PT_LOAD`. Everything
// above it is the machinery that has to be right for that to happen.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use vmm::coredump_filter::CoredumpFilter as F;
use hal::UserVirtAddr;
use vmm::{FileBacking, FileBackingError, SharedFrame, Vma, VmaBacking, VmaFlags, VmaProt};

use crate::coredump::elf::tests::reader::Image;
use crate::coredump::elf::{
    build_core_image, CoreArch, CoreIdentity, CoreImageInput, CoreSegFile, CoreSegment, CoreState,
    CoreThread, CoreTimes, SEG_EXEC, SEG_READ, SEG_WRITE,
};
use crate::coredump::elf::uapi::{NT_FILE, PT_LOAD};
use crate::coredump::plan::{plan_mappings, PlannedSegment};

const PAGE: u64 = 4096;
const TEXT: u64 = 0x0040_0000;
const DATA: u64 = 0x0060_0000;
const LIBD: u64 = 0x0080_0000;
const HEAP: u64 = 0x00a0_0000;
const EXE: &[u8] = b"/usr/bin/crasher";
const LIB: &[u8] = b"/usr/lib64/libc.so.6";

const REGULAR_EXEC: u16 = 0o100755;
const REGULAR_DATA: u16 = 0o100644;

struct Obj { mode: u16, path: &'static [u8] }

impl FileBacking for Obj {
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, FileBackingError> { Ok(0) }
    fn size_hint(&self) -> u64 { PAGE }
    fn i_mode(&self) -> u16 { self.mode }
    fn map_path(&self) -> Option<&[u8]> { Some(self.path) }
    fn shared_frame(&self, _off: u64) -> Result<Option<SharedFrame>, FileBackingError> { Ok(None) }
}

/// A backing with no name, the way anonymous shared memory presents.
struct Nameless;

impl FileBacking for Nameless {
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, FileBackingError> { Ok(0) }
    fn size_hint(&self) -> u64 { PAGE }
    fn i_nlink(&self) -> u32 { 0 }
    fn shared_frame(&self, _off: u64) -> Result<Option<SharedFrame>, FileBackingError> { Ok(None) }
}

fn va(a: u64) -> UserVirtAddr { UserVirtAddr::new(a).expect("user address") }

fn map(start: u64, pages: u64, prot: VmaProt, flags: VmaFlags, backing: VmaBacking) -> Vma {
    Vma::new(va(start), va(start + pages * PAGE), prot, flags, backing)
}

fn file(mode: u16, path: &'static [u8], off: u64) -> VmaBacking {
    VmaBacking::File { backing: Arc::new(Obj { mode, path }), off }
}

/// Text, data and heap, the shape a crashed dynamically-linked program has.
fn tree() -> Vec<Vma> {
    let text = map(TEXT, 2, VmaProt::READ | VmaProt::EXEC, VmaFlags::PRIVATE,
        file(REGULAR_EXEC, EXE, 0));
    let data = map(DATA, 1, VmaProt::READ, VmaFlags::PRIVATE, file(REGULAR_DATA, LIB, 0));
    // Further into the same object: the header-page rule does not reach a
    // mapping that does not start at its object's first page.
    let libd = map(LIBD, 1, VmaProt::READ | VmaProt::WRITE, VmaFlags::PRIVATE,
        file(REGULAR_DATA, LIB, 3 * PAGE));
    let heap = map(HEAP, 2, VmaProt::READ | VmaProt::WRITE, VmaFlags::PRIVATE, VmaBacking::Anonymous);
    heap.anon_pages.store(true, Ordering::Release);
    alloc::vec![text, data, libd, heap]
}

/// Synthetic memory: the byte at `va` is a function of `va`, so a segment
/// written from the wrong address reads back wrong rather than empty.
fn byte_at(v: u64) -> u8 { (v >> 8) as u8 ^ (v as u8) ^ 0x5a }

/// A reader that answers every address, and whose text pages start with the
/// magic that identifies a mapped object.
fn memory() -> impl FnMut(u64, &mut [u8]) -> usize {
    |v: u64, buf: &mut [u8]| {
        for (i, b) in buf.iter_mut().enumerate() { *b = byte_at(v + i as u64) }
        if v == TEXT || v == DATA {
            let n = buf.len().min(crate::coredump::filter::ELF_MAGIC.len());
            buf[..n].copy_from_slice(&crate::coredump::filter::ELF_MAGIC[..n]);
        }
        buf.len()
    }
}

fn plan(vmas: &[Vma], filter: F) -> Vec<PlannedSegment> {
    let mut mem = memory();
    plan_mappings(vmas, 0, 0, filter, PAGE, &mut mem)
}

#[test]
fn every_mapping_is_planned_in_address_order_even_when_it_carries_nothing() {
    let vmas = tree();
    let p = plan(&vmas, F::empty());
    assert_eq!(p.len(), 4);
    assert_eq!(p[0].start, TEXT);
    assert_eq!(p[1].start, DATA);
    assert_eq!(p[2].start, LIBD);
    assert_eq!(p[3].start, HEAP);
    // Excluded by the filter, but still described: a debugger sees the range.
    assert!(p.iter().all(|s| s.dump_size == 0));
    assert_eq!(p[0].end, TEXT + 2 * PAGE);
}

#[test]
fn permissions_reach_the_program_header_flags() {
    let vmas = tree();
    let p = plan(&vmas, F::empty());
    assert_eq!(p[0].prot, SEG_READ | SEG_EXEC);
    assert_eq!(p[1].prot, SEG_READ);
    assert_eq!(p[2].prot, SEG_READ | SEG_WRITE);
    assert_eq!(p[3].prot, SEG_READ | SEG_WRITE);
}

#[test]
fn the_default_filter_carries_written_anonymous_memory_and_one_page_of_each_object() {
    let vmas = tree();
    let p = plan(&vmas, F::DEFAULT);
    // An executable object is a program image without reading it.
    assert_eq!(p[0].dump_size, PAGE);
    // A data object's head has to be read; it starts with the magic here.
    assert_eq!(p[1].dump_size, PAGE);
    // Not the head of its object, so the header-page rule leaves it out.
    assert_eq!(p[2].dump_size, 0);
    assert_eq!(p[3].dump_size, 2 * PAGE);
}

/// The deferred verdict really consults memory: the same mapping under the
/// same filter is dumped or skipped according to what its first bytes say.
#[test]
fn a_non_executable_object_is_carried_only_when_its_head_says_it_is_one() {
    let vmas = tree();
    let mut nothing = |_va: u64, _buf: &mut [u8]| 0usize;
    let p = plan_mappings(&vmas, 0, 0, F::DEFAULT, PAGE, &mut nothing);
    assert_eq!(p[1].dump_size, 0, "unreadable head is not a mapped object");
    assert_eq!(p[0].dump_size, PAGE, "an executable object needs no probe");
}

#[test]
fn the_whole_file_mapping_bit_carries_every_page_of_it() {
    let vmas = tree();
    let p = plan(&vmas, F::DEFAULT | F::MAPPED_PRIVATE);
    assert_eq!(p[0].dump_size, 2 * PAGE);
    assert_eq!(p[1].dump_size, PAGE);
    assert_eq!(p[2].dump_size, PAGE);
}

#[test]
fn a_named_object_reaches_the_mapping_table_with_its_offset_in_pages() {
    let vmas = tree();
    let p = plan(&vmas, F::DEFAULT);
    let f0 = p[0].file.as_ref().expect("text names its object");
    assert_eq!(f0.path, EXE);
    assert_eq!(f0.pgoff_pages, 0);
    let f1 = p[1].file.as_ref().expect("data names its object");
    assert_eq!(f1.path, LIB);
    assert_eq!(f1.pgoff_pages, 0);
    let f2 = p[2].file.as_ref().expect("the later mapping names it too");
    assert_eq!(f2.pgoff_pages, 3);
    assert!(p[3].file.is_none(), "anonymous memory names no object");
}

#[test]
fn a_backing_with_no_name_contributes_no_mapping_table_entry() {
    let shm = map(HEAP, 1, VmaProt::READ | VmaProt::WRITE, VmaFlags::SHARED,
        VmaBacking::File { backing: Arc::new(Nameless), off: 0 });
    let p = plan(&[shm], F::ANON_SHARED);
    assert_eq!(p[0].dump_size, PAGE);
    assert!(p[0].file.is_none());
}

// --- the image the plan produces ---------------------------------------

fn image(p: &[PlannedSegment]) -> Vec<u8> {
    let arch = CoreArch::native();
    let regs = alloc::vec![0u8; arch.gregset_bytes()];
    let threads = [CoreThread { tid: 7, regs: &regs, fpregs: None, xstate: None,
        times: CoreTimes::default() }];
    let segs: Vec<CoreSegment<'_>> = p.iter().map(|s| CoreSegment {
        start: s.start, end: s.end, prot: s.prot, dump_size: s.dump_size,
        file: s.file.as_ref().map(|f| CoreSegFile { path: &f.path, pgoff_pages: f.pgoff_pages }),
    }).collect();
    let input = CoreImageInput {
        arch,
        identity: CoreIdentity {
            pid: 7, ppid: 1, pgrp: 7, sid: 7, uid: 0, gid: 0, signo: 11,
            sigpend: 0, sighold: 0, state: CoreState::Running, nice: 0, flag: 0,
            comm: b"crasher", psargs: b"crasher", times: CoreTimes::default(),
        },
        threads: &threads, segments: &segs, auxv: &[], siginfo: None,
    };
    let mut mem = memory();
    build_core_image(&input, &mut mem).expect("image builds")
}

/// The whole point: a crash produces a core whose `PT_LOAD` segments hold the
/// faulting text, at the address it executed from, byte for byte.
#[test]
fn the_faulting_text_reaches_the_image_as_the_contents_of_a_pt_load() {
    let vmas = tree();
    let p = plan(&vmas, F::DEFAULT | F::MAPPED_PRIVATE);
    let bytes = image(&p);
    let img = Image::new(&bytes);

    /// An address inside the second text page — past anything the header-page
    /// rule alone would have carried.
    const FAULT_PC: u64 = TEXT + PAGE + 0x40;
    let ph = img.phdrs().into_iter()
        .find(|h| h.ty == PT_LOAD && h.vaddr <= FAULT_PC && FAULT_PC < h.vaddr + h.memsz)
        .expect("a PT_LOAD covers the faulting instruction");
    assert_eq!(ph.vaddr, TEXT);
    assert_eq!(ph.memsz, 2 * PAGE);
    assert_eq!(ph.filesz, 2 * PAGE, "the text is present, not elided");
    assert_eq!(ph.flags & 0x1, 0x1, "the segment is marked executable");

    let at = (ph.offset + (FAULT_PC - ph.vaddr)) as usize;
    let want: Vec<u8> = (0..16).map(|i| byte_at(FAULT_PC + i)).collect();
    assert_eq!(&bytes[at..at + 16], &want[..], "the instruction bytes are the mapped ones");
}

/// And the objects it did not carry whole are named, so a debugger can reopen
/// them for the rest.
#[test]
fn the_image_names_every_object_the_process_had_mapped() {
    let vmas = tree();
    let p = plan(&vmas, F::DEFAULT);
    let bytes = image(&p);
    let img = Image::new(&bytes);
    let files = img.notes().into_iter().find(|n| n.ty == NT_FILE).expect("NT_FILE");
    let count = u64::from_le_bytes(files.desc[..8].try_into().expect("count word"));
    assert_eq!(count, 3);
    assert_eq!(u64::from_le_bytes(files.desc[8..16].try_into().expect("page size")), PAGE);
    let names = &files.desc[(2 + 3 * count as usize) * 8..];
    let mut it = names.split(|&b| b == 0);
    assert_eq!(it.next().expect("first path"), EXE);
    assert_eq!(it.next().expect("second path"), LIB);
    assert_eq!(it.next().expect("third path"), LIB);
}
