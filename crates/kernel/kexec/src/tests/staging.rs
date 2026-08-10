// Staging: the control-page choice, the relocation chain, the destination
// collision swap, and page accounting on every exit.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use super::fake::{FakeFrames, FaultingSource, PatternSource};
use crate::frames::Frames;
use crate::image::KImage;
use crate::stage::{stage_image, KernelSource, Limits};
use crate::uapi::*;
use crate::validate::Error;

fn seg(mem: u64, memsz: u64, bufsz: u64) -> KexecSegment {
    KexecSegment { buf: 0, bufsz, mem, memsz }
}

/// Split a relocation entry into (flags, page).
fn split(e: u64) -> (u64, u64) { (e & IND_FLAGS, e & PAGE_MASK) }

#[test]
fn a_control_page_is_never_allowed_to_sit_on_a_destination() {
    // The supply is aimed straight at the segment's destination twice, then at
    // a free page. A control page inside the destination would be overwritten
    // by the relocation it is itself performing.
    let dest = 0x20_0000u64;
    let mut f = FakeFrames::with_queue(&[dest, dest + PAGE_SIZE, 0x80_0000], 0x90_0000);
    let mut img = KImage::new(0, ImageType::Default, vec![seg(dest, 2 * PAGE_SIZE, 0)]);
    let page = img.alloc_control_page(&mut f).expect("a page outside the destination exists");
    assert_eq!(page, 0x80_0000);
    // The two rejects went straight back to the supply, not into the image.
    assert_eq!(f.freed, vec![dest, dest + PAGE_SIZE]);
}

#[test]
fn control_page_allocation_reports_nomem_rather_than_looping_forever() {
    let dest = 0x20_0000u64;
    let mut f = FakeFrames::with_queue(&[dest], 0x20_0000);
    f.fail_after = 1;
    let mut img = KImage::new(0, ImageType::Default, vec![seg(dest, PAGE_SIZE, 0)]);
    assert_eq!(img.alloc_control_page(&mut f), Err(Error::Nomem));
}

#[test]
fn the_relocation_chain_names_one_destination_then_one_source_per_page() {
    let dest = 0x20_0000u64;
    let mut f = FakeFrames::new(0x80_0000);
    let src = PatternSource::new(3 * PAGE_SIZE as usize);
    let segs = vec![seg(dest, 3 * PAGE_SIZE, 3 * PAGE_SIZE)];
    let img = stage_image(&mut f, 0x20_0000, segs, 0, Limits::default(), &src).expect("stages");

    let entries = img.relocation_entries(&f);
    let tags: Vec<u64> = entries.iter().map(|&(e, _)| split(e).0).collect();
    // head is an indirection into the first entry page, then dest + 3 sources.
    assert_eq!(tags, vec![IND_INDIRECTION, IND_DESTINATION, IND_SOURCE, IND_SOURCE, IND_SOURCE]);
    assert_eq!(split(entries[1].0).1, dest);
    // The running destination advances one page per source, which is the whole
    // contract between this list and the trampoline.
    assert_eq!(entries[2].1, dest);
    assert_eq!(entries[3].1, dest + PAGE_SIZE);
    assert_eq!(entries[4].1, dest + 2 * PAGE_SIZE);
    // Sources are distinct pages, and none of them is the destination range.
    let sources: Vec<u64> = entries.iter().filter(|&&(e, _)| e & IND_SOURCE != 0)
        .map(|&(e, _)| split(e).1).collect();
    assert_eq!(sources.len(), 3);
    for s in &sources { assert!(!(dest..dest + 3 * PAGE_SIZE).contains(s), "{s:#x} is a destination"); }
}

#[test]
fn the_staged_bytes_are_the_segment_bytes_and_the_tail_is_zero() {
    // bufsz is one and a half pages into a two-page segment: page 0 is a full
    // copy, page 1 is half data and half zero. Getting the split wrong is how a
    // new kernel boots with a truncated or garbage-tailed image.
    let dest = 0x20_0000u64;
    let half = (PAGE_SIZE / 2) as usize;
    let mut f = FakeFrames::new(0x80_0000);
    let src = PatternSource::new(PAGE_SIZE as usize + half);
    let segs = vec![seg(dest, 2 * PAGE_SIZE, PAGE_SIZE + half as u64)];
    let img = stage_image(&mut f, 0, segs, 0, Limits::default(), &src).expect("stages");

    let sources: Vec<u64> = img.relocation_entries(&f).iter()
        .filter(|&&(e, _)| e & IND_SOURCE != 0).map(|&(e, _)| split(e).1).collect();
    assert_eq!(f.page(sources[0]), &src.bytes[..PAGE_SIZE as usize]);
    assert_eq!(&f.page(sources[1])[..half], &src.bytes[PAGE_SIZE as usize..]);
    assert!(f.page(sources[1])[half..].iter().all(|&b| b == 0), "the tail beyond bufsz is zeroed");
}

#[test]
fn a_source_page_landing_on_another_segments_destination_is_swapped_not_kept() {
    // THE invariant: a source page is either its own destination or not a
    // destination at all. Segment A is staged first; the supply then hands out
    // a page that sits inside A's destination while segment B is being staged.
    // Keeping it would let the trampoline overwrite B's source while copying A.
    let a = 0x20_0000u64;
    let b = 0x40_0000u64;
    // Control page, swap page, A's source, then B's source aimed INTO A.
    let mut f = FakeFrames::with_queue(&[0x80_0000, 0x81_0000, 0x82_0000, a], 0x90_0000);
    let src = PatternSource::new(2 * PAGE_SIZE as usize);
    let segs = vec![seg(a, PAGE_SIZE, PAGE_SIZE), seg(b, PAGE_SIZE, PAGE_SIZE)];
    let img = stage_image(&mut f, 0, segs, 0, Limits::default(), &src).expect("stages");

    let entries = img.relocation_entries(&f);
    let sources: Vec<(u64, u64)> = entries.iter().filter(|&&(e, _)| e & IND_SOURCE != 0)
        .map(|&(e, d)| (split(e).1, d)).collect();
    assert_eq!(sources.len(), 2);
    for &(page, dest) in &sources {
        let is_own_destination = page == dest;
        let in_a = (a..a + PAGE_SIZE).contains(&page);
        let in_b = (b..b + PAGE_SIZE).contains(&page);
        assert!(is_own_destination || !(in_a || in_b),
                "source {page:#x} for {dest:#x} sits on another segment's destination");
    }
    // The page aimed at A's destination was taken for A itself, and A's old
    // source was handed to B — so A's bytes must have moved with it.
    let (a_page, _) = sources[0];
    assert_eq!(a_page, a, "the page that IS the destination becomes that destination's source");
    assert_eq!(f.page(a_page), &src.bytes[..PAGE_SIZE as usize],
               "segment A's bytes followed the swap");
}

#[test]
fn a_faulting_source_frees_every_page_it_had_staged() {
    let mut f = FakeFrames::new(0x80_0000);
    let segs = vec![seg(0x20_0000, 4 * PAGE_SIZE, 4 * PAGE_SIZE)];
    let before = f.live_count();
    assert_eq!(stage_image(&mut f, 0, segs, 0, Limits::default(), &FaultingSource).err(),
               Some(Error::Fault));
    assert_eq!(f.live_count(), before, "a failed stage leaks no page");
}

#[test]
fn an_exhausted_supply_reports_nomem_and_leaks_nothing() {
    let mut f = FakeFrames::new(0x80_0000);
    f.fail_after = 4;
    let src = PatternSource::new(8 * PAGE_SIZE as usize);
    let segs = vec![seg(0x20_0000, 8 * PAGE_SIZE, 8 * PAGE_SIZE)];
    assert_eq!(stage_image(&mut f, 0, segs, 0, Limits::default(), &src).err(), Some(Error::Nomem));
    assert_eq!(f.live_count(), 0);
}

#[test]
fn freeing_an_image_returns_every_page_and_resets_the_list() {
    let mut f = FakeFrames::new(0x80_0000);
    let src = PatternSource::new(4 * PAGE_SIZE as usize);
    let segs = vec![seg(0x20_0000, 4 * PAGE_SIZE, 4 * PAGE_SIZE)];
    let mut img = stage_image(&mut f, 0, segs, 0, Limits::default(), &src).expect("stages");
    assert!(img.page_count() >= 4 + 2 + 1, "sources, control pages and an indirection page");
    assert_eq!(f.live_count(), img.page_count());
    img.free(&mut f);
    assert_eq!(f.live_count(), 0);
    assert_eq!(img.page_count(), 0);
    assert_eq!(img.head, 0);
}

#[test]
fn the_list_grows_a_second_page_once_the_first_is_full() {
    // 512 entries per page, and the last slot of each page is the indirection
    // to the next — so a 512-page segment must span two entry pages. An
    // off-by-one here writes the 512th entry over the chain link and the
    // trampoline walks into a page that is not a list.
    let pages = ENTRIES_PER_PAGE as u64 + 4;
    let mut f = FakeFrames::new(0x1000_0000);
    let src = PatternSource::new((pages * PAGE_SIZE) as usize);
    let segs = vec![seg(0x2000_0000, pages * PAGE_SIZE, pages * PAGE_SIZE)];
    let img = stage_image(&mut f, 0, segs, 0, Limits::default(), &src).expect("stages");

    let entries = img.relocation_entries(&f);
    let inds = entries.iter().filter(|&&(e, _)| e & IND_INDIRECTION != 0).count();
    assert_eq!(inds, 2, "head plus one chain link");
    let sources = entries.iter().filter(|&&(e, _)| e & IND_SOURCE != 0).count();
    assert_eq!(sources as u64, pages, "every destination page has exactly one source");
    // Every entry carries exactly one tag.
    for &(e, _) in &entries { assert!((e & IND_FLAGS).count_ones() == 1, "entry {e:#x}"); }
}

#[test]
fn a_terminated_list_ends_in_ind_done() {
    let mut f = FakeFrames::new(0x80_0000);
    let src = PatternSource::new(PAGE_SIZE as usize);
    let segs = vec![seg(0x20_0000, PAGE_SIZE, PAGE_SIZE)];
    let img = stage_image(&mut f, 0, segs, 0, Limits::default(), &src).expect("stages");
    // The walk stops at IND_DONE; if terminate had not run, the walk would end
    // on a zero slot instead and the trampoline would relocate stale bytes.
    let entries = img.relocation_entries(&f);
    let last_source = entries.last().expect("entries").0;
    assert!(last_source & IND_SOURCE != 0);
    // Read the slot past the last entry directly through the supply.
    let ind_page = split(entries[0].0).1;
    let idx = entries.len() - 1; // head is not in the entry page
    // SAFETY: `ind_page` is an image-owned indirection page and `idx` is within
    // ENTRIES_PER_PAGE, so the read stays inside that page.
    let slot = unsafe { (f.ptr(ind_page).expect("mapped") as *const u64).add(idx).read() };
    assert_eq!(slot, IND_DONE);
}

#[test]
fn a_kernel_source_reads_by_offset_and_refuses_to_run_off_the_end() {
    let bytes: Vec<u8> = (0..64u8).collect();
    let s = KernelSource { bytes: &bytes };
    let mut got = [0u8; 8];
    assert_eq!(crate::image::SegmentSource::read_at(&s, 16, 0, &mut got), Ok(()));
    assert_eq!(got, [16, 17, 18, 19, 20, 21, 22, 23]);
    assert_eq!(crate::image::SegmentSource::read_at(&s, 16, 8, &mut got), Ok(()));
    assert_eq!(got, [24, 25, 26, 27, 28, 29, 30, 31]);
    let mut over = [0u8; 64];
    assert_eq!(crate::image::SegmentSource::read_at(&s, 16, 0, &mut over), Err(Error::Fault));
}

#[test]
fn a_crash_load_is_refused_before_any_page_is_allocated() {
    let mut f = FakeFrames::new(0x80_0000);
    let src = PatternSource::new(PAGE_SIZE as usize);
    let segs = vec![seg(0x20_0000, PAGE_SIZE, PAGE_SIZE)];
    assert_eq!(stage_image(&mut f, 0x20_0000, segs, KEXEC_ON_CRASH, Limits::default(), &src).err(),
               Some(Error::AddrNotAvail));
    assert_eq!(f.live_count(), 0);
}

#[test]
fn a_staged_image_keeps_the_entry_point_and_the_validated_segment_list() {
    let mut f = FakeFrames::new(0x80_0000);
    let src = PatternSource::new(PAGE_SIZE as usize);
    let segs = vec![seg(0x20_0000, PAGE_SIZE, PAGE_SIZE)];
    let img = stage_image(&mut f, 0x20_1234, segs.clone(), 0, Limits::default(), &src).expect("ok");
    assert_eq!(img.start, 0x20_1234);
    assert_eq!(img.segments, segs);
    assert_eq!(img.ty, ImageType::Default);
    assert!(!img.preserve_context);
    assert_ne!(img.control_code_page, 0);
    assert_ne!(img.swap_page, 0);
    assert_ne!(img.control_code_page, img.swap_page);
}

#[test]
fn the_machine_step_refuses_rather_than_reporting_a_jump_it_did_not_make() {
    // The hosted harness has no machine to replace, so the jump reports
    // ENOSYS. Returning Ok here would leave every store-level case asserting
    // on a relocation that did not happen.
    let mut f = FakeFrames::new(0x80_0000);
    let src = PatternSource::new(PAGE_SIZE as usize);
    let segs = vec![seg(0x20_0000, PAGE_SIZE, PAGE_SIZE)];
    let mut img = stage_image(&mut f, 0x20_0000, segs, 0, Limits::default(), &src).expect("ok");
    assert_eq!(crate::machine::prepare(&mut img, &mut f), Ok(()));
    assert_eq!(crate::machine::kexec(&img), Err(Error::NoSys));
}

// --- crash images -----------------------------------------------------------
//
// A crash image is staged into memory this kernel has promised not to use, and
// the promise is the whole point: everything it needs at panic time — its
// control pages, its identity tables, its own bytes — has to be somewhere the
// running kernel will not have overwritten by then. A crash image that touches
// the allocator at all is one that boots from whatever happened to land in
// those pages, and no boot would report it.

/// A reserved region and a supply that owns none of it.
fn crash_fixture(start: u64, len: u64) -> (FakeFrames, Limits) {
    let mut f = FakeFrames::new(0x8000_0000);
    f.reserve_region(start, len);
    let limits = Limits {
        dest_limit: u64::MAX,
        crash: Some(crate::validate::CrashRange { start, end: start + len - 1 }),
    };
    (f, limits)
}

#[test]
fn a_crash_image_takes_every_control_page_from_the_reserved_region() {
    let (start, len) = (0x100_0000u64, 0x40_0000u64);
    let (mut f, limits) = crash_fixture(start, len);
    let dest = start + 0x10_0000;
    let src = PatternSource::new(PAGE_SIZE as usize);
    let segs = vec![seg(dest, PAGE_SIZE, PAGE_SIZE)];
    let img = stage_image(&mut f, dest, segs, KEXEC_ON_CRASH, limits, &src)
        .expect("a crash image stages inside its region");
    assert!(img.control_pages_are_reserved());
    // Nothing came from the allocator. This is the assertion that fails if a
    // crash image ever reaches for a page the running kernel is still using.
    assert_eq!(f.live_count(), 0, "a crash image must not allocate");
    assert_ne!(img.control_code_page, 0);
    assert!(img.control_code_page >= start && img.control_code_page < start + len);
}

#[test]
fn a_crash_images_control_page_is_never_one_of_its_destinations() {
    // The first page of the region IS the destination here, so the bump walk
    // has to step over it. A control page on a destination is overwritten by
    // the image being written on top of it.
    let (start, len) = (0x100_0000u64, 0x40_0000u64);
    let (mut f, limits) = crash_fixture(start, len);
    let src = PatternSource::new(2 * PAGE_SIZE as usize);
    let segs = vec![seg(start, 2 * PAGE_SIZE, 2 * PAGE_SIZE)];
    let img = stage_image(&mut f, start, segs, KEXEC_ON_CRASH, limits, &src).expect("stages");
    assert!(img.control_code_page >= start + 2 * PAGE_SIZE,
            "the control page stepped onto a destination");
}

#[test]
fn a_crash_images_segments_are_written_to_their_destinations_at_load_time() {
    // There is no relocation for a crash image: the bytes go where they will
    // run, while a syscall can still report a failure. Staging them elsewhere
    // would leave a machine that has just panicked to do the copy.
    let (start, len) = (0x100_0000u64, 0x40_0000u64);
    let (mut f, limits) = crash_fixture(start, len);
    let dest = start + 0x20_0000;
    // Dirty the destination first. A region page is reused by every crash
    // image this boot stages, so "arrives zeroed" is only a real claim if
    // there was something there to clear.
    f.dirty_region(dest, 0xA5);
    f.dirty_region(dest + PAGE_SIZE, 0xA5);
    let src = PatternSource::new(PAGE_SIZE as usize + 16);
    let segs = vec![seg(dest, 2 * PAGE_SIZE, PAGE_SIZE + 16)];
    let img = stage_image(&mut f, dest, segs, KEXEC_ON_CRASH, limits, &src).expect("stages");
    let first = f.page(dest);
    assert_eq!(first[0], src.bytes[0]);
    assert_eq!(first[PAGE_SIZE as usize - 1], src.bytes[PAGE_SIZE as usize - 1]);
    // The tail past the source length arrives zeroed, or the new kernel's
    // uninitialised data is whatever the previous image left in the region.
    let second = f.page(dest + PAGE_SIZE);
    assert_eq!(second[16], 0, "the tail past the source kept the previous image's bytes");
    assert!(second[16..].iter().all(|&b| b == 0));
    assert_eq!(&second[..16], &src.bytes[PAGE_SIZE as usize..]);
    // And the relocation list carries no work at all — only its terminator.
    assert!(img.relocation_entries(&f).is_empty());
}

#[test]
fn freeing_a_crash_image_gives_nothing_back_to_the_allocator() {
    // A reserved page returned to the allocator is worse than a leak: the next
    // caller writes over the region a crash kernel is supposed to boot from.
    let (start, len) = (0x100_0000u64, 0x40_0000u64);
    let (mut f, limits) = crash_fixture(start, len);
    let dest = start + 0x10_0000;
    let src = PatternSource::new(PAGE_SIZE as usize);
    let segs = vec![seg(dest, PAGE_SIZE, PAGE_SIZE)];
    let mut img = stage_image(&mut f, dest, segs, KEXEC_ON_CRASH, limits, &src).expect("stages");
    img.free(&mut f);
    assert!(f.freed.is_empty(), "reserved pages were handed to the allocator");
    assert_eq!(f.live_count(), 0);
    assert!(!img.control_pages_are_reserved());
}

#[test]
fn a_crash_image_that_outgrows_its_region_is_refused_rather_than_spilling() {
    // Spilling into the allocator is the failure this refuses: it would
    // succeed at load time and boot from overwritten memory.
    let (start, len) = (0x100_0000u64, PAGE_SIZE);
    let (mut f, limits) = crash_fixture(start, len);
    let src = PatternSource::new(PAGE_SIZE as usize);
    let segs = vec![seg(start, PAGE_SIZE, PAGE_SIZE)];
    let r = stage_image(&mut f, start, segs, KEXEC_ON_CRASH, limits, &src);
    assert_eq!(r.err(), Some(Error::Nomem));
    assert_eq!(f.live_count(), 0);
    assert!(f.freed.is_empty());
}
