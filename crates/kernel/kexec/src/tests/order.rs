// The refusal ladders. Every assertion here is an errno a real `kexec -l`
// depends on to tell "you may not" from "your list is wrong" from "that
// address does not exist".

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::uapi::*;
use crate::validate::*;

fn seg(mem: u64, memsz: u64, bufsz: u64) -> KexecSegment {
    KexecSegment { buf: 0x1000_0000, bufsz, mem, memsz }
}

const RAM: u64 = 1 << 20; // 4 GiB of pages, so the half-of-memory rule is slack.

#[test]
fn permission_is_decided_before_the_flags_are_even_looked_at() {
    // An unprivileged caller with a nonsense flag word learns EPERM, not
    // EINVAL. Reversing these tells a process that could never kexec anything
    // which flag words this kernel considers well formed.
    assert_eq!(kexec_load_check(false, 0, 0xdead_0000_0000_0000), Err(Error::Perm));
    assert_eq!(kexec_file_load_check(false, 0xffff_ffff), Err(Error::Perm));
}

#[test]
fn the_flag_mask_excludes_the_architecture_field_rather_than_permitting_it() {
    // `(flags & KEXEC_FLAGS) == (flags & ~KEXEC_ARCH_MASK)`: an arch tag in the
    // high half is not an unknown bit, but an unknown LOW bit still is.
    assert_eq!(kexec_load_check(true, 1, KEXEC_ARCH_X86_64), Ok(()));
    assert_eq!(kexec_load_check(true, 1, KEXEC_ON_CRASH | KEXEC_ARCH_AARCH64), Ok(()));
    assert_eq!(kexec_load_check(true, 1, 0x10), Err(Error::Inval));
    assert_eq!(kexec_load_check(true, 1, 1 << 15), Err(Error::Inval));
}

#[test]
fn preserve_context_is_refused_because_nothing_here_can_come_back() {
    // A jump-less kernel refuses the bit; accepting and ignoring it would turn
    // "resume this kernel afterwards" into "never resume", silently.
    assert_eq!(KEXEC_FLAGS & KEXEC_PRESERVE_CONTEXT, 0);
    assert_eq!(kexec_load_check(true, 1, KEXEC_PRESERVE_CONTEXT), Err(Error::Inval));
}

#[test]
fn the_segment_cap_is_sixteen_and_is_checked_after_the_flags() {
    assert_eq!(KEXEC_SEGMENT_MAX, 16);
    assert_eq!(kexec_load_check(true, 16, 0), Ok(()));
    assert_eq!(kexec_load_check(true, 17, 0), Err(Error::Inval));
    // Both wrong: the flag word is decided first, so the cap never reports.
    assert_eq!(kexec_load_check(true, 17, 0x10), Err(Error::Inval));
}

#[test]
fn a_foreign_architecture_tag_is_refused_and_default_is_not() {
    assert_eq!(arch_ok(KEXEC_ARCH_DEFAULT), Ok(()));
    assert_eq!(arch_ok(KEXEC_ARCH), Ok(()));
    assert_eq!(arch_ok(KEXEC_ARCH_386), Err(Error::Inval));
    let foreign = if KEXEC_ARCH == KEXEC_ARCH_X86_64 { KEXEC_ARCH_AARCH64 } else { KEXEC_ARCH_X86_64 };
    assert_eq!(arch_ok(foreign), Err(Error::Inval));
    // The low half never affects the architecture decision.
    assert_eq!(arch_ok(KEXEC_ARCH | KEXEC_ON_CRASH), Ok(()));
}

#[test]
fn the_file_flag_test_is_exact_membership_with_no_architecture_field() {
    for f in [0, KEXEC_FILE_UNLOAD, KEXEC_FILE_ON_CRASH, KEXEC_FILE_NO_INITRAMFS,
              KEXEC_FILE_DEBUG, KEXEC_FILE_NO_CMA, KEXEC_FILE_FORCE_DTB, KEXEC_FILE_FLAGS] {
        assert_eq!(kexec_file_load_check(true, f), Ok(()), "flag {f:#x} is defined");
    }
    assert_eq!(kexec_file_load_check(true, 0x40), Err(Error::Inval));
    // The architecture bits are legal in `kexec_load` and NOT in the file form.
    assert_eq!(kexec_file_load_check(true, KEXEC_ARCH_X86_64), Err(Error::Inval));
}

#[test]
fn an_unaligned_destination_reports_addrnotavail_not_inval() {
    // Alignment is decided before overlap, so a list that is both unaligned and
    // overlapping reports the alignment. `kexec-tools` distinguishes them.
    let unaligned = vec![seg(0x1001, 0x1000, 0)];
    assert_eq!(sanity_check_segment_list(&unaligned, ImageType::Default, RAM, u64::MAX, None),
               Err(Error::AddrNotAvail));
    let bad_size = vec![seg(0x1000, 0x800, 0)];
    assert_eq!(sanity_check_segment_list(&bad_size, ImageType::Default, RAM, u64::MAX, None),
               Err(Error::AddrNotAvail));
    let both = vec![seg(0x1000, 0x2000, 0), seg(0x1001, 0x2000, 0)];
    assert_eq!(sanity_check_segment_list(&both, ImageType::Default, RAM, u64::MAX, None),
               Err(Error::AddrNotAvail));
}

#[test]
fn a_destination_at_or_above_the_limit_is_addrnotavail() {
    let s = vec![seg(0x1000, 0x1000, 0)];
    assert_eq!(sanity_check_segment_list(&s, ImageType::Default, RAM, 0x2000, None),
               Err(Error::AddrNotAvail));
    assert_eq!(sanity_check_segment_list(&s, ImageType::Default, RAM, 0x2001, None), Ok(()));
    // `mem + memsz` overflowing the address space is the same class of answer,
    // not a panic and not a wrap into a legal-looking range.
    let wrap = vec![seg(0xffff_ffff_ffff_f000, 0x2000, 0)];
    assert_eq!(sanity_check_segment_list(&wrap, ImageType::Default, RAM, u64::MAX, None),
               Err(Error::AddrNotAvail));
}

#[test]
fn overlapping_destinations_are_refused_including_the_touching_case() {
    let overlap = vec![seg(0x1000, 0x3000, 0), seg(0x2000, 0x1000, 0)];
    assert_eq!(sanity_check_segment_list(&overlap, ImageType::Default, RAM, u64::MAX, None),
               Err(Error::Inval));
    // Reversed order: the check is pairwise, not "each against the previous".
    let reversed = vec![seg(0x2000, 0x1000, 0), seg(0x1000, 0x3000, 0)];
    assert_eq!(sanity_check_segment_list(&reversed, ImageType::Default, RAM, u64::MAX, None),
               Err(Error::Inval));
    // Abutting is NOT overlapping: `mend > pstart && mstart < pend` is strict,
    // and a loader that packs segments back to back is normal.
    let abut = vec![seg(0x1000, 0x1000, 0), seg(0x2000, 0x1000, 0)];
    assert_eq!(sanity_check_segment_list(&abut, ImageType::Default, RAM, u64::MAX, None), Ok(()));
    // Fully contained, and identical, both count.
    let inside = vec![seg(0x1000, 0x4000, 0), seg(0x2000, 0x1000, 0)];
    assert_eq!(sanity_check_segment_list(&inside, ImageType::Default, RAM, u64::MAX, None),
               Err(Error::Inval));
    let same = vec![seg(0x1000, 0x1000, 0), seg(0x1000, 0x1000, 0)];
    assert_eq!(sanity_check_segment_list(&same, ImageType::Default, RAM, u64::MAX, None),
               Err(Error::Inval));
}

#[test]
fn a_buffer_larger_than_its_destination_is_refused_after_the_overlap_test() {
    let big_buf = vec![seg(0x1000, 0x1000, 0x2000)];
    assert_eq!(sanity_check_segment_list(&big_buf, ImageType::Default, RAM, u64::MAX, None),
               Err(Error::Inval));
    // bufsz == memsz is the ordinary case, and bufsz == 0 is how a loader
    // reserves zeroed memory (`.bss`).
    assert_eq!(sanity_check_segment_list(&[seg(0x1000, 0x1000, 0x1000)], ImageType::Default,
               RAM, u64::MAX, None), Ok(()));
    assert_eq!(sanity_check_segment_list(&[seg(0x1000, 0x1000, 0)], ImageType::Default,
               RAM, u64::MAX, None), Ok(()));
}

#[test]
fn no_image_may_claim_more_than_half_of_memory() {
    // One oversized segment.
    let ram = 100u64;
    let huge = vec![seg(0x1000, 51 * PAGE_SIZE, 0)];
    assert_eq!(sanity_check_segment_list(&huge, ImageType::Default, ram, u64::MAX, None),
               Err(Error::Inval));
    // Each half fits; together they do not. Checking only per segment would
    // let a 16-segment list consume all of RAM and soft-lock the allocator.
    let pair = vec![seg(0x1000, 30 * PAGE_SIZE, 0), seg(0x100000, 30 * PAGE_SIZE, 0)];
    assert_eq!(sanity_check_segment_list(&pair, ImageType::Default, ram, u64::MAX, None),
               Err(Error::Inval));
    let fits = vec![seg(0x1000, 20 * PAGE_SIZE, 0), seg(0x100000, 20 * PAGE_SIZE, 0)];
    assert_eq!(sanity_check_segment_list(&fits, ImageType::Default, ram, u64::MAX, None), Ok(()));
}

#[test]
fn a_crash_load_without_a_reserved_region_is_addrnotavail_not_a_normal_load() {
    // No `crashkernel=` reservation exists in this kernel, so every crash-type
    // load is refused at the entry point — before any page is allocated.
    assert_eq!(crash_entry_ok(0x100_0000, None), Err(Error::AddrNotAvail));
    let r = CrashRange { start: 0x100_0000, end: 0x1ff_ffff };
    assert_eq!(crash_entry_ok(0x100_0000, Some(r)), Ok(()));
    assert_eq!(crash_entry_ok(0x1ff_ffff, Some(r)), Ok(()));
    assert_eq!(crash_entry_ok(0x0ff_ffff, Some(r)), Err(Error::AddrNotAvail));
    assert_eq!(crash_entry_ok(0x200_0000, Some(r)), Err(Error::AddrNotAvail));
}

#[test]
fn a_crash_images_segments_must_stay_inside_the_reserved_region() {
    let r = CrashRange { start: 0x100_0000, end: 0x1ff_ffff };
    let inside = vec![seg(0x100_0000, 0x1000, 0)];
    assert_eq!(sanity_check_segment_list(&inside, ImageType::Crash, RAM, u64::MAX, Some(r)), Ok(()));
    let below = vec![seg(0x0ff_f000, 0x1000, 0)];
    assert_eq!(sanity_check_segment_list(&below, ImageType::Crash, RAM, u64::MAX, Some(r)),
               Err(Error::AddrNotAvail));
    let past = vec![seg(0x1ff_f000, 0x2000, 0)];
    assert_eq!(sanity_check_segment_list(&past, ImageType::Crash, RAM, u64::MAX, Some(r)),
               Err(Error::AddrNotAvail));
    // The same list is fine for a default-type image: containment is a crash
    // rule, because only a crash image is written into reserved memory.
    assert_eq!(sanity_check_segment_list(&past, ImageType::Default, RAM, u64::MAX, Some(r)), Ok(()));
}

#[test]
fn image_type_comes_from_the_on_crash_bit_alone() {
    assert_eq!(image_type(0), ImageType::Default);
    assert_eq!(image_type(KEXEC_ON_CRASH), ImageType::Crash);
    assert_eq!(image_type(KEXEC_ARCH_X86_64 | KEXEC_UPDATE_ELFCOREHDR), ImageType::Default);
}

#[test]
fn a_command_line_must_be_nul_terminated_and_an_empty_one_is_legal() {
    assert_eq!(cmdline_ok(b""), Ok(()));
    assert_eq!(cmdline_ok(b"ro root=/dev/vda\0"), Ok(()));
    assert_eq!(cmdline_ok(b"ro root=/dev/vda"), Err(Error::Inval));
    assert_eq!(cmdline_ok(&[0]), Ok(()));
}

#[test]
fn no_signature_check_is_claimed_that_this_kernel_cannot_perform() {
    // Read, not assumed: with signature verification unconfigured the
    // reference runs no check at all and loads unsigned images. Refusing every
    // image instead would be a refusal the reference never makes.
    assert!(!signature_check_required());
}

#[test]
fn the_segment_record_decodes_the_sixty_four_bit_abi_layout() {
    assert_eq!(KEXEC_SEGMENT_SIZE, 32);
    let mut raw = [0u8; KEXEC_SEGMENT_SIZE];
    raw[0..8].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
    raw[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
    raw[16..24].copy_from_slice(&0x20_0000u64.to_le_bytes());
    raw[24..32].copy_from_slice(&0x2000u64.to_le_bytes());
    let s = KexecSegment::from_bytes(&raw);
    assert_eq!((s.buf, s.bufsz, s.mem, s.memsz), (0x1122_3344_5566_7788, 0x1000, 0x20_0000, 0x2000));
}

#[test]
fn the_relocation_entry_flags_are_the_encoding_the_trampoline_reads() {
    // Wrong bits here corrupt an image with no diagnostic anywhere: the
    // trampoline runs after this kernel has stopped.
    assert_eq!((IND_DESTINATION, IND_INDIRECTION, IND_DONE, IND_SOURCE), (1, 2, 4, 8));
    assert_eq!(IND_FLAGS, 0xf);
    // Every flag fits below the page mask, so an entry carries both.
    assert_eq!(IND_FLAGS & PAGE_MASK, 0);
    assert_eq!(ENTRIES_PER_PAGE, 512);
}

#[test]
fn page_count_rounds_up_and_zero_costs_nothing() {
    assert_eq!(page_count(0), 0);
    assert_eq!(page_count(1), 1);
    assert_eq!(page_count(PAGE_SIZE), 1);
    assert_eq!(page_count(PAGE_SIZE + 1), 2);
}

#[test]
fn an_empty_segment_list_passes_every_check_because_it_is_the_unload() {
    let none: Vec<KexecSegment> = Vec::new();
    assert_eq!(sanity_check_segment_list(&none, ImageType::Default, RAM, u64::MAX, None), Ok(()));
    assert_eq!(kexec_load_check(true, 0, 0), Ok(()));
}
