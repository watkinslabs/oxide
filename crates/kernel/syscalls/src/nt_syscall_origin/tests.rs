use super::*;

const EXE: PeImageExtent = PeImageExtent { base: 0x0000_0001_4000_0000, size: 0x0002_0000 };
const RUNTIME: PeImageExtent = PeImageExtent { base: 0x0000_0007_bc00_0000, size: 0x0018_0000 };
/// Where the launcher and the runtime's Unix objects live: ordinary ELF text,
/// mapped nowhere near either image.
const LAUNCHER_TEXT: u64 = 0x0000_7f55_c2bf_87c0;

fn images() -> [PeImageExtent; 2] { [EXE, RUNTIME] }

#[test]
fn service_stub_inside_a_mapped_image_is_a_pe_origin() {
    assert_eq!(origin_of(RUNTIME.base, images()), SyscallOrigin::PeImage);
    assert_eq!(origin_of(RUNTIME.base + RUNTIME.size - 1, images()), SyscallOrigin::PeImage);
    assert_eq!(origin_of(EXE.base + 0x1234, images()), SyscallOrigin::PeImage);
}

#[test]
fn addresses_outside_every_image_are_native() {
    assert_eq!(origin_of(LAUNCHER_TEXT, images()), SyscallOrigin::Native);
    // One past the end of an image is the next mapping, not this one.
    assert_eq!(origin_of(EXE.base + EXE.size, images()), SyscallOrigin::Native);
    assert_eq!(origin_of(EXE.base - 1, images()), SyscallOrigin::Native);
}

#[test]
fn an_unreadable_entry_frame_is_never_a_pe_origin() {
    assert_eq!(origin_of(0, images()), SyscallOrigin::Native);
    // Even when an image were placed at zero, an absent frame stays native:
    // the address is not evidence of the caller.
    assert_eq!(origin_of(0, [PeImageExtent { base: 0, size: 0x1000 }]), SyscallOrigin::Native);
}

#[test]
fn a_process_with_no_mapped_image_has_only_native_callers() {
    assert_eq!(origin_of(LAUNCHER_TEXT, []), SyscallOrigin::Native);
    assert_eq!(origin_of(EXE.base, []), SyscallOrigin::Native);
}

#[test]
fn a_zero_sized_record_covers_no_address() {
    let empty = PeImageExtent { base: 0x4000, size: 0 };
    assert_eq!(origin_of(0x4000, [empty]), SyscallOrigin::Native);
}

#[test]
fn raw_ordinals_are_claimed_only_for_pe_calls_in_an_nt_process() {
    assert!(claims_raw_nt_ordinal(true, SyscallOrigin::PeImage));
    assert!(!claims_raw_nt_ordinal(true, SyscallOrigin::Native));
    assert!(!claims_raw_nt_ordinal(false, SyscallOrigin::PeImage));
    assert!(!claims_raw_nt_ordinal(false, SyscallOrigin::Native));
}

/// The measured defect: the launcher's own startup calls carry words that are
/// also filled service ordinals. Personality alone routes every one of them to
/// a service; the origin routes them to the Linux tables that own them.
#[test]
fn launcher_startup_words_that_collide_with_services_stay_linux() {
    // access(2), read(2), openat(2), writev-class, epoll_create(2), and the
    // exit_group(2) that ended the process when a service answered it.
    for nr in [21u64, 0, 257, 20, 213, 231] {
        let origin = origin_of(LAUNCHER_TEXT, images());
        assert_eq!(origin, SyscallOrigin::Native, "nr={nr:#x}");
        assert!(!claims_raw_nt_ordinal(true, origin), "nr={nr:#x}");
    }
}

/// The same words issued by a service stub still reach the services.
#[test]
fn the_same_words_from_pe_text_still_reach_the_services() {
    for nr in [21u64, 0, 257, 20, 213, 231] {
        let origin = origin_of(RUNTIME.base + 0x40, images());
        assert!(claims_raw_nt_ordinal(true, origin), "nr={nr:#x}");
    }
}
