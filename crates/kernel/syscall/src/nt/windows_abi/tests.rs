//! Argument positions across the shipped runtime's calling convention.

use super::*;

/// One entry record as the host convention presents it: the register a stub
/// moves the first argument into is read as the fourth.
fn entry(first: u64, second: u64, third: u64, fourth: u64) -> SyscallArgs {
    SyscallArgs { a0: 0xdead_0000, a1: 0xdead_0001, a2: second, a3: first, a4: third, a5: fourth }
}

#[test]
fn the_first_four_arguments_land_in_the_first_four_positions() {
    let args = windows_args(entry(1, 2, 3, 4), |_| None);
    assert_eq!((args.a0, args.a1, args.a2, args.a3), (1, 2, 3, 4));
}

#[test]
fn neither_scratch_register_is_ever_read_as_an_argument() {
    // The two words the host convention would take first carry whatever the
    // caller last left in them; reading either as an argument is the defect
    // this conversion exists to prevent.
    let args = windows_args(entry(1, 2, 3, 4), |_| Some(9));
    for value in [args.a0, args.a1, args.a2, args.a3, args.a4, args.a5] {
        assert_ne!(value, 0xdead_0000);
        assert_ne!(value, 0xdead_0001);
    }
}

#[test]
fn the_fifth_and_sixth_arguments_come_from_the_callers_frame() {
    let args = windows_args(entry(1, 2, 3, 4), |index| match index {
        4 => Some(0x50),
        5 => Some(0x60),
        _ => None,
    });
    assert_eq!(args.a4, 0x50);
    assert_eq!(args.a5, 0x60);
}

#[test]
fn a_frame_word_the_caller_never_reserved_reads_as_no_argument() {
    // A four-argument service reserves no space for a fifth, so the words
    // beyond its arguments may be unreadable. That is not a failed call.
    let args = windows_args(entry(7, 8, 9, 10), |_| None);
    assert_eq!(args.a4, 0);
    assert_eq!(args.a5, 0);
}

#[test]
fn the_register_argument_count_is_the_convention_boundary() {
    // The first frame-carried argument is the one after the register ones,
    // and the frame is asked for it by that same index.
    assert_eq!(REGISTER_ARGS, 4);
    let mut asked = alloc::vec::Vec::new();
    let _ = windows_args(entry(1, 2, 3, 4), |index| { asked.push(index); None });
    assert_eq!(asked, alloc::vec![4, 5]);
}

#[test]
fn the_runtime_heap_reservation_decodes_to_the_call_the_runtime_made() {
    // The first system service the shipped runtime issues is the reservation
    // behind its process heap. It passes the current-process pseudo handle,
    // an address slot, no zero bits, a size slot, the reserve type and a
    // read/write page protection — the last two in the caller's frame.
    const MEM_RESERVE: u32 = 0x2000;
    const PAGE_READWRITE: u32 = 0x04;
    let address_slot = 0x7fff_0000_1000u64;
    let size_slot = 0x7fff_0000_1008u64;
    let converted = windows_args(entry(u64::MAX, address_slot, 0, size_slot), |index| match index {
        4 => Some(MEM_RESERVE as u64),
        5 => Some(PAGE_READWRITE as u64),
        _ => None,
    });
    let call = crate::nt::NtCall { service: crate::nt::NtService::AllocateVirtualMemory, args: converted };
    let crate::nt::NtMemoryCall::Allocate { process, base, zero_bits, size, allocation_type, protect } =
        crate::nt::decode_memory(call).expect("the reservation is a memory call") else {
        panic!("the reservation decodes as an allocation");
    };
    assert_eq!(process, u64::MAX, "the current-process pseudo handle is the first argument");
    assert_eq!(base.as_u64(), address_slot);
    assert_eq!(zero_bits, 0);
    assert_eq!(size.as_u64(), size_slot);
    assert_eq!(allocation_type, MEM_RESERVE);
    assert_eq!(protect, PAGE_READWRITE);
}

#[test]
fn the_unconverted_record_would_not_have_named_the_current_process() {
    // Without the conversion the same entry record decodes with a scratch
    // register in the process position, which is the failure the reservation
    // hit: it is refused, the heap is never created, and the runtime's first
    // allocation dereferences nothing.
    let raw = entry(u64::MAX, 0x7fff_0000_1000, 0, 0x7fff_0000_1008);
    assert_ne!(raw.a0, u64::MAX, "the scratch register is not the process handle");
}
