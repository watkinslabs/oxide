// The argument shape of the virtual-memory and section services, pinned
// against the values a stock runtime passes: a ULONG in a frame word carries
// an unrelated upper half, and a service that reads the whole word refuses
// calls that were never made.
use super::*;

// A frame word whose upper half is left over from an earlier call.
const STALE_HIGH: u64 = 0x7fff_1234_0000_0000;

#[test]
fn a_zero_count_admits_the_call_whatever_the_frame_word_held() {
    assert!(extended_parameters_admitted(0, 0), "no extended parameters at all");
    assert!(extended_parameters_admitted(0, STALE_HIGH), "the count is the low half of the word");
    assert!(extended_parameters_admitted(0xdead_beef_0000, STALE_HIGH),
        "a pointer beside a zero count names nothing and is not grounds to refuse");
    assert!(!extended_parameters_admitted(0x1000, STALE_HIGH | 1), "one entry needs an owner this kernel lacks");
}

#[test]
fn an_allocation_type_is_the_low_half_of_its_frame_word() {
    assert_eq!(allocation_type(STALE_HIGH | 0x0010_0000), 0x0010_0000);
    assert_eq!(map_view_allocation_type_refusal(STALE_HIGH | 0x0010_0000, false), None,
        "a top-down view is mapped, not refused");
    assert_eq!(map_view_allocation_type_refusal(STALE_HIGH, false), None,
        "an upper half left over from an earlier call is not an allocation type");
    assert_eq!(map_view_allocation_type_refusal(AT_ROUND_TO_PAGE as u64, false), Some(STATUS_INVALID_PARAMETER_9),
        "the ninth argument names the page-rounded view a 64-bit space has no form of");
    assert_eq!(map_view_allocation_type_refusal(AT_ROUND_TO_PAGE as u64, true), Some(STATUS_INVALID_PARAMETER),
        "the extended service names no argument index for it");
}

#[test]
fn the_set_information_ladder_answers_in_declared_argument_order() {
    // A prefetch of one range with a one-word information buffer.
    assert_eq!(set_information_refusal(0, 1, 0x2000, VM_INFORMATION_BYTES), None);
    assert_eq!(set_information_refusal(STALE_HIGH, 1, 0x2000, STALE_HIGH | VM_INFORMATION_BYTES), None,
        "both the class and the length are the low halves of their words");
    assert_eq!(set_information_refusal(1, 1, 0x2000, VM_INFORMATION_BYTES), Some(STATUS_INVALID_PARAMETER_2),
        "an unanswered class names the class argument");
    assert_eq!(set_information_refusal(VM_PAGE_DIRTY_STATE_INFORMATION as u64, 1, 0x2000, VM_INFORMATION_BYTES),
        Some(STATUS_NOT_SUPPORTED), "page-dirty state needs a write-exception owner");
    assert_eq!(set_information_refusal(0, 1, 0, VM_INFORMATION_BYTES), Some(STATUS_INVALID_PARAMETER_5),
        "the information buffer is refused before the length");
    assert_eq!(set_information_refusal(0, 1, 0x2000, 8), Some(STATUS_INVALID_PARAMETER_6));
    assert_eq!(set_information_refusal(0, 0, 0x2000, VM_INFORMATION_BYTES), Some(STATUS_INVALID_PARAMETER_3),
        "an empty range array is refused last");
}

#[test]
fn a_range_entry_of_no_bytes_is_refused_at_its_own_argument() {
    assert_eq!(range_entry_refusal(0), Some(STATUS_INVALID_PARAMETER_4));
    assert_eq!(range_entry_refusal(1), None);
    assert_eq!(range_entry_bytes_address(0x1000, 0), Some(0x1008));
    assert_eq!(range_entry_bytes_address(0x1000, 2), Some(0x1028));
    assert_eq!(range_entry_bytes_address(u64::MAX, 1), None, "an array that runs off the address space");
}

#[test]
fn every_frame_word_index_is_the_arguments_own_position() {
    // NtMapViewOfSection takes ten arguments; the four register words are
    // section, process, base and zero bits, so the sixth declared argument is
    // frame word five.
    assert_eq!(MAP_VIEW_COMMIT_SIZE_ARG, 4);
    assert_eq!(MAP_VIEW_OFFSET_ARG, 5);
    assert_eq!(MAP_VIEW_SIZE_ARG, 6);
    assert_eq!(MAP_VIEW_INHERIT_ARG, 7);
    assert_eq!(MAP_VIEW_ALLOCATION_TYPE_ARG, 8);
    assert_eq!(MAP_VIEW_PROTECT_ARG, 9);
    // NtMapViewOfSectionEx takes nine, with no commit size and no inherit.
    assert_eq!(MAP_VIEW_EX_ALLOCATION_TYPE_ARG, 5);
    assert_eq!(MAP_VIEW_EX_PROTECT_ARG, 6);
    assert_eq!(MAP_VIEW_EX_PARAMETERS_ARG, 7);
    assert_eq!(MAP_VIEW_EX_COUNT_ARG, 8);
    // NtCreateSectionEx is NtCreateSection's seven with an array and a count.
    assert_eq!(CREATE_SECTION_EX_PARAMETERS_ARG, 7);
    assert_eq!(CREATE_SECTION_EX_COUNT_ARG, 8);
    // NtAllocateVirtualMemoryEx takes seven: the array is the sixth argument.
    assert_eq!(ALLOCATE_EX_PARAMETERS_ARG, 5);
    assert_eq!(ALLOCATE_EX_COUNT_ARG, 6);
    // NtSetInformationVirtualMemory takes six; the length is the last.
    assert_eq!(SET_INFORMATION_MEMORY_LENGTH_ARG, 5);
}
