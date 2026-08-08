// The source-filter admission ladder, driven as a decision.

use super::*;

fn limits() -> Limits {
    Limits { optmem_max: 131_072, max_msf: DEFAULT_IGMP_MAX_MSF,
             numsrc_overflow: MAX_NUMSRC_WIDE }
}

#[test]
fn a_buffer_too_small_to_name_a_count_is_refused_before_the_memory_ceiling() {
    let tight = Limits { optmem_max: 8, ..limits() };
    // Both refusals apply, and the size of the fixed part answers first — the
    // caller is told its buffer is malformed, not that it is too large.
    assert_eq!(admit_length(4, GROUP_FILTER, tight), Err(Errno::Einval));
    assert_eq!(admit_length(GROUP_FILTER.header, GROUP_FILTER, tight), Err(Errno::Enobufs));
}

#[test]
fn the_whole_option_is_bounded_by_the_option_memory_ceiling() {
    let small = Limits { optmem_max: 200, ..limits() };
    assert_eq!(admit_length(200, GROUP_FILTER, small), Ok(()));
    assert_eq!(admit_length(201, GROUP_FILTER, small), Err(Errno::Enobufs));
    // The narrow request shape is judged by the same ceiling.
    assert_eq!(admit_length(201, IP_MSFILTER, small), Err(Errno::Enobufs));
}

#[test]
fn too_many_sources_is_a_capacity_refusal_not_a_malformed_buffer() {
    // At the ceiling the write is admitted when the buffer carries the list.
    let at_ceiling = IP_MSFILTER.header + 10 * IP_MSFILTER.entry;
    assert_eq!(admit_sources(at_ceiling, 10, IP_MSFILTER, limits()), Ok(()));
    // One past it is ENOBUFS even though the buffer is big enough — the count
    // ceiling is asked before the length-versus-count screen.
    let past = IP_MSFILTER.header + 11 * IP_MSFILTER.entry;
    assert_eq!(admit_sources(past, 11, IP_MSFILTER, limits()), Err(Errno::Enobufs));
    // A count within the ceiling that the buffer does not carry is EINVAL.
    assert_eq!(admit_sources(IP_MSFILTER.header, 4, IP_MSFILTER, limits()), Err(Errno::Einval));
    assert_eq!(admit_sources(at_ceiling - 1, 10, IP_MSFILTER, limits()), Err(Errno::Einval));
}

#[test]
fn a_count_whose_size_overflows_is_refused_before_it_is_multiplied() {
    // Both overflow points are ENOBUFS, and neither depends on the buffer.
    let wide = Limits { max_msf: i64::MAX, ..limits() };
    assert_eq!(admit_sources(u32::MAX, MAX_NUMSRC_WIDE, GROUP_FILTER, wide), Err(Errno::Enobufs));
    let narrow = Limits { numsrc_overflow: MAX_NUMSRC_NARROW, max_msf: i64::MAX, ..limits() };
    assert_eq!(admit_sources(u32::MAX, MAX_NUMSRC_NARROW, IP_MSFILTER, narrow),
        Err(Errno::Enobufs));
    // Just below the overflow the count is legal, and the size it needs still
    // fits the widest buffer a caller can describe — which is exactly why the
    // ceiling sits where it does.
    assert_eq!(admit_sources(u32::MAX, MAX_NUMSRC_WIDE - 1, GROUP_FILTER, wide), Ok(()));
    assert_eq!(admit_sources(GROUP_FILTER.header, MAX_NUMSRC_WIDE - 1, GROUP_FILTER, wide),
        Err(Errno::Einval));
}

#[test]
fn the_two_families_carry_their_reference_ceilings() {
    assert_eq!((DEFAULT_IGMP_MAX_MSF, DEFAULT_MLD_MAX_MSF), (10, 64));
    assert_eq!((IP_MSFILTER.header, IP_MSFILTER.entry), (16, 4));
    assert_eq!((GROUP_FILTER.header, GROUP_FILTER.entry), (144, 128));
}
