// Provenance for the crash reservation: the `crashkernel=` grammar, where the
// request lands, what a shrink does, and the panic path's one branch.
//
// Every case here is a decision a boot cannot report on. A machine that
// reserved the wrong amount, reserved nothing because a suffix was misread, or
// placed the region over the running kernel boots identically to one that got
// it right, and differs only on the day it panics — by which time there is
// nobody left to read a log.

use crate::crashk::parse::{parse_line, parse_value, round_system_ram, ParseError, Pref};
use crate::crashk::place::{place, search, PlaceError, Placement, RamRange, DEFAULT_CRASH_LOW_SIZE};
use crate::crashk::shrink::{shrink_target, ShrinkError};
use crate::crashk::{CRASH_ALIGN, CRASH_SHRINK_ALIGN};

/// A machine size big enough that no test size trips the "at least as large as
/// memory" refusal by accident.
const RAM: u64 = 64 * 1024 * 1024 * 1024;

const M: u64 = 1024 * 1024;
const G: u64 = 1024 * 1024 * 1024;

fn req(v: &[u8]) -> Result<crate::crashk::parse::CrashKernelReq, ParseError> {
    parse_value(v, RAM).map(|(r, _)| r)
}

// --- grammar -------------------------------------------------------------

#[test]
fn a_plain_size_reserves_that_many_bytes_anywhere() {
    let r = req(b"256M").expect("parses");
    assert_eq!(r.size, 256 * M);
    assert_eq!(r.base, None);
    assert_eq!(r.pref, Pref::Auto);
}

#[test]
fn every_binary_suffix_scales() {
    assert_eq!(req(b"64K").unwrap().size, 64 * 1024);
    assert_eq!(req(b"64k").unwrap().size, 64 * 1024);
    assert_eq!(req(b"512M").unwrap().size, 512 * M);
    assert_eq!(req(b"1G").unwrap().size, G);
    assert_eq!(req(b"1g").unwrap().size, G);
    assert_eq!(req(b"1048576").unwrap().size, M, "a bare number is bytes, not megabytes");
}

#[test]
fn an_at_sign_fixes_the_base() {
    let r = req(b"128M@16M").expect("parses");
    assert_eq!((r.size, r.base), (128 * M, Some(16 * M)));
}

#[test]
fn a_hex_value_is_accepted_on_both_sides_of_the_at_sign() {
    let r = req(b"0x8000000@0x1000000").expect("parses");
    assert_eq!((r.size, r.base), (0x800_0000, Some(0x100_0000)));
}

#[test]
fn a_zero_size_is_refused_rather_than_reserving_nothing_silently() {
    assert_eq!(req(b"0M").unwrap_err(), ParseError::ZeroSize);
    assert_eq!(req(b"0").unwrap_err(), ParseError::ZeroSize);
}

#[test]
fn a_size_at_least_as_large_as_memory_is_refused() {
    assert_eq!(parse_value(b"64G", RAM).unwrap_err(), ParseError::TooBig);
    assert_eq!(parse_value(b"65G", RAM).unwrap_err(), ParseError::TooBig);
    parse_value(b"63G", RAM).expect("just under the machine's memory is allowed");
}

#[test]
fn text_the_grammar_does_not_account_for_is_refused() {
    assert_eq!(req(b"128Mx").unwrap_err(), ParseError::Trailing);
    assert_eq!(req(b"128M@16Mz").unwrap_err(), ParseError::Trailing);
    assert_eq!(req(b"M").unwrap_err(), ParseError::NoNumber);
    assert_eq!(req(b"").unwrap_err(), ParseError::NoNumber);
    assert_eq!(req(b"128M@").unwrap_err(), ParseError::NoNumber);
}

#[test]
fn a_range_table_picks_the_entry_covering_this_machine() {
    let v = b"512M-2G:64M,2G-6G:128M,6G-:256M";
    assert_eq!(parse_value(v, G).unwrap().0.size, 64 * M);
    assert_eq!(parse_value(v, 4 * G).unwrap().0.size, 128 * M);
    assert_eq!(parse_value(v, 8 * G).unwrap().0.size, 256 * M);
}

#[test]
fn an_open_topped_range_covers_everything_above_its_start() {
    assert_eq!(parse_value(b"4G-:512M", 1024 * G).unwrap().0.size, 512 * M);
}

#[test]
fn a_machine_below_every_range_reserves_nothing() {
    assert_eq!(parse_value(b"4G-8G:256M", G).unwrap_err(), ParseError::NoMatchingRange);
}

#[test]
fn a_range_whose_end_is_not_above_its_start_is_refused() {
    assert_eq!(parse_value(b"2G-2G:64M", 4 * G).unwrap_err(), ParseError::BadRange);
    assert_eq!(parse_value(b"4G-2G:64M", 4 * G).unwrap_err(), ParseError::BadRange);
}

#[test]
fn a_range_table_may_fix_a_base_after_the_last_entry() {
    let r = parse_value(b"512M-4G:64M,4G-:128M@0x40000000", 8 * G).unwrap().0;
    assert_eq!((r.size, r.base), (128 * M, Some(G)));
}

#[test]
fn a_range_entry_larger_than_memory_is_refused_even_when_another_entry_matches() {
    // The operator learns on the machine that boots, not on the one that
    // crashes: a table with a nonsense entry is a broken table everywhere.
    assert_eq!(parse_value(b"512M-4G:64M,4G-:128G", 2 * G).unwrap_err(), ParseError::TooBig);
}

#[test]
fn the_placement_suffixes_are_recognised_and_carry_no_base() {
    let (r, s) = parse_value(b"1G,high", RAM).expect("parses");
    assert_eq!((r.size, r.pref, s), (G, Pref::High, Some(&b"high"[..])));
    let (r, s) = parse_value(b"64M,low", RAM).expect("parses");
    assert_eq!((r.size, r.pref, s), (64 * M, Pref::Auto, Some(&b"low"[..])));
    let (r, s) = parse_value(b"256M,cma", RAM).expect("parses");
    assert_eq!((r.size, r.pref, s), (256 * M, Pref::Auto, Some(&b"cma"[..])));
}

#[test]
fn a_suffixed_value_may_not_also_fix_a_base() {
    assert_eq!(parse_value(b"1G@2G,high", RAM).unwrap_err(), ParseError::Trailing);
}

#[test]
fn an_unknown_suffix_is_refused_rather_than_ignored() {
    assert_eq!(parse_value(b"1G,middle", RAM).unwrap_err(), ParseError::Trailing);
}

#[test]
fn the_last_value_of_each_form_wins() {
    let s = parse_line(b"quiet crashkernel=64M console=ttyS0 crashkernel=256M", RAM);
    assert_eq!(s.main.expect("a main request").size, 256 * M);
}

#[test]
fn the_main_and_low_forms_are_independent_requests() {
    // A line carrying both asks for BOTH regions. Letting the second token
    // replace the first would silently drop the region the low form exists to
    // guarantee, and nothing would say so until a device could not reach its
    // buffer inside the kernel reading the dump.
    let s = parse_line(b"crashkernel=1G,high crashkernel=64M,low crashkernel=32M,cma", RAM);
    assert_eq!(s.main.expect("main").size, G);
    assert_eq!(s.main.unwrap().pref, Pref::High);
    assert_eq!(s.low, Some(64 * M));
    assert_eq!(s.cma, Some(32 * M));
}

#[test]
fn a_malformed_value_does_not_take_the_forms_that_parsed_with_it() {
    let s = parse_line(b"crashkernel=256M crashkernel=nonsense,cma", RAM);
    assert_eq!(s.main.expect("main survives").size, 256 * M);
    assert_eq!(s.cma, None);
}

#[test]
fn a_line_without_the_parameter_asks_for_nothing() {
    let s = parse_line(b"quiet console=ttyS0 root=/dev/vda1", RAM);
    assert_eq!(s.main, None);
    assert_eq!(s.low, None);
}

#[test]
fn a_parameter_whose_name_merely_starts_the_same_is_not_ours() {
    let s = parse_line(b"crashkernel_x=256M crashkernelfoo=1G", RAM);
    assert_eq!(s.main, None);
}

#[test]
fn the_memory_size_is_rounded_up_before_a_range_table_sees_it() {
    // Firmware carves pieces out below the kernel, so a machine sold as 4 GiB
    // reports less. Unrounded, it falls out of the bottom of the entry the
    // operator wrote for its size class and reserves the smaller figure.
    let raw = 4 * G - 100 * M;
    assert_eq!(round_system_ram(raw), 4 * G);
    assert_eq!(parse_value(b"512M-4G:64M,4G-:256M", round_system_ram(raw)).unwrap().0.size, 256 * M);
    assert_eq!(parse_value(b"512M-4G:64M,4G-:256M", raw).unwrap().0.size, 64 * M,
        "the rounding is what puts the machine in the right class");
}

#[test]
fn rounding_an_already_aligned_size_leaves_it_alone() {
    assert_eq!(round_system_ram(4 * G), 4 * G);
    assert_eq!(round_system_ram(0), 0);
}

// --- placement -----------------------------------------------------------

fn ram_all() -> [RamRange; 2] {
    [RamRange { start: 0, end: 3 * G }, RamRange { start: 4 * G, end: 16 * G }]
}

fn spec(v: &[u8]) -> crate::crashk::parse::CrashKernelSpec { parse_line(v, RAM) }

#[test]
fn the_plain_form_lands_below_the_thirty_two_bit_boundary() {
    let p = place(&spec(b"crashkernel=256M"), &ram_all()).expect("placed");
    assert!(p.base + p.size <= 4 * G, "base {:#x}", p.base);
    assert_eq!(p.size, 256 * M);
    assert_eq!(p.base % CRASH_ALIGN, 0);
}

#[test]
fn the_high_form_lands_above_it() {
    let p = place(&spec(b"crashkernel=256M,high"), &ram_all()).expect("placed");
    assert!(p.base >= 4 * G, "base {:#x}", p.base);
}

#[test]
fn the_plain_form_falls_back_above_the_boundary_when_nothing_fits_below() {
    let ram = [RamRange { start: 0, end: 512 * M }, RamRange { start: 4 * G, end: 16 * G }];
    let p = place(&spec(b"crashkernel=1G"), &ram).expect("placed");
    assert!(p.base >= 4 * G, "the fallback is what makes the plain form usable on a machine with little low memory");
}

#[test]
fn the_high_form_falls_back_below_the_boundary_when_nothing_fits_above() {
    let ram = [RamRange { start: 0, end: 3 * G }];
    let p = place(&spec(b"crashkernel=256M,high"), &ram).expect("placed");
    assert!(p.base + p.size <= 4 * G);
}

#[test]
fn a_fixed_base_is_used_exactly_or_not_at_all() {
    let p = place(&spec(b"crashkernel=256M@0x40000000"), &ram_all()).expect("placed");
    assert_eq!(p.base, G);
    // The operator picked an address firmware and devices leave alone.
    // Searching elsewhere would reserve memory they have reason to distrust.
    assert_eq!(place(&spec(b"crashkernel=256M@0xE0000000"), &ram_all()).unwrap_err(), PlaceError::NoSpace);
}

#[test]
fn a_fixed_base_that_is_not_aligned_is_refused() {
    assert_eq!(place(&spec(b"crashkernel=256M@0x40001000"), &ram_all()).unwrap_err(), PlaceError::NoSpace);
}

#[test]
fn the_reserved_size_is_rounded_up_to_the_region_alignment() {
    let p = place(&spec(b"crashkernel=100M"), &ram_all()).expect("placed");
    assert_eq!(p.size % CRASH_ALIGN, 0);
    assert!(p.size >= 100 * M);
}

#[test]
fn a_request_larger_than_any_window_is_refused() {
    let ram = [RamRange { start: 0, end: 512 * M }];
    assert_eq!(place(&spec(b"crashkernel=1G"), &ram).unwrap_err(), PlaceError::NoSpace);
}

#[test]
fn an_empty_line_places_nothing() {
    assert_eq!(place(&spec(b"quiet"), &ram_all()).unwrap_err(), PlaceError::NotRequested);
}

#[test]
fn the_search_works_downwards_from_the_top_of_a_window() {
    // The bottom of usable memory holds the running kernel, its early
    // bookkeeping and the firmware tables. A search that started there would
    // pick a window whose pages are already spoken for, and the reservation
    // would silently cover somebody else's memory.
    let ram = [RamRange { start: 0, end: 1024 * M }];
    let base = search(&ram, 64 * M, 0, 4 * G).expect("found");
    assert_eq!(base, 1024 * M - 64 * M);
    assert!(base > 512 * M, "a bottom-up search would have answered near zero");
}

#[test]
fn the_search_respects_both_bounds() {
    let ram = [RamRange { start: 0, end: 16 * G }];
    assert!(search(&ram, 64 * M, 0, 4 * G).unwrap() + 64 * M <= 4 * G);
    assert!(search(&ram, 64 * M, 4 * G, 16 * G).unwrap() >= 4 * G);
    assert_eq!(search(&ram, 64 * M, 4 * G, 4 * G + M), None);
}

#[test]
fn the_low_companion_is_reserved_only_when_the_main_region_landed_high() {
    let p = place(&spec(b"crashkernel=1G,high crashkernel=64M,low"), &ram_all()).expect("placed");
    assert!(p.base >= 4 * G);
    assert_eq!(p.low_size, 64 * M);
    assert!(p.low_base + p.low_size <= 4 * G, "low base {:#x}", p.low_base);
}

#[test]
fn a_high_crash_region_gets_linux_default_low_companion() {
    let p = place(&spec(b"crashkernel=1G,high"), &ram_all()).expect("placed");
    assert_eq!(p.low_size, DEFAULT_CRASH_LOW_SIZE);
    assert!(p.low_base + p.low_size <= 4 * G);
}

#[test]
fn the_low_companion_is_skipped_when_the_main_region_is_already_low() {
    let p = place(&spec(b"crashkernel=256M crashkernel=64M,low"), &ram_all()).expect("placed");
    assert!(p.base < 4 * G);
    assert_eq!((p.low_base, p.low_size), (0, 0),
        "a second region for a problem that does not exist is memory spent for nothing");
}

#[test]
fn a_low_companion_that_does_not_fit_aborts_the_whole_reservation() {
    // Half-reserving is the worst outcome: a device that cannot address above
    // the boundary would have nowhere to put its buffers inside the kernel
    // that has to read the dump, and nothing would have said so.
    let ram = [RamRange { start: 0, end: 16 * M }, RamRange { start: 4 * G, end: 16 * G }];
    assert_eq!(place(&spec(b"crashkernel=1G,high crashkernel=64M,low"), &ram).unwrap_err(),
        PlaceError::NoLowSpace);
}

#[test]
fn the_low_companion_stays_below_the_boundary_even_when_high_memory_is_roomier() {
    // The companion exists FOR the device that cannot address above the
    // boundary. A search that were allowed to run past it would answer with
    // the largest window on the machine — which is exactly the memory the
    // device cannot reach — and the reservation would look correct.
    let ram = [RamRange { start: 0, end: 3 * G }, RamRange { start: 4 * G, end: 512 * G }];
    let p = place(&spec(b"crashkernel=1G,high crashkernel=64M,low"), &ram).expect("placed");
    assert!(p.base >= 4 * G);
    assert_eq!(p.low_size, 64 * M);
    assert!(p.low_base + p.low_size <= 4 * G, "low landed at {:#x}", p.low_base);
    // Disjoint by construction, which is why no overlap check is written.
    assert!(p.low_base + p.low_size <= p.base);
}

// --- shrink --------------------------------------------------------------

#[test]
fn a_shrink_rounds_the_request_up() {
    assert_eq!(shrink_target(256 * M, 100 * M + 1, false).unwrap(), 100 * M + CRASH_SHRINK_ALIGN);
    assert_eq!(shrink_target(256 * M, 100 * M, false).unwrap(), 100 * M);
}

#[test]
fn a_shrink_to_the_size_already_reserved_is_a_no_op_not_a_refusal() {
    assert_eq!(shrink_target(256 * M, 256 * M, false).unwrap(), 256 * M);
}

#[test]
fn a_shrink_may_never_grow_the_region() {
    // Growing would have to take pages the page allocator has already handed
    // out; there is no way back from that except a reboot.
    assert_eq!(shrink_target(256 * M, 512 * M, false).unwrap_err(), ShrinkError::Grow);
    assert_eq!(shrink_target(256 * M, 256 * M + 1, false).unwrap_err(), ShrinkError::Grow);
    assert_eq!(shrink_target(256 * M, u64::MAX, false).unwrap_err(), ShrinkError::Grow);
}

#[test]
fn a_shrink_to_zero_releases_the_whole_region() {
    assert_eq!(shrink_target(256 * M, 0, false).unwrap(), 0);
}

#[test]
fn a_staged_crash_image_blocks_a_shrink_before_any_arithmetic() {
    // The reason reported is the reason the caller can act on: unload the
    // image. Reporting a size complaint would send them to fix the number.
    assert_eq!(shrink_target(256 * M, 128 * M, true).unwrap_err(), ShrinkError::Loaded);
    assert_eq!(shrink_target(256 * M, 512 * M, true).unwrap_err(), ShrinkError::Loaded);
    assert_eq!(shrink_target(0, 0, true).unwrap_err(), ShrinkError::Loaded);
}

#[test]
fn a_shrink_with_nothing_reserved_is_refused() {
    assert_eq!(shrink_target(0, 128 * M, false).unwrap_err(), ShrinkError::NoRegion);
}

// --- the live reservation and the load path ------------------------------

#[test]
fn the_load_limits_carry_the_live_reservation() {
    let _g = super::gate::test_lock();
    crate::crashk::clear_for_tests();
    // No reservation: a crash load has nowhere legal to land, which is what a
    // machine booted without the parameter must answer.
    assert_eq!(crate::stage::Limits::current().crash, None);
    assert_eq!(crate::validate::crash_entry_ok(G, crate::stage::Limits::current().crash),
        Err(crate::validate::Error::AddrNotAvail));
    crate::crashk::publish(G, 256 * M);
    let l = crate::stage::Limits::current();
    let r = l.crash.expect("the reservation reaches the load path");
    assert_eq!((r.start, r.end), (G, G + 256 * M - 1));
    // The whole point of the wiring: a crash entry point inside the reserved
    // region is now accepted, and one outside it still is not.
    assert_eq!(crate::validate::crash_entry_ok(G + M, l.crash), Ok(()));
    assert_eq!(crate::validate::crash_entry_ok(G - M, l.crash),
        Err(crate::validate::Error::AddrNotAvail));
    crate::crashk::clear_for_tests();
}

#[test]
fn the_published_range_is_inclusive_of_its_last_byte() {
    let _g = super::gate::test_lock();
    crate::crashk::clear_for_tests();
    crate::crashk::publish(4 * G, 16 * M);
    let r = crate::crashk::crash_range().expect("reserved");
    assert_eq!(r.end, 4 * G + 16 * M - 1, "an exclusive end would admit one page past the region");
    crate::crashk::clear_for_tests();
}

// --- the panic path ------------------------------------------------------

#[test]
fn the_panic_path_attempts_a_crash_boot_only_with_somewhere_to_go() {
    use crate::crashk::panic::crash_boot_wanted;
    assert!(crash_boot_wanted(true, true));
    assert!(!crash_boot_wanted(false, true), "no entry point installed");
    assert!(!crash_boot_wanted(true, false), "nothing reserved, so nothing was staged");
}

#[test]
fn the_crash_boot_hook_round_trips() {
    fn boot() -> bool { false }
    crate::crashk::panic::set_crash_boot_hook(boot);
    assert!(crate::crashk::panic::crash_boot_hook().is_some());
    assert!(!crate::crashk::panic::crash_boot_hook().unwrap()());
}

#[test]
fn a_panic_with_nothing_reserved_falls_through_instead_of_stopping() {
    let _g = super::gate::test_lock();
    crate::crashk::clear_for_tests();
    // Returning is the contract: a machine with no crash image must still
    // print, still snapshot, and still honour the boot line's restart request.
    crate::crashk::panic::crash_kexec();
    crate::crashk::clear_for_tests();
}

#[test]
fn a_placement_is_reported_whole() {
    // `Placement` is what the boot path acts on; a field it forgot to fill
    // would reserve one region and publish another.
    let p: Placement = place(&spec(b"crashkernel=256M"), &ram_all()).expect("placed");
    assert_ne!(p.base, 0);
    assert_ne!(p.size, 0);
}
