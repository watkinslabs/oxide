//! The two fault-injection options: what the line says, what the mount arms,
//! and what the mount table reports back.

use syscall::errno::Errno;

use crate::fault::{apply, Fault, Info, ALL_TYPES};
use crate::opts::{parse, show, Options};

fn p(s: &str) -> Result<Options, Errno> { parse(Options::defaults(), s) }

#[test]
fn a_line_that_asks_for_neither_leaves_the_mount_uninjected() {
    let o = Options::defaults();
    assert!(!o.fault.asked());
    assert!(!show(&o).contains("fault"));
}

#[test]
fn the_rate_and_the_site_list_are_taken_separately() {
    let o = p("fault_injection=100").unwrap();
    assert_eq!(o.fault.rate, Some(100));
    assert_eq!(o.fault.types, None);
    let o = p("fault_type=3").unwrap();
    assert_eq!(o.fault.rate, None);
    assert_eq!(o.fault.types, Some(3));
}

#[test]
fn a_site_list_past_the_last_site_but_one_is_taken_and_then_dropped() {
    // The bound the mount interface states is one wider than the set of sites.
    // The single value in between is accepted on the line and refused where
    // the mask is stored, so the mount comes up with nothing armed rather than
    // failing — which is the contract, not a rounding.
    let o = p(&alloc::format!("fault_type={}", ALL_TYPES + 1)).unwrap();
    assert_eq!(o.fault.types, Some(ALL_TYPES + 1));
    let live = Info::new();
    apply(&live, &o.fault);
    assert_eq!(live.types(), 0);
    assert_eq!(p(&alloc::format!("fault_type={}", ALL_TYPES + 2)), Err(Errno::Einval));
}

#[test]
fn a_negative_rate_reaches_a_mount_that_runs_with_injection_off() {
    let o = p("fault_injection=-1").unwrap();
    assert_eq!(o.fault.rate, Some(-1));
    let live = Info::new();
    apply(&live, &o.fault);
    assert_eq!(live.rate(), 0);
}

#[test]
fn a_non_numeric_value_is_refused() {
    assert_eq!(p("fault_injection=often"), Err(Errno::Einval));
    assert_eq!(p("fault_type=all"), Err(Errno::Einval));
    assert_eq!(p("fault_injection"), Err(Errno::Einval));
    assert_eq!(p("fault_type"), Err(Errno::Einval));
}

#[test]
fn what_the_line_asks_for_is_what_the_mount_arms() {
    let mask = Fault::ReadIo.bit() | Fault::WriteIo.bit();
    let o = p(&alloc::format!("fault_injection=1,fault_type={mask}")).unwrap();
    let live = Info::new();
    apply(&live, &o.fault);
    assert!(live.armed(Fault::ReadIo));
    assert!(live.armed(Fault::WriteIo));
    assert!(!live.armed(Fault::Kmalloc));
    assert_eq!(live.rate(), 1);
}

#[test]
fn an_injected_mount_never_looks_like_an_uninjected_one() {
    // A volume running with failures injected on purpose must be visible as
    // such in the mount table; a short line would make a test rig
    // indistinguishable from a real one.
    let o = p("fault_injection=7,fault_type=5").unwrap();
    let line = show(&o);
    assert!(line.contains(",fault_injection=7"), "{line}");
    assert!(line.contains(",fault_type=5"), "{line}");
}

#[test]
fn the_two_options_round_trip_through_their_own_rendering() {
    for line in ["fault_injection=9", "fault_type=64", "fault_injection=2,fault_type=1"] {
        let o = p(line).unwrap();
        assert_eq!(parse(Options::defaults(), &show(&o)).unwrap(), o, "{line}");
    }
}
