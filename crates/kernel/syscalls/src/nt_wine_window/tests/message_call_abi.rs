use super::*;

/// The wide title that exposed the defect, as the sender holds it.
const TITLE: &str = "Untitled - Notepad";

/// Units of a wide message string that survive delivery under one published
/// source encoding. A sender published as ANSI is measured as a byte string,
/// so a wide buffer ends at the high byte of its first character; a sender
/// published as Unicode is measured in units and arrives whole.
fn delivered_units(ansi: bool, wide: &[u16]) -> usize {
    if !ansi { return wide.iter().take_while(|unit| **unit != 0).count(); }
    let bytes: alloc::vec::Vec<u8> = wide.iter().flat_map(|unit| unit.to_le_bytes()).collect();
    bytes.iter().take_while(|byte| **byte != 0).count()
}

fn title_units() -> alloc::vec::Vec<u16> { TITLE.encode_utf16().collect() }

#[test]
fn selector_comes_from_sixth_argument_and_only_seventh_is_read() {
    for ansi in [0, 1, u64::MAX] {
        let mut reads = alloc::vec::Vec::new();
        assert_eq!(tail(0xffff_ffff_0000_1234, |index| { reads.push(index); (index == 6).then_some(ansi) }), Some((0x1234, ansi != 0)));
        assert_eq!(reads, [6]);
    }
}

#[test]
fn ansi_fault_is_not_silently_unicode() { assert_eq!(tail(0x1234, |_| None), None); }

/// A caller's leftover high half of the argument slot is not the flag.
#[test]
fn a_unicode_sender_stays_unicode_under_stack_residue() {
    for residue in [0xffff_ffff_0000_0000u64, 0x0000_0001_0000_0000, 0xdead_beef_0000_0000] {
        assert_eq!(tail(0x02b1, |_| Some(residue)), Some((0x02b1, false)));
    }
    for set in [1u64, 0xffff_ffff, 0xdead_beef_0000_0001] {
        assert_eq!(tail(0x02b1, |_| Some(set)), Some((0x02b1, true)));
    }
}

/// The observed failure, end to end: the send that carries the window title
/// arrives with residue in the slot's high half, and every unit must survive.
#[test]
fn a_wide_window_title_survives_a_send_whose_flag_slot_carries_residue() {
    let title = title_units();
    assert_eq!(title.len(), 18);
    let residue = 0xffff_ffff_0000_0000u64;
    let (_, ansi) = tail(0x02b1, |_| Some(residue)).unwrap();
    assert_eq!(delivered_units(ansi, &title), 18);
    // The same title under the encoding a widened slot would publish is the
    // single wide 'U' the failing boot showed.
    assert_eq!(delivered_units(true, &title), 1);
}
