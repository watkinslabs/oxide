use crate::diag::sysrq::table::{decode, Cmd, KEYS};

/// The letters an operator already knows. `c` crashes and `b` reboots on every
/// other machine they will ever touch; this kernel bound `c` to a per-CPU dump
/// and `b` to a backtrace, so both of the keys that take a machine down printed
/// a table instead.
#[test]
fn the_keys_that_take_a_machine_down_are_the_reference_letters() {
    assert_eq!(decode(b'c'), Cmd::Crash);
    assert_eq!(decode(b'b'), Cmd::Reboot);
    assert_eq!(decode(b'o'), Cmd::PowerOff);
}

#[test]
fn the_dump_keys_are_the_reference_letters() {
    assert_eq!(decode(b't'), Cmd::ShowTasks);
    assert_eq!(decode(b'w'), Cmd::ShowBlocked);
    assert_eq!(decode(b'l'), Cmd::ShowBacktraceAllCpus);
    assert_eq!(decode(b'p'), Cmd::ShowRegisters);
}

/// An upper-case letter is not the same command in a different case: the shift
/// key is how a key press arrives already, and folding it would let a shifted
/// keystroke crash a machine.
#[test]
fn case_is_significant() {
    assert_eq!(decode(b'C'), Cmd::Unbound(b'C'));
    assert_eq!(decode(b'B'), Cmd::Unbound(b'B'));
}

#[test]
fn an_unbound_key_is_distinguishable_from_asking_for_help() {
    assert_eq!(decode(b'h'), Cmd::Help);
    assert_eq!(decode(b'z'), Cmd::Unbound(b'z'));
}

/// Every key the list names is bound, and every bound key that is not `h` is
/// named. A list that drifts from the table is how a key stops being
/// discoverable.
#[test]
fn the_help_list_is_exactly_the_bound_keys() {
    for &(key, _) in KEYS {
        assert!(!matches!(decode(key), Cmd::Unbound(_) | Cmd::Help),
                "{} is listed but not a command", key as char);
    }
    for key in 0x20u8..0x7f {
        let bound = !matches!(decode(key), Cmd::Unbound(_) | Cmd::Help);
        assert_eq!(bound, KEYS.iter().any(|&(k, _)| k == key),
                   "{} is bound but not listed, or the reverse", key as char);
    }
}
