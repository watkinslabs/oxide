use core::sync::atomic::AtomicU64;

use crate::diag::sysrq::rx::{advance, decide, RxStep, ARM_WINDOW_NS, DISARMED, SYSRQ_ARM};
use crate::diag::sysrq::table::Cmd;

/// A notional clock. `decide` takes the time as an argument precisely so the
/// expiry is checkable with no clock, no interrupt and no machine.
const T0: u64 = 1_000_000_000;

fn arm_at(now: u64) -> u64 {
    match decide(DISARMED, now, SYSRQ_ARM) {
        RxStep::Armed(deadline) => deadline,
        other => panic!("a break did not arm the line: {other:?}"),
    }
}

/// The sequence the boot gate types at every guest, byte for byte: a break
/// arms the line, and the byte after it is the command. `?` is bound to
/// nothing, which is deliberately how the gate asks for the key list — it
/// wants an answer that cannot take the machine down.
#[test]
fn a_break_then_a_key_is_the_typed_console_sequence() {
    let deadline = arm_at(T0);
    assert_eq!(decide(deadline, T0, b'?'), RxStep::Run(Cmd::Unbound(b'?')));
    assert_eq!(decide(deadline, T0, b't'), RxStep::Run(Cmd::ShowTasks));
}

/// An unarmed ordinary byte belongs to the tty. Consuming it here would swallow
/// every character typed at the console.
#[test]
fn an_unarmed_ordinary_byte_goes_to_the_tty() {
    for b in [b'a', b'?', b't', b'\r', b'\n', 0xff] {
        assert_eq!(decide(DISARMED, T0, b), RxStep::Passthrough, "byte {b:#x} was eaten");
    }
}

/// **The window expires.** A break followed by silence must not leave a console
/// one keystroke from a deliberate panic — which is exactly what a bare armed
/// flag did: it was cleared only by the next byte to arrive, so a single stray
/// zero on the wire armed the machine for as long as it ran, and the next
/// character that happened along, minutes or days later, was taken as a
/// command. On our boot line `b` reboots and `c` panics.
///
/// The reference bounds the window at five seconds and gates every dispatch on
/// the current time still being before the stored deadline.
#[test]
fn the_armed_window_expires_and_a_later_key_reaches_the_tty() {
    let deadline = arm_at(T0);
    assert_eq!(deadline, T0 + ARM_WINDOW_NS, "the window is not the reference's five seconds");

    // One nanosecond inside the window: the dangerous keys still answer, or
    // this test would pass for the wrong reason.
    assert_eq!(decide(deadline, deadline - 1, b'b'), RxStep::Run(Cmd::Reboot));
    assert_eq!(decide(deadline, deadline - 1, b'c'), RxStep::Run(Cmd::Crash));

    // The instant the deadline arrives, and long after it: nothing dispatches
    // and the byte is the tty's.
    for now in [deadline, deadline + 1, deadline + 60 * ARM_WINDOW_NS, u64::MAX] {
        for b in [b'b', b'c', b'o', b't', b'h'] {
            assert_eq!(decide(deadline, now, b), RxStep::Passthrough,
                       "byte {b:#x} dispatched {}ns past the deadline", now - deadline);
        }
    }
}

/// Every path out of an armed line disarms it, so an expired window cannot be
/// re-entered by the byte that found it expired.
#[test]
fn every_step_out_of_an_armed_line_disarms_it() {
    let deadline = arm_at(T0);
    assert_eq!(decide(deadline, T0, b't').next_armed_until(), DISARMED);
    assert_eq!(decide(deadline, deadline, b't').next_armed_until(), DISARMED);
    assert_eq!(decide(deadline, T0, SYSRQ_ARM).next_armed_until(), DISARMED);
    assert_eq!(decide(DISARMED, T0, b't').next_armed_until(), DISARMED);
    assert_eq!(decide(DISARMED, T0, SYSRQ_ARM).next_armed_until(), deadline);
}

/// A deadline can never be mistaken for the disarmed sentinel, whatever the
/// clock reads — otherwise arming at time zero would arm nothing, and a machine
/// whose counter had not started would silently have no sysrq at all.
#[test]
fn an_armed_deadline_is_never_the_disarmed_sentinel() {
    for now in [0, 1, T0, u64::MAX - 1, u64::MAX] {
        assert_ne!(arm_at(now), DISARMED, "arming at {now} produced the disarmed sentinel");
    }
}

/// A second zero is not a command. The reference guards its dispatch on the
/// byte being non-zero, and its break handler clears the armed state when a
/// break arrives on an already-armed port; both leave the byte to the tty. Two
/// zeros on the wire therefore leave no trace — where this kernel used to
/// answer the second one with the key list and swallow a byte the tty should
/// have seen.
#[test]
fn a_second_break_is_not_a_command_byte() {
    let deadline = arm_at(T0);
    assert_eq!(decide(deadline, T0, SYSRQ_ARM), RxStep::Passthrough);
}

/// Exactly one byte value arms the line; an armed line inside its window takes
/// every byte EXCEPT zero as a command, and zero disarms.
#[test]
fn exactly_one_byte_arms_the_line() {
    let deadline = arm_at(T0);
    for b in 0u8..=0xff {
        assert_eq!(decide(DISARMED, T0, b) == RxStep::Armed(deadline), b == SYSRQ_ARM,
                   "byte {b:#x} armed the line, or the break failed to");
        let step = decide(deadline, T0, b);
        if b == SYSRQ_ARM {
            assert_eq!(step, RxStep::Passthrough, "a second break was taken as a command");
        } else {
            assert!(matches!(step, RxStep::Run(_)),
                    "byte {b:#x} was not taken as a command on an armed line");
        }
    }
}

#[test]
fn a_break_arms_only_the_uart_that_received_it() {
    let a = AtomicU64::new(DISARMED);
    let b = AtomicU64::new(DISARMED);

    assert!(matches!(advance(&a, T0, SYSRQ_ARM), RxStep::Armed(_)));
    assert_eq!(advance(&b, T0, b't'), RxStep::Passthrough,
        "a key on another UART completed the first UART's SysRq sequence");
    assert_eq!(advance(&a, T0, b't'), RxStep::Run(Cmd::ShowTasks));
}
