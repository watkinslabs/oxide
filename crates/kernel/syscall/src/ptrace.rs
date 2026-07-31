// ptrace(2) ABI numbers that the wait(2) family has to understand: the
// `PTRACE_EVENT_*` codes a tracee's stop reports, and how they compose into
// the stop code a wait status carries. Numbers + pure composition only, no
// policy — the request dispatch and permission ladder stay in `syscalls`.
//
// These live in the ABI crate rather than beside the ptrace dispatcher because
// the wait engine and the stop-code encoder both need them, and a second copy
// next to `wait.rs` would be a split source of truth.

/// `SIGTRAP` — the signal every ptrace event stop reports as.
pub const SIGTRAP: i32 = 5;

/// `PTRACE_O_TRACESYSGOOD` sets bit 7 of the reported signal so a tracer can
/// tell a syscall-entry/exit stop from a real SIGTRAP.
pub const SYSCALL_STOP_BIT: i32 = 0x80;

/// `PTRACE_EVENT_*` codes, reported in the second byte of the stop code.
pub const EVENT_FORK:       u32 = 1;
pub const EVENT_VFORK:      u32 = 2;
pub const EVENT_CLONE:      u32 = 3;
pub const EVENT_EXEC:       u32 = 4;
pub const EVENT_VFORK_DONE: u32 = 5;
pub const EVENT_EXIT:       u32 = 6;
pub const EVENT_SECCOMP:    u32 = 7;
pub const EVENT_STOP:       u32 = 128;

/// Bits the event code occupies inside a stop code.
pub const EVENT_SHIFT: u32 = 8;

/// Stop code for a `PTRACE_EVENT_*` stop: `SIGTRAP | (event << 8)`. The wait
/// status then shifts this left another 8 and ORs `0x7f`, so userspace reads
/// `WSTOPSIG() == SIGTRAP` and `status >> 16 == event`.
/// # C: O(1)
pub const fn event_stop_code(event: u32) -> i32 { SIGTRAP | ((event as i32) << EVENT_SHIFT) }

/// Stop code for a syscall-entry/exit stop under `PTRACE_O_TRACESYSGOOD`.
/// # C: O(1)
pub const fn syscall_stop_code() -> i32 { SIGTRAP | SYSCALL_STOP_BIT }

/// The `PTRACE_EVENT_*` code carried by a stop code, 0 for a plain signal
/// stop. Inverse of `event_stop_code`. # C: O(1)
pub const fn event_of_stop_code(code: i32) -> u32 { ((code >> EVENT_SHIFT) as u32) & 0xff }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_event_stop_code_round_trips_through_its_event_byte() {
        for e in [EVENT_FORK, EVENT_VFORK, EVENT_CLONE, EVENT_EXEC,
                  EVENT_VFORK_DONE, EVENT_EXIT, EVENT_SECCOMP, EVENT_STOP] {
            let code = event_stop_code(e);
            assert_eq!(code & 0xff, SIGTRAP, "event {e} must still report as SIGTRAP");
            assert_eq!(event_of_stop_code(code), e);
        }
    }

    #[test]
    fn a_syscall_stop_sets_bit_7_and_carries_no_event() {
        assert_eq!(syscall_stop_code(), 0x85);
        assert_eq!(event_of_stop_code(syscall_stop_code()), 0);
    }

    #[test]
    fn a_plain_signal_stop_code_carries_no_event() {
        assert_eq!(event_of_stop_code(SIGTRAP), 0);
        assert_eq!(event_of_stop_code(19), 0);
    }
}
