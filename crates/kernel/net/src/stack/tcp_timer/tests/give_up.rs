use super::give_up_cause;
use syscall::errno::Errno;

/// A connection that recorded a non-fatal report reports THAT when it runs
/// out of retransmissions; one that recorded nothing reports the timeout.
#[test]
fn the_give_up_cause_prefers_the_recorded_non_fatal_error() {
    assert_eq!(give_up_cause(0), Errno::Etimedout as i32);
    assert_eq!(give_up_cause(Errno::Ehostunreach as i32), Errno::Ehostunreach as i32);
}
