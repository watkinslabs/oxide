use super::*;

const NOBODY: Consumer = Consumer { pid: 0, port_id: 0, route: 0 };
const LIVE: Consumer = Consumer { pid: 100, port_id: 7, route: 0 };

#[test]
fn nobody_is_registered_until_someone_registers() {
    assert!(!NOBODY.registered());
    assert!(LIVE.registered());
}

#[test]
fn a_caller_registers_itself() {
    assert_eq!(pid_action(NOBODY, 100, 100), Ok(PidAction::Register));
}

/// A control client may not point the record stream at an unrelated process:
/// the pid it names must be its own.
#[test]
fn a_caller_may_not_register_another_process() {
    assert_eq!(pid_action(NOBODY, 100, 101), Err(Errno::Einval));
    assert_eq!(pid_action(LIVE, 100, 101), Err(Errno::Einval),
        "the ownership check runs before the replacement check");
}

/// Replacing a live consumer is refused rather than silently taking over — the
/// running daemon would otherwise stop receiving records with no indication.
#[test]
fn a_healthy_consumer_cannot_be_replaced() {
    assert_eq!(pid_action(LIVE, 200, 200), Err(Errno::Eexist));
    assert_eq!(pid_action(LIVE, 100, 100), Err(Errno::Eexist),
        "even the registered consumer re-registering is a replacement");
}

#[test]
fn only_the_registered_consumer_may_stand_down() {
    assert_eq!(pid_action(LIVE, 100, 0), Ok(PidAction::Unregister));
    assert_eq!(pid_action(LIVE, 200, 0), Err(Errno::Eacces));
}

/// Unregistering when nobody is registered is not an error: a daemon shutting
/// down after the kernel already dropped it must not fail.
#[test]
fn unregistering_an_absent_consumer_succeeds() {
    assert_eq!(pid_action(NOBODY, 100, 0), Ok(PidAction::Unregister));
}
