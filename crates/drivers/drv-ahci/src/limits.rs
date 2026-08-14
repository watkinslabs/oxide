//! AHCI command and dispatch-wait limit contracts.

/// Deadline starts after a command owns the port and is issued to hardware.
pub(crate) const COMMAND_TIMEOUT_NS: u64 = 5_000_000_000;

/// Port arbitration has no command deadline: release or device removal wakes it.
pub(crate) const QUEUE_WAIT_DEADLINE_NS: u64 = 0;

#[cfg(test)]
mod tests {
    use super::{COMMAND_TIMEOUT_NS, QUEUE_WAIT_DEADLINE_NS};

    #[test]
    fn port_arbitration_does_not_consume_the_active_command_timeout() {
        assert_eq!(QUEUE_WAIT_DEADLINE_NS, 0);
        assert_ne!(COMMAND_TIMEOUT_NS, QUEUE_WAIT_DEADLINE_NS);
    }
}
