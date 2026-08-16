// Idle-state ABI constants: the state flags a driver declares and the two
// reasons a state can be unavailable.

/// A polling state: the CPU spins rather than sleeping. Entering it costs
/// nothing and leaves the local timer running.
pub const FLAG_POLLING: u32 = 1 << 0;

/// Entering the state stops the local timer, so something else has to wake the
/// CPU for a deadline it was going to serve.
pub const FLAG_TIMER_STOP: u32 = 1 << 2;

/// The driver found the state unusable on this hardware. Distinct from a user
/// disabling it: userspace cannot re-enable it.
pub const FLAG_UNUSABLE: u32 = 1 << 3;

/// The state exists but is off until userspace asks for it.
pub const FLAG_OFF: u32 = 1 << 4;

/// Entering the state flushes the translation caches.
pub const FLAG_TLB_FLUSHED: u32 = 1 << 5;

/// Disabled because userspace wrote `disable`.
pub const DISABLED_BY_USER: u32 = 1 << 0;
/// Disabled because the driver declared the state unusable.
pub const DISABLED_BY_DRIVER: u32 = 1 << 1;

/// Longest state name a driver may declare.
pub const NAME_LEN: usize = 16;
/// Longest state description a driver may declare.
pub const DESC_LEN: usize = 32;

/// `default_status` text for a state a driver ships enabled.
pub const STATUS_ENABLED: &str = "enabled";
/// `default_status` text for a state a driver ships off.
pub const STATUS_DISABLED: &str = "disabled";

/// Text for a name or description the driver left empty. A blank line would
/// read as a state with no identity rather than one with none declared.
pub const NULL_TEXT: &str = "<null>";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_state_flags_keep_their_abi_positions() {
        assert_eq!(FLAG_POLLING, 0x01);
        assert_eq!(FLAG_TIMER_STOP, 0x04);
        assert_eq!(FLAG_UNUSABLE, 0x08);
        assert_eq!(FLAG_OFF, 0x10);
        assert_eq!(FLAG_TLB_FLUSHED, 0x20);
    }

    #[test]
    fn the_two_reasons_a_state_is_off_are_separately_recorded() {
        assert_ne!(DISABLED_BY_USER, DISABLED_BY_DRIVER);
        let both = DISABLED_BY_USER | DISABLED_BY_DRIVER;
        assert_ne!(both & DISABLED_BY_USER, 0);
        assert_ne!(both & DISABLED_BY_DRIVER, 0);
        // Clearing the user bit must leave a driver-disabled state disabled.
        assert_ne!((both & !DISABLED_BY_USER), 0);
    }
}
