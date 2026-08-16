// Units, defaults and bounds.
//
// Every frequency in this crate is kilohertz. Firmware reports megahertz and
// device trees report hertz; both are converted at the provider boundary, and
// a figure that skipped the conversion is a thousand- or million-fold error
// that still looks like a plausible clock speed.

/// Kilohertz per megahertz.
pub const KHZ_PER_MHZ: u64 = 1_000;
/// Hertz per kilohertz.
pub const HZ_PER_KHZ: u64 = 1_000;
/// Nanoseconds per microsecond.
pub const NSEC_PER_USEC: u64 = 1_000;
/// Microseconds per millisecond.
pub const USEC_PER_MSEC: u64 = 1_000;

/// Transition latency assumed for a driver that declares none, nanoseconds.
pub const DEFAULT_TRANSITION_LATENCY_NS: u64 = 1_000_000;

/// Most table entries one policy may carry.
pub const MAX_TABLE_ENTRIES: usize = 64;

/// Kilohertz from the megahertz firmware reports. # C: O(1)
pub fn mhz_to_khz(mhz: u64) -> u64 { mhz.saturating_mul(KHZ_PER_MHZ) }

/// Kilohertz from the hertz a device tree reports. # C: O(1)
pub fn hz_to_khz(hz: u64) -> u64 { hz / HZ_PER_KHZ }

/// How often a governor may act, from the driver's declared transition
/// latency.
///
/// Half again the latency: sampling at exactly the transition cost would spend
/// two thirds of the CPU's time in transitions. A driver that declares no
/// latency gets a millisecond, because zero would be a busy loop. # C: O(1)
pub fn transition_delay_us(transition_latency_ns: u64) -> u64 {
    let latency_us = transition_latency_ns / NSEC_PER_USEC;
    if latency_us == 0 { return USEC_PER_MSEC; }
    latency_us + latency_us / 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firmware_megahertz_become_kilohertz() {
        assert_eq!(mhz_to_khz(2_400), 2_400_000);
        assert_eq!(mhz_to_khz(800), 800_000);
        assert_ne!(mhz_to_khz(2_400), 2_400,
                   "an unconverted megahertz figure reads as a 2.4 MHz processor");
    }

    #[test]
    fn device_tree_hertz_become_kilohertz() {
        assert_eq!(hz_to_khz(1_800_000_000), 1_800_000);
        assert_eq!(hz_to_khz(999), 0);
    }

    #[test]
    fn the_sampling_interval_is_half_again_the_transition_cost() {
        assert_eq!(transition_delay_us(10_000), 15, "10 us latency yields 15 us");
        assert_eq!(transition_delay_us(100_000), 150);
        assert_eq!(transition_delay_us(DEFAULT_TRANSITION_LATENCY_NS), 1_500);
    }

    #[test]
    fn a_driver_declaring_no_latency_still_gets_a_finite_interval() {
        assert_eq!(transition_delay_us(0), USEC_PER_MSEC);
        assert_eq!(transition_delay_us(999), USEC_PER_MSEC,
                   "a sub-microsecond latency must not round down to a busy loop");
    }
}
