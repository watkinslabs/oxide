use core::sync::atomic::{AtomicU64, Ordering};

const BASE_SHIFT: u32 = 0;
const DYNAMIC_SHIFT: u32 = 5;
const RELATIVE_SHIFT: u32 = 10;
const BOOST_DISABLED_SHIFT: u32 = 15;
const SATURATED_SHIFT: u32 = 16;
const DECREMENT_SHIFT: u32 = 17;
const INCREMENT_SHIFT: u32 = 22;
const REASON_SHIFT: u32 = 27;
const RESET_SHIFT: u32 = 29;
const REMAINING_SHIFT: u32 = 45;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NtAdjustReason { None, Boost, Unwait }

impl NtAdjustReason {
    const fn from_raw(raw: u8) -> Self {
        match raw { 1 => Self::Boost, 2 => Self::Unwait, _ => Self::None }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtSchedSnapshot {
    pub base_priority: u8,
    pub dynamic_priority: u8,
    pub relative_priority: i8,
    pub relative_saturated: bool,
    pub boost_disabled: bool,
    pub priority_decrement: u8,
    pub adjust_increment: u8,
    pub adjust_reason: NtAdjustReason,
    pub quantum_reset: u16,
    pub quantum_remaining: u16,
}

impl NtSchedSnapshot {
    pub(crate) fn new(level: u8, quantum: u32) -> Self {
        let quantum = quantum.clamp(1, u16::MAX as u32) as u16;
        Self { base_priority: level, dynamic_priority: level, relative_priority: 0,
            relative_saturated: false, boost_disabled: false, priority_decrement: 0,
            adjust_increment: 0, adjust_reason: NtAdjustReason::None,
            quantum_reset: quantum, quantum_remaining: quantum }
    }

    pub(crate) fn pack(self) -> u64 {
        debug_assert!((1..=31).contains(&self.base_priority));
        debug_assert!((1..=31).contains(&self.dynamic_priority));
        debug_assert!((-15..=15).contains(&self.relative_priority));
        (self.base_priority as u64) << BASE_SHIFT
            | (self.dynamic_priority as u64) << DYNAMIC_SHIFT
            | ((self.relative_priority + 15) as u64) << RELATIVE_SHIFT
            | (self.boost_disabled as u64) << BOOST_DISABLED_SHIFT
            | (self.relative_saturated as u64) << SATURATED_SHIFT
            | (self.priority_decrement as u64) << DECREMENT_SHIFT
            | (self.adjust_increment as u64) << INCREMENT_SHIFT
            | (self.adjust_reason as u64) << REASON_SHIFT
            | (self.quantum_reset as u64) << RESET_SHIFT
            | (self.quantum_remaining as u64) << REMAINING_SHIFT
    }

    fn unpack(word: u64) -> Self {
        Self {
            base_priority: ((word >> BASE_SHIFT) & 31) as u8,
            dynamic_priority: ((word >> DYNAMIC_SHIFT) & 31) as u8,
            relative_priority: ((word >> RELATIVE_SHIFT) & 31) as i8 - 15,
            boost_disabled: word & (1 << BOOST_DISABLED_SHIFT) != 0,
            relative_saturated: word & (1 << SATURATED_SHIFT) != 0,
            priority_decrement: ((word >> DECREMENT_SHIFT) & 31) as u8,
            adjust_increment: ((word >> INCREMENT_SHIFT) & 31) as u8,
            adjust_reason: NtAdjustReason::from_raw(((word >> REASON_SHIFT) & 3) as u8),
            quantum_reset: ((word >> RESET_SHIFT) & 0xffff) as u16,
            quantum_remaining: ((word >> REMAINING_SHIFT) & 0xffff) as u16,
        }
    }
}

pub(crate) struct NtEntityState(AtomicU64);

impl NtEntityState {
    pub(crate) fn new(level: u8, quantum: u32) -> Self {
        Self(AtomicU64::new(NtSchedSnapshot::new(level, quantum).pack()))
    }
    pub(crate) fn load(&self) -> NtSchedSnapshot {
        NtSchedSnapshot::unpack(self.0.load(Ordering::Acquire))
    }
    pub(crate) fn store(&self, state: NtSchedSnapshot) {
        self.0.store(state.pack(), Ordering::Release);
    }
}
