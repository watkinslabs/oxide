use super::{NtAdjustReason, NtSchedSnapshot};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NtPriorityClass { Idle, BelowNormal, Normal, AboveNormal, High, Realtime }

impl NtPriorityClass {
    pub const fn base(self) -> u8 {
        match self { Self::Idle => 4, Self::BelowNormal => 6, Self::Normal => 8,
            Self::AboveNormal => 10, Self::High => 13, Self::Realtime => 24 }
    }
    pub const fn realtime(self) -> bool { matches!(self, Self::Realtime) }
    const fn row(self) -> usize { self as usize }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NtRelativePriority { Idle, Lowest, BelowNormal, Normal, AboveNormal, Highest, TimeCritical }

impl NtRelativePriority {
    const fn column(self) -> usize { self as usize }
    pub const fn increment(self) -> i8 {
        match self { Self::Idle => -15, Self::Lowest => -2, Self::BelowNormal => -1,
            Self::Normal => 0, Self::AboveNormal => 1, Self::Highest => 2,
            Self::TimeCritical => 15 }
    }
}

const CLASS_RELATIVE: [[u8; 7]; 6] = [
    [1, 2, 3, 4, 5, 6, 15], [1, 4, 5, 6, 7, 8, 15],
    [1, 6, 7, 8, 9, 10, 15], [1, 8, 9, 10, 11, 12, 15],
    [1, 11, 12, 13, 14, 15, 15], [16, 22, 23, 24, 25, 26, 31],
];

pub const fn class_relative_priority(class: NtPriorityClass, relative: NtRelativePriority) -> u8 {
    CLASS_RELATIVE[class.row()][relative.column()]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtQuantumPolicy { FixedShort, FixedLong, VariableShort, VariableLong }

impl NtQuantumPolicy {
    pub const fn quantum(self, separation: u8, idle: bool) -> u16 {
        if idle { return 6; }
        let i = if separation > 2 { 2 } else { separation } as usize;
        match self { Self::FixedShort => [18, 18, 18][i],
            Self::FixedLong => [36, 36, 36][i],
            Self::VariableShort => [6, 12, 18][i],
            Self::VariableLong => [12, 24, 36][i] }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NtTickOutcome { pub expired: bool, pub priority_changed: bool }

pub(crate) fn tick(mut state: NtSchedSnapshot) -> (NtSchedSnapshot, NtTickOutcome) {
    if state.quantum_remaining > 1 {
        state.quantum_remaining -= 1;
        return (state, NtTickOutcome { expired: false, priority_changed: false });
    }
    state.quantum_remaining = state.quantum_reset;
    state.adjust_reason = NtAdjustReason::None;
    state.adjust_increment = 0;
    if state.dynamic_priority >= 16 {
        return (state, NtTickOutcome { expired: true, priority_changed: false });
    }
    let old = state.dynamic_priority;
    state.dynamic_priority = old.saturating_sub(state.priority_decrement.saturating_add(1))
        .max(state.base_priority);
    state.priority_decrement = 0;
    (state, NtTickOutcome { expired: true, priority_changed: state.dynamic_priority != old })
}

pub(crate) fn boost(mut state: NtSchedSnapshot, increment: u8) -> NtSchedSnapshot {
    state.adjust_reason = NtAdjustReason::None;
    state.adjust_increment = 0;
    if state.boost_disabled || state.dynamic_priority >= 13 || state.dynamic_priority > increment {
        return state;
    }
    let next = increment.saturating_add(1).min(13);
    state.priority_decrement = state.priority_decrement
        .saturating_add(next - state.dynamic_priority).min(31);
    state.dynamic_priority = next;
    state.quantum_remaining = state.quantum_remaining.max(4) - 1;
    state
}

pub(crate) fn unwait(mut state: NtSchedSnapshot, increment: u8, separation: u8,
                     kernel_apc: bool) -> NtSchedSnapshot {
    state.adjust_reason = NtAdjustReason::None;
    state.adjust_increment = 0;
    if state.dynamic_priority >= 16 || state.boost_disabled || state.priority_decrement != 0 {
        return state;
    }
    let base_boost = state.base_priority.saturating_add(increment).min(15);
    let wanted = base_boost.saturating_add(separation.min(2)).min(15);
    state.dynamic_priority = state.dynamic_priority.max(wanted);
    state.priority_decrement = state.dynamic_priority.saturating_sub(base_boost);
    if state.base_priority >= 14 || (state.priority_decrement == 0 && increment != 0) {
        state.quantum_remaining = state.quantum_reset;
    }
    if !kernel_apc && state.quantum_remaining > 0 { state.quantum_remaining -= 1; }
    state
}
