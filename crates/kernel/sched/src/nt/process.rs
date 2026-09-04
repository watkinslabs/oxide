use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use crate::Task;
use super::{NtPriorityClass, NtQuantumPolicy, NtSchedSnapshot};
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
use super::{boost, tick, unwait, NtAdjustReason, NtTickOutcome};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtProcessSchedConfig {
    pub class: NtPriorityClass,
    pub base_priority: u8,
    pub boost_disabled: bool,
    pub foreground: bool,
    pub separation: u8,
    pub quantum_policy: NtQuantumPolicy,
}

impl Default for NtProcessSchedConfig {
    fn default() -> Self {
        Self { class: NtPriorityClass::Normal, base_priority: 8, boost_disabled: false,
            foreground: false, separation: 0, quantum_policy: NtQuantumPolicy::VariableShort }
    }
}

impl NtProcessSchedConfig {
    fn quantum(self, priority: u8) -> u16 {
        self.quantum_policy.quantum(if self.foreground { self.separation } else { 0 }, priority == 1)
    }
    fn realtime(self) -> bool { self.base_priority >= 16 }
}

pub(crate) struct NtProcessState {
    pub(crate) config: NtProcessSchedConfig,
    members: Vec<Weak<Task>>,
}

impl NtProcessState {
    pub(crate) fn new() -> Self { Self { config: NtProcessSchedConfig::default(), members: Vec::new() } }
    pub(crate) fn register(&mut self, task: &Arc<Task>) {
        self.members.retain(|member| member.strong_count() != 0);
        if self.members.iter().any(|member| member.ptr_eq(&Arc::downgrade(task))) { return; }
        self.members.push(Arc::downgrade(task));
    }
    fn live_members(&mut self) -> Vec<Arc<Task>> {
        self.members.retain(|member| member.strong_count() != 0);
        self.members.iter().filter_map(Weak::upgrade).collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtSchedError { InvalidPriority, PrivilegeNotHeld }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtProcessSchedRequest {
    PriorityClass { class: NtPriorityClass, foreground: Option<bool>, may_increase: bool },
    BasePriority { priority: u8, may_increase: bool },
    PriorityBoost { disabled: bool },
    Foreground { foreground: bool, separation: u8 },
    QuantumPolicy(NtQuantumPolicy),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtThreadSchedRequest {
    Priority { priority: u8, may_increase: bool },
    BasePriority(i8),
    PriorityBoost { disabled: bool },
    Boost { increment: u8 },
    Unwait { increment: u8, kernel_apc: bool },
}

#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
enum ProcessChange { Priority { old: u8 }, Boost, Quantum }

#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub fn apply_nt_process(group: &crate::thread_group::ThreadGroup,
                        request: NtProcessSchedRequest) -> Result<(), NtSchedError> {
    group.with_nt_sched(|state| {
        let old = state.config;
        let (next, change) = validate_process_request(old, request)?;
        let members = state.live_members();
        for task in &members {
            crate::live::runqueue::mutate_nt(task, |task| {
                let current = task.sched.nt_snapshot();
                let updated = match change {
                    ProcessChange::Priority { old } => process_priority(current, old, next),
                    ProcessChange::Boost => NtSchedSnapshot { boost_disabled: next.boost_disabled, ..current },
                    ProcessChange::Quantum => requantum(current, next),
                };
                task.sched.store_nt_unlocked(updated);
            });
            crate::live::pi_boost::notify_waiter_change(task);
        }
        state.config = next;
        Ok(())
    })
}

#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
fn validate_process_request(mut config: NtProcessSchedConfig, request: NtProcessSchedRequest)
    -> Result<(NtProcessSchedConfig, ProcessChange), NtSchedError> {
    let change = match request {
        NtProcessSchedRequest::PriorityClass { class, foreground, may_increase } => {
            let base = class.base();
            if class.realtime() && !config.class.realtime() && !may_increase {
                return Err(NtSchedError::PrivilegeNotHeld);
            }
            let old = config.base_priority;
            config.class = class;
            config.base_priority = base;
            if let Some(foreground) = foreground { config.foreground = foreground; }
            ProcessChange::Priority { old }
        }
        NtProcessSchedRequest::BasePriority { priority, may_increase } => {
            if !(1..=31).contains(&priority) { return Err(NtSchedError::InvalidPriority); }
            if priority > config.base_priority && !may_increase {
                return Err(NtSchedError::PrivilegeNotHeld);
            }
            let old = config.base_priority;
            config.base_priority = priority;
            config.class = if priority >= 16 { NtPriorityClass::Realtime } else { config.class };
            ProcessChange::Priority { old }
        }
        NtProcessSchedRequest::PriorityBoost { disabled } => {
            config.boost_disabled = disabled;
            ProcessChange::Boost
        }
        NtProcessSchedRequest::Foreground { foreground, separation } => {
            if separation > 2 { return Err(NtSchedError::InvalidPriority); }
            config.foreground = foreground;
            config.separation = separation;
            ProcessChange::Quantum
        }
        NtProcessSchedRequest::QuantumPolicy(policy) => {
            config.quantum_policy = policy;
            ProcessChange::Quantum
        }
    };
    Ok((config, change))
}

#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
fn process_priority(mut task: NtSchedSnapshot, old_process_base: u8,
                    config: NtProcessSchedConfig) -> NtSchedSnapshot {
    let delta = config.base_priority as i16 - old_process_base as i16;
    let (low, high) = if config.realtime() { (16, 31) } else { (1, 15) };
    task.base_priority = (task.base_priority as i16 + delta).clamp(low, high) as u8;
    task.dynamic_priority = task.base_priority;
    task.priority_decrement = 0;
    task.adjust_increment = 0;
    task.adjust_reason = NtAdjustReason::None;
    task.quantum_reset = config.quantum(task.base_priority);
    task.quantum_remaining = task.quantum_reset;
    task
}

#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
fn requantum(mut task: NtSchedSnapshot, config: NtProcessSchedConfig) -> NtSchedSnapshot {
    task.quantum_reset = config.quantum(task.base_priority);
    task.quantum_remaining = task.quantum_reset;
    task
}

#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub fn apply_nt_thread(task: &Arc<Task>, request: NtThreadSchedRequest)
    -> Result<(), NtSchedError> {
    let config = task.thread_group.nt_sched_config();
    let update = validate_thread_request(task.sched.nt_snapshot(), config, request)?;
    crate::live::runqueue::mutate_nt(task, |task| task.sched.store_nt_unlocked(update));
    crate::live::pi_boost::notify_waiter_change(task);
    Ok(())
}

#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
fn validate_thread_request(mut state: NtSchedSnapshot, config: NtProcessSchedConfig,
                           request: NtThreadSchedRequest) -> Result<NtSchedSnapshot, NtSchedError> {
    match request {
        NtThreadSchedRequest::Priority { priority, may_increase } => {
            if !(1..=31).contains(&priority) { return Err(NtSchedError::InvalidPriority); }
            if priority >= 16 && !may_increase { return Err(NtSchedError::PrivilegeNotHeld); }
            if state.dynamic_priority != priority {
                state.dynamic_priority = priority;
                state.priority_decrement = 0;
                state.quantum_remaining = state.quantum_reset;
            }
        }
        NtThreadSchedRequest::BasePriority(relative) => {
            if !valid_relative(relative, config.realtime()) { return Err(NtSchedError::InvalidPriority); }
            let (base, saturated) = derive_thread_base(config.base_priority, relative, config.realtime());
            let decayed = state.dynamic_priority.saturating_sub(
                state.priority_decrement.saturating_add(1)).max(state.base_priority);
            let shifted = decayed as i16 + base as i16 - state.base_priority as i16;
            state.base_priority = base;
            state.dynamic_priority = if config.realtime() || saturated { base }
                else { shifted.clamp(1, 15) as u8 };
            state.relative_priority = relative;
            state.relative_saturated = saturated;
            state.priority_decrement = 0;
            state.quantum_reset = config.quantum(base);
            state.quantum_remaining = state.quantum_reset;
        }
        NtThreadSchedRequest::PriorityBoost { disabled } => state.boost_disabled = disabled,
        NtThreadSchedRequest::Boost { increment } => state = boost(state, increment.min(15)),
        NtThreadSchedRequest::Unwait { increment, kernel_apc } => {
            let separation = if config.foreground { config.separation } else { 0 };
            state = unwait(state, increment.min(15), separation, kernel_apc);
        }
    }
    Ok(state)
}

#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
fn valid_relative(relative: i8, realtime: bool) -> bool {
    relative == -15 || relative == 15 || if realtime {
        (-7..=6).contains(&relative)
    } else { (-2..=2).contains(&relative) }
}

#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
fn derive_thread_base(process_base: u8, relative: i8, realtime: bool) -> (u8, bool) {
    if relative == -15 { return (if realtime { 16 } else { 1 }, true); }
    if relative == 15 { return (if realtime { 31 } else { 15 }, true); }
    let (low, high) = if realtime { (16, 31) } else { (1, 15) };
    let raw = process_base as i16 + relative as i16;
    (raw.clamp(low, high) as u8, raw < low || raw > high)
}

pub fn initialize_new_thread(task: &Task) {
    let config = task.thread_group.nt_sched_config();
    let level = config.base_priority;
    let mut state = NtSchedSnapshot::new(level, config.quantum(level) as u32);
    state.boost_disabled = config.boost_disabled;
    task.sched.store_nt_unlocked(state);
}

/// Move the running task into its process's native scheduler configuration.
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub fn initialize_current_process(task: &Task) {
    let rq = crate::live::runqueue::global().expect("native exec requires an installed runqueue");
    // SAFETY: exec runs preempt-disabled on the current task.
    let current = unsafe { rq.current_arc() };
    assert!(core::ptr::eq(current.as_ref(), task),
        "native process initialization targeted a non-current task");
    let config = task.thread_group.nt_sched_config();
    let level = config.base_priority;
    let mut state = NtSchedSnapshot::new(level, config.quantum(level) as u32);
    state.boost_disabled = config.boost_disabled;
    crate::live::runqueue::mutate_nt(&current,
        |task| task.sched.store_nt_unlocked(state));
}

#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub(crate) fn tick_unlocked(task: &Task) -> NtTickOutcome {
    let (state, outcome) = tick(task.sched.nt_snapshot());
    task.sched.store_nt_unlocked(state);
    outcome
}
