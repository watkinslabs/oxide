//! One task-owned scheduler state tree and coherent priority snapshots (`13a§5`).

use core::sync::atomic::{fence, AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use super::{LoadWeight, SchedClass, SchedEntity, SchedEntityState, SchedPolicy,
    SchedPriority, SchedRtEntity, SchedRtEntityState};
use super::sched_entity::{MIN_NICE, SCHED_FIXEDPOINT_SHIFT, SCHED_PRIO_TO_WEIGHT};
mod dl_pi;
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedClassId { Deadline, PosixRt, NtFixed, Fair, Idle }
impl SchedClassId {
    /// Decode task-owned atomic class storage. # C: O(1)
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw { 0 => Some(Self::Deadline), 1 => Some(Self::PosixRt),
            2 => Some(Self::NtFixed), 3 => Some(Self::Fair), 4 => Some(Self::Idle), _ => None }
    }
}
/// Exact Linux task policy values; distinct from runqueue class membership.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskPolicy { Normal = 0, Fifo = 1, Rr = 2, Batch = 3, Idle = 5, Deadline = 6, NtFixed = 7 }
impl TaskPolicy {
    /// Validate a Linux scheduler policy wire value. # C: O(1)
    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            0 => Some(Self::Normal), 1 => Some(Self::Fifo), 2 => Some(Self::Rr),
            3 => Some(Self::Batch), 5 => Some(Self::Idle), 6 => Some(Self::Deadline),
            7 => Some(Self::NtFixed), _ => None,
        }
    }
    /// Linux scheduler policy wire value. # C: O(1)
    pub const fn code(self) -> u32 { self as u32 }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrioritySnapshot {
    pub prio: SchedPriority,
    pub static_prio: SchedPriority,
    pub normal_prio: SchedPriority,
    pub rt_priority: u8,
    pub policy: TaskPolicy,
    pub reset_on_fork: bool,
    pub has_donor: bool,
    pub sched_class: SchedClassId,
    pub load: LoadWeight,
}

/// Validated Linux utilization-clamp request owned by one task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchedUclamp {
    min: u32,
    max: u32,
    user_defined: u8,
}

impl SchedUclamp {
    /// Construct a canonical clamp pair. Bits 0/1 identify user-defined
    /// MIN/MAX respectively; no other bits are meaningful. # C: O(1)
    pub fn new(min: u32, max: u32, user_defined: u8) -> Option<Self> {
        // Linux validates each requested slot against capacity, but stores MIN
        // and MAX independently. An automatic RT MIN may therefore exceed a
        // retained user MAX; effective-clamp aggregation resolves that later.
        if min > crate::sched_enc::UCLAMP_CAPACITY_SCALE
            || max > crate::sched_enc::UCLAMP_CAPACITY_SCALE || user_defined & !3 != 0 {
            return None;
        }
        Some(Self { min, max, user_defined })
    }

    pub const fn min(self) -> u32 { self.min }
    pub const fn max(self) -> u32 { self.max }
    pub const fn user_defined(self) -> u8 { self.user_defined }
}

pub(crate) struct TaskSched {
    publish_sequence: AtomicU32,
    prio: AtomicU8,
    static_prio: AtomicU8,
    normal_prio: AtomicU8,
    rt_priority: AtomicU8,
    policy: AtomicU8,
    reset_on_fork: AtomicBool,
    has_donor: AtomicBool,
    donor_prio: AtomicU8,
    donor_class: AtomicU8,
    dl_pi: dl_pi::DlPiState,
    class: AtomicU8,
    pub(crate) se: SchedEntityState,
    pub(crate) rt: SchedRtEntityState,
    pub(crate) dl: crate::deadline::DlEntity,
    uclamp_min: AtomicU32,
    uclamp_max: AtomicU32,
    uclamp_user_defined: AtomicU8,
    group_id: AtomicU64,
}

impl TaskSched {
    pub(crate) fn policy_generation(&self) -> (u32, u32) {
        loop {
            let before = self.publish_sequence.load(Ordering::Acquire);
            if before & 1 != 0 { core::hint::spin_loop(); continue; }
            let policy = self.policy.load(Ordering::Relaxed) as u32;
            fence(Ordering::Acquire);
            if self.publish_sequence.load(Ordering::Relaxed) == before {
                return (policy, before);
            }
        }
    }

    /// Build a complete task scheduler state from the legacy construction descriptor. # C: O(NICE_WIDTH)
    pub(crate) fn new(class: SchedClass, rr_ticks: u32, uclamp_max: u32) -> Self {
        let (static_prio, normal_prio, class_id, policy, rt_priority, load) = match class {
            SchedClass::Deadline => (SchedPriority::Deadline, SchedClassId::Deadline,
                TaskPolicy::Deadline, 0,
                LoadWeight::for_nice(0).unwrap()).with_static_nice(0),
            SchedClass::Rt { prio, policy } => (SchedPriority::posix_rt(prio)
                    .expect("RT task construction requires priority 1 through 99"),
                SchedClassId::PosixRt, rt_task_policy(policy), prio,
                LoadWeight::for_nice(0).unwrap()).with_static_nice(0),
            SchedClass::NtFixed { level, .. } => (SchedPriority::nt_fixed(level)
                .expect("NT task construction requires priority 1 through 31"),
                SchedClassId::NtFixed, TaskPolicy::NtFixed, 0,
                LoadWeight::for_nice(0).unwrap()).with_static_nice(0),
            SchedClass::Normal { weight } => {
                let (nice, policy, load) = if weight == super::sched_entity::WEIGHT_IDLEPRIO {
                    (0, TaskPolicy::Idle, LoadWeight::idle())
                } else {
                    let nice = nice_for_weight(weight)
                        .expect("fair task construction requires a Linux nice-table weight");
                    (nice, TaskPolicy::Normal, LoadWeight::for_nice(nice).unwrap())
                };
                let fair = SchedPriority::fair(nice as i32).unwrap();
                (fair, fair, SchedClassId::Fair, policy, 0, load)
            }
            SchedClass::Idle => (SchedPriority::fair(0).unwrap(), SchedPriority::Idle,
                SchedClassId::Idle, TaskPolicy::Normal, 0, LoadWeight::idle()),
        };
        Self {
            publish_sequence: AtomicU32::new(0),
            prio: AtomicU8::new(normal_prio.raw()), static_prio: AtomicU8::new(static_prio.raw()),
            normal_prio: AtomicU8::new(normal_prio.raw()), rt_priority: AtomicU8::new(rt_priority),
            policy: AtomicU8::new(policy as u8), reset_on_fork: AtomicBool::new(false),
            has_donor: AtomicBool::new(false), donor_prio: AtomicU8::new(SchedPriority::Idle.raw()),
            donor_class: AtomicU8::new(SchedClassId::Idle as u8),
            dl_pi: dl_pi::DlPiState::new(),
            class: AtomicU8::new(class_id as u8),
            se: SchedEntityState::new(SchedEntity::new(load)),
            rt: SchedRtEntityState::new(SchedRtEntity::new(rr_ticks)),
            dl: crate::deadline::DlEntity::new(), uclamp_min: AtomicU32::new(0),
            uclamp_max: AtomicU32::new(uclamp_max), uclamp_user_defined: AtomicU8::new(0),
            group_id: AtomicU64::new(0),
        }
    }

    /// Snapshot one complete published priority/configuration generation. # C: O(1) expected
    pub fn priority_snapshot(&self) -> PrioritySnapshot {
        loop {
            let before = self.publish_sequence.load(Ordering::Acquire);
            if before & 1 != 0 { core::hint::spin_loop(); continue; }
            let state = PrioritySnapshot {
                prio: load_priority(&self.prio), static_prio: load_priority(&self.static_prio),
                normal_prio: load_priority(&self.normal_prio),
                rt_priority: self.rt_priority.load(Ordering::Relaxed),
                policy: TaskPolicy::from_code(self.policy.load(Ordering::Relaxed) as u32)
                    .expect("published scheduler policy must be valid"),
                reset_on_fork: self.reset_on_fork.load(Ordering::Relaxed),
                has_donor: self.has_donor.load(Ordering::Relaxed),
                sched_class: SchedClassId::from_raw(self.class.load(Ordering::Relaxed))
                    .expect("published scheduler class must be valid"),
                load: self.se.load.snapshot(),
            };
            fence(Ordering::Acquire);
            if self.publish_sequence.load(Ordering::Relaxed) == before { return state; }
        }
    }

    /// Effective class descriptor consumed by current class runqueues. # C: O(1)
    pub fn effective_class(&self) -> SchedClass {
        let state = self.priority_snapshot();
        match state.sched_class {
            SchedClassId::Deadline => SchedClass::Deadline,
            SchedClassId::PosixRt => {
                let p = state.prio.rt_priority().unwrap();
                let policy = if state.policy == TaskPolicy::Rr { SchedPolicy::Rr }
                    else { SchedPolicy::Fifo };
                SchedClass::Rt { prio: p, policy }
            }
            SchedClassId::NtFixed => SchedClass::NtFixed {
                level: state.prio.nt_level().expect("NT class requires NT priority"),
                quantum: self.rt.time_slice.load(Ordering::Acquire),
            },
            SchedClassId::Fair => SchedClass::Normal {
                weight: (state.load.weight >> SCHED_FIXEDPOINT_SHIFT) as u32 },
            SchedClassId::Idle => SchedClass::Idle,
        }
    }

    /// Normal class descriptor with PI donation removed. # C: O(1)
    pub fn normal_class(&self) -> SchedClass {
        let state = self.priority_snapshot();
        match state.normal_prio {
            SchedPriority::Deadline => SchedClass::Deadline,
            SchedPriority::PosixRt(p) => SchedClass::Rt { prio: p.rt_priority(),
                policy: if state.policy == TaskPolicy::Rr { SchedPolicy::Rr }
                else { SchedPolicy::Fifo } },
            SchedPriority::NtFixed(p) => SchedClass::NtFixed {
                level: p.level(), quantum: self.rt.time_slice.load(Ordering::Acquire),
            },
            SchedPriority::Fair(_) => SchedClass::Normal {
                weight: (state.load.weight >> SCHED_FIXEDPOINT_SHIFT) as u32 },
            SchedPriority::Idle => SchedClass::Idle,
        }
    }
    /// Publish effective class/priority without changing configured state. # C: O(NICE_WIDTH)
    #[cfg(not(target_os = "oxide-kernel"))]
    pub(crate) fn store_effective_class(&self, class: SchedClass) {
        let normal_class = self.normal_class();
        let class = if matches!((normal_class, class), (SchedClass::Normal { .. },
            SchedClass::Normal { .. })) { normal_class } else { class };
        let is_normal = class == normal_class;
        if matches!(class, SchedClass::Deadline) {
            assert!(matches!(load_priority(&self.normal_prio), SchedPriority::Deadline));
        }
        let (derived_prio, id) = priority_for_class(class);
        let prio = if is_normal { load_priority(&self.normal_prio) } else { derived_prio };
        self.begin_publish();
        self.prio.store(prio.raw(), Ordering::Relaxed);
        self.class.store(id as u8, Ordering::Relaxed);
        let donated = !is_normal;
        self.has_donor.store(donated, Ordering::Relaxed);
        self.donor_prio.store(if donated { prio.raw() } else { SchedPriority::Idle.raw() }, Ordering::Relaxed);
        self.donor_class.store(if donated { id as u8 } else { SchedClassId::Idle as u8 }, Ordering::Relaxed);
        self.end_publish();
    }
    /// Whether a donor relation remains attached. # C: O(1)
    pub fn is_boosted(&self) -> bool {
        self.has_donor.load(Ordering::Acquire)
    }

    pub(crate) fn uclamp_snapshot(&self) -> SchedUclamp {
        loop {
            let before = self.publish_sequence.load(Ordering::Acquire);
            if before & 1 != 0 { core::hint::spin_loop(); continue; }
            let value = SchedUclamp {
                min: self.uclamp_min.load(Ordering::Relaxed),
                max: self.uclamp_max.load(Ordering::Relaxed),
                user_defined: self.uclamp_user_defined.load(Ordering::Relaxed),
            };
            fence(Ordering::Acquire);
            if self.publish_sequence.load(Ordering::Relaxed) == before { return value; }
        }
    }

    pub(crate) fn store_uclamp(&self, req: SchedUclamp) {
        self.begin_publish();
        self.uclamp_min.store(req.min, Ordering::Relaxed);
        self.uclamp_max.store(req.max, Ordering::Relaxed);
        self.uclamp_user_defined.store(req.user_defined, Ordering::Relaxed);
        self.end_publish();
    }

    /// Linux nice derived from canonical static priority. # C: O(1)
    pub fn nice(&self) -> i8 {
        self.priority_snapshot().static_prio.nice().unwrap_or(0) as i8
    }

    pub(crate) fn store_group_id(&self, id: u64) {
        self.group_id.store(id, Ordering::Release);
    }

    pub(crate) fn group_id(&self) -> u64 {
        self.group_id.load(Ordering::Acquire)
    }

    /// Change latent static priority and fair entity load. # C: O(1)
    pub(crate) fn store_nice(&self, nice: i8) {
        let fair = SchedPriority::fair(nice as i32).expect("nice must be in Linux range");
        self.begin_publish();
        self.static_prio.store(fair.raw(), Ordering::Relaxed);
        if matches!(load_priority(&self.normal_prio), SchedPriority::Fair(_)) {
            let load = if self.policy.load(Ordering::Relaxed) == TaskPolicy::Idle as u8 {
                LoadWeight::idle()
            } else { LoadWeight::for_nice(nice).unwrap() };
            self.se.load.store(load);
            self.normal_prio.store(fair.raw(), Ordering::Relaxed);
            self.store_effective_from_normal(fair, SchedClassId::Fair);
        }
        self.end_publish();
    }

    /// Replace configured normal class while retaining a stronger PI donation. # C: O(NICE_WIDTH)
    pub(crate) fn store_normal_class(&self, class: SchedClass, policy: u32) {
        let policy = TaskPolicy::from_code(policy).expect("scheduler policy code must be valid");
        match class {
            SchedClass::Deadline => assert!(policy == TaskPolicy::Deadline),
            SchedClass::Rt { prio, policy: class_policy } => {
                assert!(SchedPriority::posix_rt(prio).is_some());
                assert!(policy == rt_task_policy(class_policy));
            }
            SchedClass::NtFixed { level, .. } => {
                assert!(super::NtFixedPriority::new(level).is_some());
                assert!(policy == TaskPolicy::NtFixed);
            }
            SchedClass::Normal { weight } => {
                assert!(matches!(policy, TaskPolicy::Normal | TaskPolicy::Batch | TaskPolicy::Idle));
                assert!(policy == TaskPolicy::Idle || nice_for_weight(weight).is_some());
            }
            SchedClass::Idle => assert!(policy == TaskPolicy::Normal),
        }
        self.begin_publish();
        let (normal, normal_id, rt_priority, policy) = match class {
            SchedClass::Deadline => {
                assert!(policy == TaskPolicy::Deadline);
                (SchedPriority::Deadline, SchedClassId::Deadline, 0, policy)
            }
            SchedClass::Rt { prio, policy: class_policy } => {
                let class_policy = rt_task_policy(class_policy);
                assert!(policy == class_policy);
                (SchedPriority::posix_rt(prio).expect("RT priority must be 1 through 99"),
                    SchedClassId::PosixRt, prio, policy)
            }
            SchedClass::NtFixed { level, .. } => {
                (SchedPriority::nt_fixed(level).expect("NT priority must be 1 through 31"),
                    SchedClassId::NtFixed, 0, policy)
            }
            SchedClass::Normal { weight } => {
                assert!(matches!(policy, TaskPolicy::Normal | TaskPolicy::Batch | TaskPolicy::Idle));
                let nice = if policy == TaskPolicy::Idle {
                    self.se.load.store(LoadWeight::idle());
                    load_priority(&self.static_prio).nice().unwrap_or(0) as i8
                } else {
                    let nice = nice_for_weight(weight)
                        .expect("normal policy requires a Linux nice-table weight");
                    self.se.load.store(LoadWeight::for_nice(nice).unwrap());
                    self.static_prio.store(SchedPriority::fair(nice as i32).unwrap().raw(), Ordering::Relaxed);
                    nice
                };
                (SchedPriority::fair(nice as i32).unwrap(), SchedClassId::Fair, 0, policy)
            }
            SchedClass::Idle => {
                assert!(policy == TaskPolicy::Normal);
                (SchedPriority::Idle, SchedClassId::Idle, 0, policy)
            }
        };
        self.rt_priority.store(rt_priority, Ordering::Relaxed);
        self.policy.store(policy as u8, Ordering::Relaxed);
        self.normal_prio.store(normal.raw(), Ordering::Relaxed);
        self.store_effective_from_normal(normal, normal_id);
        self.end_publish();
    }
    fn store_effective_from_normal(&self, normal: SchedPriority, normal_id: SchedClassId) {
        let inheritable = matches!(SchedClassId::from_raw(self.donor_class.load(Ordering::Relaxed)),
            Some(SchedClassId::Deadline | SchedClassId::PosixRt | SchedClassId::NtFixed));
        let idle_policy_donor = self.policy.load(Ordering::Relaxed) == TaskPolicy::Idle as u8;
        let donor = load_priority(&self.donor_prio);
        let donor_wins = self.has_donor.load(Ordering::Relaxed) && inheritable
            && (idle_policy_donor || donor > normal
                || (donor == SchedPriority::Deadline && normal == SchedPriority::Deadline
                    && (self.dl_pi.snapshot().2.is_special() || crate::deadline::dl_time_before(
                        self.dl_pi.snapshot().1, self.dl.abs_deadline()))));
        if donor_wins {
            self.prio.store(self.donor_prio.load(Ordering::Relaxed), Ordering::Relaxed);
            self.class.store(self.donor_class.load(Ordering::Relaxed), Ordering::Relaxed);
            self.dl_pi.set_used(donor == SchedPriority::Deadline);
        } else {
            self.prio.store(normal.raw(), Ordering::Relaxed);
            self.class.store(normal_id as u8, Ordering::Relaxed);
            self.dl_pi.set_used(false);
        }
    }
    /// Clear donor state after the configured class already became effective. # C: O(1)
    #[cfg(not(target_os = "oxide-kernel"))]
    pub(crate) fn restore_normal(&self) {
        self.begin_publish();
        let normal = load_priority(&self.normal_prio);
        self.has_donor.store(false, Ordering::Relaxed);
        self.donor_prio.store(SchedPriority::Idle.raw(), Ordering::Relaxed);
        self.donor_class.store(SchedClassId::Idle as u8, Ordering::Relaxed);
        self.dl_pi.clear();
        self.store_effective_from_normal(normal, class_id(normal));
        self.end_publish();
    }

    /// Store the one-shot fork reset bit in the published configuration. # C: O(1)
    pub(crate) fn store_reset_on_fork(&self, reset: bool) {
        self.begin_publish();
        self.reset_on_fork.store(reset, Ordering::Relaxed);
        self.end_publish();
    }

    fn begin_publish(&self) { self.publish_sequence.fetch_add(1, Ordering::AcqRel); }
    fn end_publish(&self) { self.publish_sequence.fetch_add(1, Ordering::Release); }
}
trait WithStaticNice {
    fn with_static_nice(self, nice: i8) ->
        (SchedPriority, SchedPriority, SchedClassId, TaskPolicy, u8, LoadWeight);
}
impl WithStaticNice for (SchedPriority, SchedClassId, TaskPolicy, u8, LoadWeight) {
    fn with_static_nice(self, nice: i8) ->
        (SchedPriority, SchedPriority, SchedClassId, TaskPolicy, u8, LoadWeight) {
        (SchedPriority::fair(nice as i32).unwrap(), self.0, self.1, self.2, self.3, self.4)
    }
}
fn load_priority(value: &AtomicU8) -> SchedPriority {
    SchedPriority::from_raw(value.load(Ordering::Acquire)).unwrap()
}
fn nice_for_weight(weight: u32) -> Option<i8> {
    SCHED_PRIO_TO_WEIGHT.iter().position(|&candidate| candidate == weight)
        .map(|index| MIN_NICE + index as i8)
}
fn rt_task_policy(policy: SchedPolicy) -> TaskPolicy {
    match policy {
        SchedPolicy::Fifo => TaskPolicy::Fifo,
        SchedPolicy::Rr => TaskPolicy::Rr,
        _ => panic!("RT class requires FIFO or RR policy"),
    }
}
fn class_id(priority: SchedPriority) -> SchedClassId {
    match priority { SchedPriority::Deadline => SchedClassId::Deadline,
        SchedPriority::PosixRt(_) => SchedClassId::PosixRt,
        SchedPriority::NtFixed(_) => SchedClassId::NtFixed,
        SchedPriority::Fair(_) => SchedClassId::Fair, SchedPriority::Idle => SchedClassId::Idle }
}
fn priority_for_class(class: SchedClass) -> (SchedPriority, SchedClassId) {
    match class {
        SchedClass::Deadline => (SchedPriority::Deadline, SchedClassId::Deadline),
        SchedClass::Rt { prio, .. } => (SchedPriority::posix_rt(prio)
            .expect("effective RT priority must be 1 through 99"), SchedClassId::PosixRt),
        SchedClass::NtFixed { level, .. } => (SchedPriority::nt_fixed(level)
            .expect("effective NT priority must be 1 through 31"), SchedClassId::NtFixed),
        SchedClass::Normal { weight } => {
            let nice = if weight == super::sched_entity::WEIGHT_IDLEPRIO { 0 } else {
                nice_for_weight(weight).expect("effective fair class requires a Linux nice-table weight") };
            (SchedPriority::fair(nice as i32).unwrap(), SchedClassId::Fair)
        }
        SchedClass::Idle => (SchedPriority::Idle, SchedClassId::Idle),
    }
}
#[cfg(test)]
#[path = "sched_state/tests.rs"]
mod tests;
