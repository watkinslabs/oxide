//! Canonical configured, normal, and effective priority values (`13a§5`).

use core::cmp::Ordering;

pub const MIN_NICE: i32 = -20;
pub const MAX_NICE: i32 = 19;
pub const NICE_WIDTH: i32 = MAX_NICE - MIN_NICE + 1;
pub const MAX_DL_PRIO: i32 = 0;
pub const MAX_RT_PRIO: i32 = 100;
pub const MAX_PRIO: i32 = MAX_RT_PRIO + NICE_WIDTH;
pub const DEFAULT_PRIO: i32 = MAX_RT_PRIO + NICE_WIDTH / 2;

pub const MIN_RT_PRIORITY: u8 = 1;
pub const MAX_RT_PRIORITY: u8 = (MAX_RT_PRIO - 1) as u8;
pub const MIN_NT_PRIORITY: u8 = 1;
pub const MAX_NT_PRIORITY: u8 = 31;
pub const DEADLINE_NORMAL_PRIO: i32 = MAX_DL_PRIO - 1;

/// Convert a nice value to its fair-class static priority. # C: O(1)
pub const fn nice_to_prio(nice: i32) -> i32 { nice + DEFAULT_PRIO }

/// Convert a fair-class static priority to its nice value. # C: O(1)
pub const fn prio_to_nice(prio: i32) -> i32 { prio - DEFAULT_PRIO }

/// Convert requested POSIX RT priority to normal scheduler priority. # C: O(1)
pub const fn rt_priority_to_normal_prio(rt_priority: u8) -> Option<i32> {
    if rt_priority < MIN_RT_PRIORITY || rt_priority > MAX_RT_PRIORITY { None }
    else { Some(MAX_RT_PRIO - 1 - rt_priority as i32) }
}

/// Convert normal scheduler priority to requested POSIX RT priority. # C: O(1)
pub const fn normal_prio_to_rt_priority(prio: i32) -> Option<u8> {
    if prio < MAX_DL_PRIO || prio >= MAX_RT_PRIO - 1 { None }
    else { Some((MAX_RT_PRIO - 1 - prio) as u8) }
}

/// Valid POSIX RT normal priority in the internal `0..=98` range.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct PosixRtPriority(u8);

impl PosixRtPriority {
    /// Construct from requested POSIX RT priority `1..=99`. # C: O(1)
    pub const fn from_rt_priority(rt_priority: u8) -> Option<Self> {
        match rt_priority_to_normal_prio(rt_priority) {
            Some(prio) => Some(Self(prio as u8)),
            None => None,
        }
    }

    /// Construct from internal POSIX RT normal priority `0..=98`. # C: O(1)
    pub const fn from_normal_prio(prio: i32) -> Option<Self> {
        if prio < MAX_DL_PRIO || prio >= MAX_RT_PRIO - 1 { None }
        else { Some(Self(prio as u8)) }
    }

    /// Internal normal/effective priority. # C: O(1)
    pub const fn normal_prio(self) -> i32 { self.0 as i32 }

    /// Requested POSIX RT priority `1..=99`. # C: O(1)
    pub const fn rt_priority(self) -> u8 { MAX_RT_PRIORITY - self.0 }
}

/// Valid fair normal/static priority in the internal `100..=139` range.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct FairPriority(u8);

impl FairPriority {
    /// Construct from nice `-20..=19`. # C: O(1)
    pub const fn from_nice(nice: i32) -> Option<Self> {
        if nice < MIN_NICE || nice > MAX_NICE { None }
        else { Some(Self(nice_to_prio(nice) as u8)) }
    }

    /// Construct from internal fair normal/static priority `100..=139`. # C: O(1)
    pub const fn from_normal_prio(prio: i32) -> Option<Self> {
        if prio < MAX_RT_PRIO || prio >= MAX_PRIO { None }
        else { Some(Self(prio as u8)) }
    }

    /// Internal normal/static priority. # C: O(1)
    pub const fn normal_prio(self) -> i32 { self.0 as i32 }

    /// Nice value `-20..=19`. # C: O(1)
    pub const fn nice(self) -> i32 { prio_to_nice(self.0 as i32) }
}

/// Valid native fixed dispatcher priority `1..=31`.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct NtFixedPriority(u8);

impl NtFixedPriority {
    /// Construct from native dispatcher level `1..=31`. # C: O(1)
    pub const fn new(level: u8) -> Option<Self> {
        if level < MIN_NT_PRIORITY || level > MAX_NT_PRIORITY { None }
        else { Some(Self(level)) }
    }

    /// Native dispatcher level `1..=31`. # C: O(1)
    pub const fn level(self) -> u8 { self.0 }
}

/// Total scheduler priority; greater values under [`Ord`] outrank lesser ones.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum SchedPriority {
    Deadline,
    PosixRt(PosixRtPriority),
    NtFixed(NtFixedPriority),
    Fair(FairPriority),
    Idle,
}

impl SchedPriority {
    const RAW_FAIR_BASE: u8 = 1;
    const RAW_NT_BASE: u8 = 64;
    const RAW_RT_BASE: u8 = 128;
    const RAW_DEADLINE: u8 = u8::MAX;

    /// Construct a POSIX RT priority from requested `sched_priority`. # C: O(1)
    pub const fn posix_rt(rt_priority: u8) -> Option<Self> {
        match PosixRtPriority::from_rt_priority(rt_priority) {
            Some(prio) => Some(Self::PosixRt(prio)),
            None => None,
        }
    }

    /// Construct a fair configured/normal priority from nice. # C: O(1)
    pub const fn fair(nice: i32) -> Option<Self> {
        match FairPriority::from_nice(nice) {
            Some(prio) => Some(Self::Fair(prio)),
            None => None,
        }
    }

    /// Construct a native fixed priority from dispatcher level. # C: O(1)
    pub const fn nt_fixed(level: u8) -> Option<Self> {
        match NtFixedPriority::new(level) {
            Some(prio) => Some(Self::NtFixed(prio)),
            None => None,
        }
    }

    /// Decode a Linux normal/effective priority, excluding native and idle. # C: O(1)
    pub const fn from_linux_prio(prio: i32) -> Option<Self> {
        if prio == DEADLINE_NORMAL_PRIO { return Some(Self::Deadline); }
        match PosixRtPriority::from_normal_prio(prio) {
            Some(rt) => return Some(Self::PosixRt(rt)),
            None => {}
        }
        match FairPriority::from_normal_prio(prio) {
            Some(fair) => Some(Self::Fair(fair)),
            None => None,
        }
    }

    /// Project deadline, POSIX RT, or fair state to Linux priority units. # C: O(1)
    pub const fn linux_prio(self) -> Option<i32> {
        match self {
            Self::Deadline => Some(DEADLINE_NORMAL_PRIO),
            Self::PosixRt(prio) => Some(prio.normal_prio()),
            Self::Fair(prio) => Some(prio.normal_prio()),
            Self::NtFixed(_) | Self::Idle => None,
        }
    }

    /// Requested POSIX RT priority when this is a POSIX RT value. # C: O(1)
    pub const fn rt_priority(self) -> Option<u8> {
        match self { Self::PosixRt(prio) => Some(prio.rt_priority()), _ => None }
    }

    /// Nice value when this is a fair configured/normal value. # C: O(1)
    pub const fn nice(self) -> Option<i32> {
        match self { Self::Fair(prio) => Some(prio.nice()), _ => None }
    }

    /// Native dispatcher level when this is a native fixed value. # C: O(1)
    pub const fn nt_level(self) -> Option<u8> {
        match self { Self::NtFixed(prio) => Some(prio.level()), _ => None }
    }

    /// Encode for task-owned atomic storage; larger values always outrank. # C: O(1)
    pub const fn raw(self) -> u8 {
        match self {
            Self::Idle => 0,
            Self::Fair(prio) => Self::RAW_FAIR_BASE + (MAX_NICE - prio.nice()) as u8,
            Self::NtFixed(prio) => Self::RAW_NT_BASE + prio.level(),
            Self::PosixRt(prio) => Self::RAW_RT_BASE + prio.rt_priority(),
            Self::Deadline => Self::RAW_DEADLINE,
        }
    }

    /// Decode task-owned atomic storage, rejecting unused tag ranges. # C: O(1)
    pub const fn from_raw(raw: u8) -> Option<Self> {
        if raw == 0 { return Some(Self::Idle); }
        if raw >= Self::RAW_FAIR_BASE && raw < Self::RAW_FAIR_BASE + NICE_WIDTH as u8 {
            return Self::fair(MAX_NICE - (raw - Self::RAW_FAIR_BASE) as i32);
        }
        if raw > Self::RAW_NT_BASE && raw <= Self::RAW_NT_BASE + MAX_NT_PRIORITY {
            return Self::nt_fixed(raw - Self::RAW_NT_BASE);
        }
        if raw > Self::RAW_RT_BASE && raw <= Self::RAW_RT_BASE + MAX_RT_PRIORITY {
            return Self::posix_rt(raw - Self::RAW_RT_BASE);
        }
        if raw == Self::RAW_DEADLINE { return Some(Self::Deadline); }
        None
    }

    const fn class_rank(self) -> u8 {
        match self {
            Self::Deadline => 4,
            Self::PosixRt(_) => 3,
            Self::NtFixed(_) => 2,
            Self::Fair(_) => 1,
            Self::Idle => 0,
        }
    }
}

impl Ord for SchedPriority {
    fn cmp(&self, other: &Self) -> Ordering {
        let class = self.class_rank().cmp(&other.class_rank());
        if class != Ordering::Equal { return class; }
        match (*self, *other) {
            (Self::PosixRt(a), Self::PosixRt(b)) => b.0.cmp(&a.0),
            (Self::NtFixed(a), Self::NtFixed(b)) => a.0.cmp(&b.0),
            (Self::Fair(a), Self::Fair(b)) => b.0.cmp(&a.0),
            _ => Ordering::Equal,
        }
    }
}

impl PartialOrd for SchedPriority {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_are_exact() {
        assert_eq!((MIN_NICE, MAX_NICE, NICE_WIDTH), (-20, 19, 40));
        assert_eq!((MAX_DL_PRIO, MAX_RT_PRIO, DEFAULT_PRIO, MAX_PRIO), (0, 100, 120, 140));
        assert_eq!(DEADLINE_NORMAL_PRIO, -1);
    }

    #[test]
    fn nice_conversion_is_exhaustive_and_roundtrips() {
        for nice in MIN_NICE..=MAX_NICE {
            let prio = nice_to_prio(nice);
            assert_eq!(prio, nice + DEFAULT_PRIO);
            assert_eq!(prio_to_nice(prio), nice);
            let value = SchedPriority::fair(nice).unwrap();
            assert_eq!(value.linux_prio(), Some(prio));
            assert_eq!(value.nice(), Some(nice));
            assert_eq!(SchedPriority::from_linux_prio(prio), Some(value));
        }
        assert_eq!(nice_to_prio(MIN_NICE), MAX_RT_PRIO);
        assert_eq!(nice_to_prio(MAX_NICE), MAX_PRIO - 1);
        assert_eq!(SchedPriority::fair(MIN_NICE - 1), None);
        assert_eq!(SchedPriority::fair(MAX_NICE + 1), None);
    }

    #[test]
    fn rt_conversion_is_exhaustive_and_roundtrips() {
        for rt_priority in MIN_RT_PRIORITY..=MAX_RT_PRIORITY {
            let prio = rt_priority_to_normal_prio(rt_priority).unwrap();
            assert_eq!(normal_prio_to_rt_priority(prio), Some(rt_priority));
            let value = SchedPriority::posix_rt(rt_priority).unwrap();
            assert_eq!(value.linux_prio(), Some(prio));
            assert_eq!(value.rt_priority(), Some(rt_priority));
            assert_eq!(SchedPriority::from_linux_prio(prio), Some(value));
        }
        assert_eq!(rt_priority_to_normal_prio(MIN_RT_PRIORITY), Some(98));
        assert_eq!(rt_priority_to_normal_prio(MAX_RT_PRIORITY), Some(0));
        assert_eq!(SchedPriority::posix_rt(0), None);
        assert_eq!(SchedPriority::posix_rt(MAX_RT_PRIORITY + 1), None);
        assert_eq!(normal_prio_to_rt_priority(-1), None);
        assert_eq!(normal_prio_to_rt_priority(99), None);
    }

    #[test]
    fn linux_projection_accepts_only_defined_ranges() {
        assert_eq!(SchedPriority::from_linux_prio(-1), Some(SchedPriority::Deadline));
        for prio in 0..=98 { assert!(matches!(SchedPriority::from_linux_prio(prio), Some(SchedPriority::PosixRt(_)))); }
        assert_eq!(SchedPriority::from_linux_prio(99), None);
        for prio in 100..=139 { assert!(matches!(SchedPriority::from_linux_prio(prio), Some(SchedPriority::Fair(_)))); }
        for prio in [-2, 140, i32::MIN, i32::MAX] { assert_eq!(SchedPriority::from_linux_prio(prio), None); }
        assert_eq!(SchedPriority::Deadline.linux_prio(), Some(-1));
        assert_eq!(SchedPriority::Idle.linux_prio(), None);
        assert_eq!(SchedPriority::nt_fixed(1).unwrap().linux_prio(), None);
    }

    #[test]
    fn nt_fixed_range_is_exact_and_roundtrips() {
        for level in MIN_NT_PRIORITY..=MAX_NT_PRIORITY {
            let value = SchedPriority::nt_fixed(level).unwrap();
            assert_eq!(value.nt_level(), Some(level));
        }
        assert_eq!(SchedPriority::nt_fixed(0), None);
        assert_eq!(SchedPriority::nt_fixed(MAX_NT_PRIORITY + 1), None);
    }

    #[test]
    fn class_order_has_positive_controls() {
        let rt_low = SchedPriority::posix_rt(MIN_RT_PRIORITY).unwrap();
        let nt_high = SchedPriority::nt_fixed(MAX_NT_PRIORITY).unwrap();
        let fair_high = SchedPriority::fair(MIN_NICE).unwrap();
        assert!(SchedPriority::Deadline > SchedPriority::posix_rt(MAX_RT_PRIORITY).unwrap());
        assert!(rt_low > nt_high);
        assert!(nt_high > fair_high);
        assert!(fair_high > SchedPriority::Idle);
    }

    #[test]
    fn within_class_order_is_exhaustive() {
        for p in MIN_RT_PRIORITY..MAX_RT_PRIORITY {
            assert!(SchedPriority::posix_rt(p + 1).unwrap() > SchedPriority::posix_rt(p).unwrap());
        }
        for p in MIN_NT_PRIORITY..MAX_NT_PRIORITY {
            assert!(SchedPriority::nt_fixed(p + 1).unwrap() > SchedPriority::nt_fixed(p).unwrap());
        }
        for nice in MIN_NICE..MAX_NICE {
            assert!(SchedPriority::fair(nice).unwrap() > SchedPriority::fair(nice + 1).unwrap());
        }
    }

    #[test]
    fn order_is_total_and_antisymmetric() {
        let mut values = [SchedPriority::Idle; 172];
        let mut n = 0;
        values[n] = SchedPriority::Deadline; n += 1;
        for p in MIN_RT_PRIORITY..=MAX_RT_PRIORITY { values[n] = SchedPriority::posix_rt(p).unwrap(); n += 1; }
        for p in MIN_NT_PRIORITY..=MAX_NT_PRIORITY { values[n] = SchedPriority::nt_fixed(p).unwrap(); n += 1; }
        for nice in MIN_NICE..=MAX_NICE { values[n] = SchedPriority::fair(nice).unwrap(); n += 1; }
        values[n] = SchedPriority::Idle; n += 1;
        assert_eq!(n, values.len());
        for a in values {
            for b in values {
                assert_eq!(a.cmp(&b), b.cmp(&a).reverse());
                assert_eq!(a == b, a.cmp(&b) == Ordering::Equal);
            }
            assert_eq!(SchedPriority::from_raw(a.raw()), Some(a));
        }
        for pair in values.windows(2) {
            if pair[0] < pair[1] { assert!(pair[0].raw() < pair[1].raw()); }
            if pair[0] > pair[1] { assert!(pair[0].raw() > pair[1].raw()); }
        }
    }
}
