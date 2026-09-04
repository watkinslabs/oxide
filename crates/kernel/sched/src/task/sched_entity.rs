//! Canonical fair and real-time task entities per `13a§6`.

use core::cell::UnsafeCell;
use core::sync::atomic::{fence, AtomicBool, AtomicI64, AtomicU16, AtomicU32,
    AtomicU64, Ordering};

use super::{RtRunNode, TreeRunNode};

pub const MIN_NICE: i8 = -20;
pub const MAX_NICE: i8 = 19;
pub const NICE_WIDTH: usize = 40;
pub const SCHED_FIXEDPOINT_SHIFT: u32 = 10;
pub const WEIGHT_IDLEPRIO: u32 = 3;
pub const WMULT_IDLEPRIO: u32 = 1_431_655_765;

pub const SCHED_PRIO_TO_WEIGHT: [u32; NICE_WIDTH] = [
    88_761, 71_755, 56_483, 46_273, 36_291,
    29_154, 23_254, 18_705, 14_949, 11_916,
     9_548,  7_620,  6_100,  4_904,  3_906,
     3_121,  2_501,  1_991,  1_586,  1_277,
     1_024,    820,    655,    526,    423,
       335,    272,    215,    172,    137,
       110,     87,     70,     56,     45,
        36,     29,     23,     18,     15,
];

pub const SCHED_PRIO_TO_WMULT: [u32; NICE_WIDTH] = [
        48_388,     59_856,     76_040,     92_818,    118_348,
       147_320,    184_698,    229_616,    287_308,    360_437,
       449_829,    563_644,    704_093,    875_809,  1_099_582,
     1_376_151,  1_717_300,  2_157_191,  2_708_050,  3_363_326,
     4_194_304,  5_237_765,  6_557_202,  8_165_337, 10_153_587,
    12_820_798, 15_790_321, 19_976_592, 24_970_740, 31_350_126,
    39_045_157, 49_367_440, 61_356_676, 76_695_844, 95_443_717,
   119_304_647,148_102_320,186_737_708,238_609_294,286_331_153,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadWeight {
    pub weight: u64,
    pub inv_weight: u32,
}

impl LoadWeight {
    /// Build a 64-bit fair-task load from a validated nice value. # C: O(1)
    pub const fn for_nice(nice: i8) -> Option<Self> {
        match nice_index(nice) {
            Some(i) => Some(Self {
                weight: (SCHED_PRIO_TO_WEIGHT[i] as u64) << SCHED_FIXEDPOINT_SHIFT,
                inv_weight: SCHED_PRIO_TO_WMULT[i],
            }),
            None => None,
        }
    }

    /// Build the load reserved for the fair idle policy. # C: O(1)
    pub const fn idle() -> Self {
        Self {
            weight: (WEIGHT_IDLEPRIO as u64) << SCHED_FIXEDPOINT_SHIFT,
            inv_weight: WMULT_IDLEPRIO,
        }
    }
}

/// Convert a valid nice value to its fair weight-table slot. # C: O(1)
pub const fn nice_index(nice: i8) -> Option<usize> {
    if nice < MIN_NICE || nice > MAX_NICE { None }
    else { Some((nice - MIN_NICE) as usize) }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SchedAvg {
    pub last_update_time: u64,
    pub load_sum: u64,
    pub runnable_sum: u64,
    pub util_sum: u32,
    pub period_contrib: u32,
    pub load_avg: u64,
    pub runnable_avg: u64,
    pub util_avg: u64,
    pub util_est: u32,
}

impl SchedAvg {
    /// Build an unaccounted entity average. # C: O(1)
    pub const fn new() -> Self {
        Self {
            last_update_time: 0,
            load_sum: 0,
            runnable_sum: 0,
            util_sum: 0,
            period_contrib: 0,
            load_avg: 0,
            runnable_avg: 0,
            util_avg: 0,
            util_est: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchedEntity {
    pub load: LoadWeight,
    pub deadline: u64,
    pub min_vruntime: u64,
    pub min_slice: u64,
    pub max_slice: u64,
    pub on_rq: bool,
    pub sched_delayed: bool,
    pub relative_deadline: bool,
    pub custom_slice: bool,
    pub exec_start: u64,
    pub sum_exec_runtime: u64,
    pub prev_sum_exec_runtime: u64,
    pub vruntime: u64,
    pub vlag: i64,
    pub protected_deadline: u64,
    pub slice: u64,
    pub nr_migrations: u64,
    pub depth: u16,
    pub runnable_weight: u64,
    pub avg: SchedAvg,
}

impl SchedEntity {
    /// Build an unqueued fair entity with the supplied load. # C: O(1)
    pub const fn new(load: LoadWeight) -> Self {
        Self {
            load,
            deadline: 0,
            min_vruntime: 0,
            min_slice: 0,
            max_slice: 0,
            on_rq: false,
            sched_delayed: false,
            relative_deadline: false,
            custom_slice: false,
            exec_start: 0,
            sum_exec_runtime: 0,
            prev_sum_exec_runtime: 0,
            vruntime: 0,
            vlag: 0,
            protected_deadline: 0,
            slice: 0,
            nr_migrations: 0,
            depth: 0,
            runnable_weight: 0,
            avg: SchedAvg::new(),
        }
    }

    /// Build an unqueued fair entity from a validated nice value. # C: O(1)
    pub const fn for_nice(nice: i8) -> Option<Self> {
        match LoadWeight::for_nice(nice) {
            Some(load) => Some(Self::new(load)),
            None => None,
        }
    }

    /// Replace only the fair load derived from a validated nice value. # C: O(1)
    pub fn reweight_nice(&mut self, nice: i8) -> bool {
        match LoadWeight::for_nice(nice) {
            Some(load) => { self.load = load; true }
            None => false,
        }
    }

    /// Replace only the fair load with the idle-policy load. # C: O(1)
    pub fn reweight_idle(&mut self) { self.load = LoadWeight::idle(); }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchedRtEntity {
    pub timeout: u64,
    pub watchdog_stamp: u64,
    pub time_slice: u32,
    pub on_rq: bool,
    pub on_list: bool,
}

impl SchedRtEntity {
    /// Build an unqueued real-time entity with its initial quantum. # C: O(1)
    pub const fn new(time_slice: u32) -> Self {
        Self { timeout: 0, watchdog_stamp: 0, time_slice, on_rq: false, on_list: false }
    }
}

pub struct AtomicLoadWeight {
    sequence: AtomicU32,
    weight: AtomicU64,
    inv_weight: AtomicU32,
}

impl AtomicLoadWeight {
    pub(super) fn new(load: LoadWeight) -> Self {
        Self { sequence: AtomicU32::new(0), weight: AtomicU64::new(load.weight),
            inv_weight: AtomicU32::new(load.inv_weight) }
    }

    /// Read one version of the paired load values. # C: O(1) expected
    pub fn snapshot(&self) -> LoadWeight {
        loop {
            let before = self.sequence.load(Ordering::Acquire);
            if before & 1 != 0 { core::hint::spin_loop(); continue; }
            let load = LoadWeight { weight: self.weight.load(Ordering::Relaxed),
                inv_weight: self.inv_weight.load(Ordering::Relaxed) };
            fence(Ordering::Acquire);
            if self.sequence.load(Ordering::Relaxed) == before { return load; }
        }
    }

    pub(crate) fn store(&self, load: LoadWeight) {
        self.sequence.fetch_add(1, Ordering::AcqRel);
        self.inv_weight.store(load.inv_weight, Ordering::Relaxed);
        self.weight.store(load.weight, Ordering::Relaxed);
        self.sequence.fetch_add(1, Ordering::Release);
    }
}

pub struct SchedEntityState {
    /// Embedded allocation-free fair ready-tree node. `CfsRunqueue` claims a
    /// unique `class_rq_owner` before access and clears links before release.
    run_node: UnsafeCell<TreeRunNode>,
    pub load: AtomicLoadWeight,
    pub deadline: AtomicU64,
    pub min_vruntime: AtomicU64,
    pub min_slice: AtomicU64,
    pub max_slice: AtomicU64,
    pub on_rq: AtomicBool,
    pub sched_delayed: AtomicBool,
    pub relative_deadline: AtomicBool,
    pub custom_slice: AtomicBool,
    pub exec_start: AtomicU64,
    pub sum_exec_runtime: AtomicU64,
    pub prev_sum_exec_runtime: AtomicU64,
    pub vruntime: AtomicU64,
    pub vlag: AtomicI64,
    pub protected_deadline: AtomicU64,
    pub slice: AtomicU64,
    pub nr_migrations: AtomicU64,
    pub depth: AtomicU16,
    pub runnable_weight: AtomicU64,
    pub avg_last_update_time: AtomicU64,
    pub avg_load_sum: AtomicU64,
    pub avg_runnable_sum: AtomicU64,
    pub avg_util_sum: AtomicU32,
    pub avg_period_contrib: AtomicU32,
    pub avg_load: AtomicU64,
    pub avg_runnable: AtomicU64,
    pub avg_util: AtomicU64,
    pub avg_util_est: AtomicU32,
}

impl SchedEntityState {
    pub(super) fn new(se: SchedEntity) -> Self {
        Self {
            run_node: UnsafeCell::new(TreeRunNode::new()),
            load: AtomicLoadWeight::new(se.load), deadline: AtomicU64::new(se.deadline),
            min_vruntime: AtomicU64::new(se.min_vruntime), min_slice: AtomicU64::new(se.min_slice),
            max_slice: AtomicU64::new(se.max_slice), on_rq: AtomicBool::new(se.on_rq),
            sched_delayed: AtomicBool::new(se.sched_delayed),
            relative_deadline: AtomicBool::new(se.relative_deadline),
            custom_slice: AtomicBool::new(se.custom_slice), exec_start: AtomicU64::new(se.exec_start),
            sum_exec_runtime: AtomicU64::new(se.sum_exec_runtime),
            prev_sum_exec_runtime: AtomicU64::new(se.prev_sum_exec_runtime),
            vruntime: AtomicU64::new(se.vruntime), vlag: AtomicI64::new(se.vlag),
            protected_deadline: AtomicU64::new(se.protected_deadline), slice: AtomicU64::new(se.slice),
            nr_migrations: AtomicU64::new(se.nr_migrations), depth: AtomicU16::new(se.depth),
            runnable_weight: AtomicU64::new(se.runnable_weight),
            avg_last_update_time: AtomicU64::new(se.avg.last_update_time),
            avg_load_sum: AtomicU64::new(se.avg.load_sum),
            avg_runnable_sum: AtomicU64::new(se.avg.runnable_sum),
            avg_util_sum: AtomicU32::new(se.avg.util_sum),
            avg_period_contrib: AtomicU32::new(se.avg.period_contrib),
            avg_load: AtomicU64::new(se.avg.load_avg),
            avg_runnable: AtomicU64::new(se.avg.runnable_avg),
            avg_util: AtomicU64::new(se.avg.util_avg),
            avg_util_est: AtomicU32::new(se.avg.util_est),
        }
    }

    /// # SAFETY: caller owns the claiming `CfsRunqueue`; its identity excludes
    /// every other class queue until all embedded links have been cleared.
    pub(crate) unsafe fn run_node_mut(&self) -> &mut TreeRunNode {
        // SAFETY: upheld by the queue's atomic claim and exclusive `&mut self`.
        unsafe { &mut *self.run_node.get() }
    }

    /// # SAFETY: caller owns the claiming `CfsRunqueue` against tree mutation.
    pub(crate) unsafe fn run_node(&self) -> &TreeRunNode {
        unsafe { &*self.run_node.get() }
    }

    pub fn snapshot(&self) -> SchedEntity {
        let mut se = SchedEntity::new(self.load.snapshot());
        se.deadline = self.deadline.load(Ordering::Acquire);
        se.min_vruntime = self.min_vruntime.load(Ordering::Acquire);
        se.min_slice = self.min_slice.load(Ordering::Acquire);
        se.max_slice = self.max_slice.load(Ordering::Acquire);
        se.on_rq = self.on_rq.load(Ordering::Acquire);
        se.sched_delayed = self.sched_delayed.load(Ordering::Acquire);
        se.relative_deadline = self.relative_deadline.load(Ordering::Acquire);
        se.custom_slice = self.custom_slice.load(Ordering::Acquire);
        se.exec_start = self.exec_start.load(Ordering::Acquire);
        se.sum_exec_runtime = self.sum_exec_runtime.load(Ordering::Acquire);
        se.prev_sum_exec_runtime = self.prev_sum_exec_runtime.load(Ordering::Acquire);
        se.vruntime = self.vruntime.load(Ordering::Acquire);
        se.vlag = self.vlag.load(Ordering::Acquire);
        se.protected_deadline = self.protected_deadline.load(Ordering::Acquire);
        se.slice = self.slice.load(Ordering::Acquire);
        se.nr_migrations = self.nr_migrations.load(Ordering::Acquire);
        se.depth = self.depth.load(Ordering::Acquire);
        se.runnable_weight = self.runnable_weight.load(Ordering::Acquire);
        se.avg.last_update_time = self.avg_last_update_time.load(Ordering::Acquire);
        se.avg.load_sum = self.avg_load_sum.load(Ordering::Acquire);
        se.avg.runnable_sum = self.avg_runnable_sum.load(Ordering::Acquire);
        se.avg.util_sum = self.avg_util_sum.load(Ordering::Acquire);
        se.avg.period_contrib = self.avg_period_contrib.load(Ordering::Acquire);
        se.avg.load_avg = self.avg_load.load(Ordering::Acquire);
        se.avg.runnable_avg = self.avg_runnable.load(Ordering::Acquire);
        se.avg.util_avg = self.avg_util.load(Ordering::Acquire);
        se.avg.util_est = self.avg_util_est.load(Ordering::Acquire);
        se
    }
}

pub struct SchedRtEntityState {
    /// Embedded allocation-free RT FIFO link. `RtRunqueue` atomically claims
    /// class-queue membership before access and clears the link before release.
    run_node: UnsafeCell<RtRunNode>,
    pub timeout: AtomicU64,
    pub watchdog_stamp: AtomicU64,
    pub time_slice: AtomicU32,
    pub on_rq: AtomicBool,
    pub on_list: AtomicBool,
}

impl SchedRtEntityState {
    pub(super) fn new(rt: SchedRtEntity) -> Self {
        Self { run_node: UnsafeCell::new(RtRunNode::new()), timeout: AtomicU64::new(rt.timeout),
            watchdog_stamp: AtomicU64::new(rt.watchdog_stamp),
            time_slice: AtomicU32::new(rt.time_slice), on_rq: AtomicBool::new(rt.on_rq),
            on_list: AtomicBool::new(rt.on_list) }
    }

    /// # SAFETY: caller owns the claiming `RtRunqueue`; its identity excludes
    /// every other class queue until the embedded link has been cleared.
    pub(crate) unsafe fn run_node_mut(&self) -> &mut RtRunNode {
        // SAFETY: upheld by the queue's atomic claim and exclusive `&mut self`.
        unsafe { &mut *self.run_node.get() }
    }

    /// # SAFETY: caller owns the claiming `RtRunqueue` against list mutation.
    pub(crate) unsafe fn run_node(&self) -> &RtRunNode {
        unsafe { &*self.run_node.get() }
    }

    pub fn snapshot(&self) -> SchedRtEntity {
        SchedRtEntity { timeout: self.timeout.load(Ordering::Acquire),
            watchdog_stamp: self.watchdog_stamp.load(Ordering::Acquire),
            time_slice: self.time_slice.load(Ordering::Acquire),
            on_rq: self.on_rq.load(Ordering::Acquire), on_list: self.on_list.load(Ordering::Acquire) }
    }
}

// SAFETY: the only embedded-node accessors are crate-private and unsafe. Their
// class queues atomically claim sole membership, mutate through exclusive queue
// ownership, clear every link, then release the claim. Other fields are atomic.
unsafe impl Sync for SchedEntityState {}
// SAFETY: the unsafe embedded-link accessors obey the same atomic class-queue
// claim/exclusive-owner/clear-before-release protocol. Other fields are atomic.
unsafe impl Sync for SchedRtEntityState {}

#[cfg(test)]
mod tests {
    use super::*;

    const WEIGHTS: [u32; NICE_WIDTH] = [
        88761,71755,56483,46273,36291,29154,23254,18705,14949,11916,
        9548,7620,6100,4904,3906,3121,2501,1991,1586,1277,
        1024,820,655,526,423,335,272,215,172,137,
        110,87,70,56,45,36,29,23,18,15,
    ];
    const INVERSES: [u32; NICE_WIDTH] = [
        48388,59856,76040,92818,118348,147320,184698,229616,287308,360437,
        449829,563644,704093,875809,1099582,1376151,1717300,2157191,2708050,3363326,
        4194304,5237765,6557202,8165337,10153587,12820798,15790321,19976592,24970740,31350126,
        39045157,49367440,61356676,76695844,95443717,119304647,148102320,186737708,238609294,286331153,
    ];

    #[test]
    fn tables_match_all_entries() {
        assert_eq!(SCHED_PRIO_TO_WEIGHT, WEIGHTS);
        assert_eq!(SCHED_PRIO_TO_WMULT, INVERSES);
    }

    #[test]
    fn every_nice_value_selects_and_scales_its_entry() {
        for i in 0..NICE_WIDTH {
            let nice = MIN_NICE + i as i8;
            assert_eq!(nice_index(nice), Some(i));
            assert_eq!(LoadWeight::for_nice(nice), Some(LoadWeight {
                weight: (WEIGHTS[i] as u64) << SCHED_FIXEDPOINT_SHIFT,
                inv_weight: INVERSES[i],
            }));
        }
    }

    #[test]
    fn nice_boundaries_reject_adjacent_invalid_values() {
        assert_eq!(nice_index(MIN_NICE), Some(0));
        assert_eq!(nice_index(MAX_NICE), Some(NICE_WIDTH - 1));
        assert_eq!(nice_index(MIN_NICE - 1), None);
        assert_eq!(nice_index(MAX_NICE + 1), None);
        assert_eq!(LoadWeight::for_nice(MIN_NICE - 1), None);
        assert_eq!(LoadWeight::for_nice(MAX_NICE + 1), None);
    }

    #[test]
    fn table_shape_and_anchor_values_are_sensitive() {
        assert_eq!(LoadWeight::for_nice(-20).unwrap().weight, 88_761 << 10);
        assert_eq!(LoadWeight::for_nice(0).unwrap(), LoadWeight {
            weight: 1_024 << 10, inv_weight: 4_194_304,
        });
        assert_eq!(LoadWeight::for_nice(19).unwrap(), LoadWeight {
            weight: 15 << 10, inv_weight: 286_331_153,
        });
        for pair in SCHED_PRIO_TO_WEIGHT.windows(2) { assert!(pair[0] > pair[1]); }
        for pair in SCHED_PRIO_TO_WMULT.windows(2) { assert!(pair[0] < pair[1]); }
    }

    #[test]
    fn idle_load_uses_its_distinct_constants() {
        assert_eq!(LoadWeight::idle(), LoadWeight {
            weight: 3 << SCHED_FIXEDPOINT_SHIFT,
            inv_weight: 1_431_655_765,
        });
        assert_ne!(LoadWeight::idle(), LoadWeight::for_nice(MAX_NICE).unwrap());
    }

    #[test]
    fn fair_constructor_zeros_runtime_and_queue_state() {
        let se = SchedEntity::for_nice(0).unwrap();
        assert_eq!(se, SchedEntity {
            load: LoadWeight::for_nice(0).unwrap(),
            deadline: 0, min_vruntime: 0, min_slice: 0, max_slice: 0,
            on_rq: false, sched_delayed: false,
            relative_deadline: false, custom_slice: false,
            exec_start: 0, sum_exec_runtime: 0, prev_sum_exec_runtime: 0,
            vruntime: 0, vlag: 0, protected_deadline: 0, slice: 0,
            nr_migrations: 0, depth: 0, runnable_weight: 0,
            avg: SchedAvg::default(),
        });
    }

    #[test]
    fn average_constructor_zeros_every_signal() {
        assert_eq!(SchedAvg::new(), SchedAvg {
            last_update_time: 0, load_sum: 0, runnable_sum: 0,
            util_sum: 0, period_contrib: 0, load_avg: 0,
            runnable_avg: 0, util_avg: 0, util_est: 0,
        });
    }

    #[test]
    fn reweight_changes_only_load_and_rejects_invalid_nice() {
        let mut se = SchedEntity::for_nice(0).unwrap();
        se.deadline = 11;
        se.exec_start = 12;
        se.sum_exec_runtime = 13;
        se.prev_sum_exec_runtime = 14;
        se.vruntime = 15;
        se.vlag = -16;
        se.slice = 17;
        se.nr_migrations = 18;
        se.on_rq = true;
        se.avg.util_avg = 19;
        let mut want = se;
        want.load = LoadWeight::for_nice(-7).unwrap();
        assert!(se.reweight_nice(-7));
        assert_eq!(se, want);
        let unchanged = se;
        assert!(!se.reweight_nice(MAX_NICE + 1));
        assert_eq!(se, unchanged);
        se.reweight_idle();
        want.load = LoadWeight::idle();
        assert_eq!(se, want);
    }

    #[test]
    fn rt_constructor_preserves_quantum_and_zeros_state() {
        let rt = SchedRtEntity::new(37);
        assert_eq!(rt, SchedRtEntity {
            timeout: 0, watchdog_stamp: 0, time_slice: 37, on_rq: false, on_list: false,
        });
    }
}
