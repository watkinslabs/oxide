use super::*;
use crate::driver::{clear_for_tests, register_driver, register_policy, test_guard, CpufreqOps};
use crate::governor::Demand;
use crate::table::{FreqEntry, FreqTable};
use core::sync::atomic::{AtomicU32, Ordering};

struct Hardware { index: AtomicU32, freq: AtomicU32, readable: bool }

impl CpufreqOps for Hardware {
    fn target_index(&self, policy: &Policy, index: usize) -> KResult<()> {
        self.index.store(index as u32, Ordering::Relaxed);
        self.freq.store(policy.table.entries[index].frequency, Ordering::Relaxed);
        Ok(())
    }
    fn get(&self, _cpu: usize) -> Option<u32> {
        if self.readable { Some(self.freq.load(Ordering::Relaxed)) } else { None }
    }
}

fn table() -> FreqTable {
    FreqTable::new(alloc::vec![
        FreqEntry::new(2_400_000, 0), FreqEntry::new(1_800_000, 1),
        FreqEntry::new(1_200_000, 2), FreqEntry::new(800_000, 3),
    ]).expect("table")
}

fn setup(readable: bool)
    -> (std::sync::MutexGuard<'static, ()>, Arc<Hardware>, Arc<Policy>)
{
    let guard = test_guard();
    let ops = Arc::new(Hardware {
        index: AtomicU32::new(2), freq: AtomicU32::new(1_200_000), readable,
    });
    register_driver("acpi-cpufreq", ops.clone()).expect("driver");
    let policy = Policy::new(alloc::vec![0, 1], table(), 10_000, 1_200_000, "performance")
        .expect("policy");
    let policy = register_policy(policy).expect("policy");
    (guard, ops, policy)
}

fn body(policy: &Arc<Policy>, attr: &str) -> String {
    String::from_utf8(show(policy, attr).expect(attr)).expect("utf8")
}

#[test]
fn every_frequency_attribute_reads_in_kilohertz() {
    let (_guard, _ops, policy) = setup(true);
    assert_eq!(body(&policy, "cpuinfo_min_freq"), "800000\n");
    assert_eq!(body(&policy, "cpuinfo_max_freq"), "2400000\n");
    assert_eq!(body(&policy, "scaling_min_freq"), "800000\n");
    assert_eq!(body(&policy, "scaling_max_freq"), "2400000\n");
    assert_eq!(body(&policy, "scaling_cur_freq"), "1200000\n");
    assert_eq!(body(&policy, "cpuinfo_cur_freq"), "1200000\n");
    clear_for_tests();
}

#[test]
fn the_transition_latency_reads_in_nanoseconds() {
    let (_guard, _ops, policy) = setup(true);
    assert_eq!(body(&policy, "cpuinfo_transition_latency"), "10000\n");
    clear_for_tests();
}

#[test]
fn a_platform_that_cannot_be_read_back_says_so_rather_than_guessing() {
    let (_guard, _ops, policy) = setup(false);
    assert_eq!(body(&policy, "cpuinfo_cur_freq"), "<unknown>\n");
    assert_eq!(body(&policy, "scaling_cur_freq"), "1200000\n",
               "the cached value still answers where the hardware cannot");
    clear_for_tests();
}

#[test]
fn the_driver_and_governor_names_read_back() {
    let (_guard, _ops, policy) = setup(true);
    assert_eq!(body(&policy, "scaling_driver"), "acpi-cpufreq\n");
    assert_eq!(body(&policy, "scaling_governor"), "performance\n");
    let available = body(&policy, "scaling_available_governors");
    assert!(available.contains("performance") && available.contains("schedutil"));
    clear_for_tests();
}

#[test]
fn the_cpu_lists_name_the_clock_domain() {
    let (_guard, _ops, policy) = setup(true);
    assert_eq!(body(&policy, "affected_cpus"), "0 1\n");
    assert_eq!(body(&policy, "related_cpus"), "0 1\n");
    clear_for_tests();
}

#[test]
fn the_available_frequency_list_is_ascending_and_space_terminated() {
    let (_guard, _ops, policy) = setup(true);
    assert_eq!(body(&policy, "scaling_available_frequencies"),
               "800000 1200000 1800000 2400000 \n");
    clear_for_tests();
}

#[test]
fn a_ceiling_write_takes_effect_and_pulls_the_current_frequency_down() {
    let (_guard, ops, policy) = setup(true);
    crate::driver::drive(&policy, crate::governor::Target::at_most(2_400_000), 0)
        .expect("drive");
    assert_eq!(ops.freq.load(Ordering::Relaxed), 2_400_000);

    assert_eq!(store(&policy, "scaling_max_freq", b"1200000\n", 0), Ok(8));
    assert_eq!(body(&policy, "scaling_max_freq"), "1200000\n");
    assert_eq!(ops.freq.load(Ordering::Relaxed), 1_200_000,
               "a cap that waits for the next sample is a cap that is not in force");
    clear_for_tests();
}

#[test]
fn a_floor_write_takes_effect_and_pushes_the_current_frequency_up() {
    let (_guard, ops, policy) = setup(true);
    assert_eq!(store(&policy, "scaling_min_freq", b"1800000", 0), Ok(7));
    assert_eq!(body(&policy, "scaling_min_freq"), "1800000\n");
    assert_eq!(ops.freq.load(Ordering::Relaxed), 1_800_000);
    clear_for_tests();
}

#[test]
fn a_user_write_does_not_release_a_thermal_cap() {
    let (_guard, ops, policy) = setup(true);
    crate::driver::set_limits(&policy, LimitSource::Thermal,
        Request { min: None, max: Some(1_200_000) }, 0).expect("cap");
    assert_eq!(store(&policy, "scaling_max_freq", b"2400000", 0), Ok(7));
    assert_eq!(body(&policy, "scaling_max_freq"), "1200000\n");
    assert_eq!(ops.freq.load(Ordering::Relaxed), 1_200_000);
    clear_for_tests();
}

#[test]
fn a_governor_write_only_accepts_one_that_exists() {
    let (_guard, _ops, policy) = setup(true);
    assert_eq!(store(&policy, "scaling_governor", b"schedutil\n", 0), Ok(10));
    assert_eq!(body(&policy, "scaling_governor"), "schedutil\n");
    assert_eq!(store(&policy, "scaling_governor", b"interactive", 0), Err(VfsError::Einval));
    assert_eq!(body(&policy, "scaling_governor"), "schedutil\n");
    clear_for_tests();
}

#[test]
fn a_written_speed_is_programmed_and_reads_back() {
    let (_guard, ops, policy) = setup(true);
    assert_eq!(body(&policy, "scaling_setspeed"), "<unknown>\n");
    assert_eq!(store(&policy, "scaling_setspeed", b"1800000", 0), Ok(7));
    assert_eq!(body(&policy, "scaling_setspeed"), "1800000\n");
    assert_eq!(ops.freq.load(Ordering::Relaxed), 1_800_000);
    clear_for_tests();
}

#[test]
fn boost_is_refused_on_a_table_that_declares_no_boost_point() {
    let (_guard, _ops, policy) = setup(true);
    assert_eq!(body(&policy, "boost"), "0\n");
    assert_eq!(store(&policy, "boost", b"1", 0), Err(VfsError::Einval));
    assert_eq!(store(&policy, "boost", b"0", 0), Ok(1));
    clear_for_tests();
}

#[test]
fn a_read_only_attribute_refuses_a_write() {
    let (_guard, _ops, policy) = setup(true);
    assert_eq!(store(&policy, "cpuinfo_max_freq", b"1", 0), Err(VfsError::Eacces));
    assert_eq!(store(&policy, "scaling_cur_freq", b"1", 0), Err(VfsError::Eacces));
    assert_eq!(show(&policy, "nonexistent"), Err(VfsError::Enoent));
    clear_for_tests();
}

#[test]
fn a_non_numeric_limit_write_is_refused_without_changing_anything() {
    let (_guard, _ops, policy) = setup(true);
    assert_eq!(store(&policy, "scaling_max_freq", b"fast", 0), Err(VfsError::Einval));
    assert_eq!(body(&policy, "scaling_max_freq"), "2400000\n");
    clear_for_tests();
}

#[test]
fn the_statistics_follow_the_transitions_the_driver_accepted() {
    let (_guard, _ops, policy) = setup(true);
    crate::driver::drive(&policy, crate::governor::Target::at_most(2_400_000), 0)
        .expect("drive");
    crate::driver::drive(&policy, crate::governor::Target::at_least(800_000), 1_000_000_000)
        .expect("drive");
    assert_eq!(String::from_utf8(show_stats(&policy, "total_trans", 0).expect("stats"))
               .expect("utf8"), "2\n");
    let occupancy = String::from_utf8(
        show_stats(&policy, "time_in_state", 2_000_000_000).expect("stats")).expect("utf8");
    assert!(occupancy.contains("2400000 100"), "a second at 2.4 GHz is a hundred ticks: {occupancy}");
    clear_for_tests();
}

#[test]
fn a_statistics_reset_clears_them_through_the_attribute() {
    let (_guard, _ops, policy) = setup(true);
    crate::driver::drive(&policy, crate::governor::Target::at_most(2_400_000), 0)
        .expect("drive");
    assert_eq!(store_stats(&policy, "reset", b"1", 0), Ok(1));
    assert_eq!(String::from_utf8(show_stats(&policy, "total_trans", 0).expect("stats"))
               .expect("utf8"), "0\n");
    assert_eq!(store_stats(&policy, "total_trans", b"0", 0), Err(VfsError::Eacces));
    assert_eq!(show_stats(&policy, "reset", 0), Err(VfsError::Eacces));
    clear_for_tests();
}

#[test]
fn a_second_policy_over_the_same_cpu_is_refused() {
    let (_guard, ops, _policy) = setup(true);
    let overlapping = Policy::new(alloc::vec![1, 2], table(), 10_000, 1_200_000, "performance")
        .expect("policy");
    assert!(matches!(register_policy(overlapping), Err(VfsError::Eexist)));
    let _ = ops;
    clear_for_tests();
}

#[test]
fn a_second_driver_registration_is_refused() {
    let (_guard, ops, _policy) = setup(true);
    assert!(matches!(register_driver("other", ops), Err(VfsError::Ebusy)));
    clear_for_tests();
}

#[test]
fn every_published_attribute_actually_renders() {
    let (_guard, _ops, policy) = setup(true);
    for (name, _) in ATTRS {
        assert!(show(&policy, name).is_ok(), "{name} is listed but does not render");
    }
    for (name, mode) in STATS_ATTRS {
        if *mode == WO { continue; }
        assert!(show_stats(&policy, name, 0).is_ok(), "{name} is listed but does not render");
    }
    clear_for_tests();
}

#[test]
fn the_governor_actually_drives_the_hardware_through_the_policy() {
    let (_guard, ops, policy) = setup(true);
    crate::driver::govern(&policy, &Demand::default(), 0).expect("govern");
    assert_eq!(ops.freq.load(Ordering::Relaxed), 2_400_000,
               "the fastest governor was selected at registration");

    crate::driver::set_governor(&policy, "powersave").expect("governor");
    crate::driver::govern(&policy, &Demand::default(), 0).expect("govern");
    assert_eq!(ops.freq.load(Ordering::Relaxed), 800_000);
    clear_for_tests();
}
