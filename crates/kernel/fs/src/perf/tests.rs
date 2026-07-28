// perf_event_open decision-ladder tests. Everything here is a pure function,
// so these run under plain `cargo test -p fs` — no target gate, no phantom.

use syscall::errno::Errno;

use super::attr::{allow_cpu, allow_kernel, parse_attr, reg_mask_ok, AttrErr};
use super::counter::{format_group, format_one, read_size, sw_source, MemberRead, SwCounter,
    SwSource, TaskCount};
use super::ioctl::{classify, period_result, refresh_result, PerfIoctl};
use super::open::{admit, clock_ok, GroupCtx, OpenCtx};
use super::uapi::{attr_bit, attr_off, attr_size, branch, fmt, ioc, open_flags, ptype, sample, sw};

/// A `size`-byte attr buffer with `type` = SOFTWARE and everything else zero.
fn attr_bytes(size: u32) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec![0u8; size as usize];
    put32(&mut v, attr_off::TYPE, ptype::SOFTWARE);
    put32(&mut v, attr_off::SIZE, size);
    v
}
fn put32(v: &mut [u8], off: usize, x: u32) { v[off..off + 4].copy_from_slice(&x.to_le_bytes()); }
fn put64(v: &mut [u8], off: usize, x: u64) { v[off..off + 8].copy_from_slice(&x.to_le_bytes()); }

fn root_ctx() -> OpenCtx {
    OpenCtx { paranoid: 2, perfmon: true, cap_kill: true, nr_cpus: 4,
              task_found: true, may_access: true, group: None }
}
fn user_ctx() -> OpenCtx {
    OpenCtx { perfmon: false, ..root_ctx() }
}

// ---- perf_copy_attr ------------------------------------------------------

#[test]
fn size_zero_means_ver0_and_is_accepted() {
    let raw = attr_bytes(attr_size::VER0);
    let a = parse_attr(&raw, 0, 2, true).expect("size==0 is the VER0 ABI quirk");
    assert_eq!(a.size, attr_size::VER0);
}

#[test]
fn size_below_ver0_is_e2big_not_einval() {
    let raw = attr_bytes(attr_size::VER0);
    assert_eq!(parse_attr(&raw, attr_size::VER0 - 8, 2, true), Err(AttrErr::TooBig));
}

#[test]
fn size_above_page_size_is_e2big() {
    let raw = attr_bytes(attr_size::VER0);
    assert_eq!(parse_attr(&raw, attr_size::CEILING + 1, 2, true), Err(AttrErr::TooBig));
}

#[test]
fn nonzero_tail_past_kernel_struct_is_e2big() {
    let big = attr_size::CURRENT + 8;
    let mut raw = attr_bytes(big);
    raw[attr_size::CURRENT as usize] = 1;
    assert_eq!(parse_attr(&raw, big, 2, true), Err(AttrErr::TooBig));
    // …and a zero tail is fine.
    raw[attr_size::CURRENT as usize] = 0;
    assert!(parse_attr(&raw, big, 2, true).is_ok());
}

#[test]
fn reserved_bitfield_tail_is_einval() {
    let mut raw = attr_bytes(attr_size::CURRENT);
    put64(&mut raw, attr_off::BITS, 1u64 << attr_bit::RESERVED_1_SHIFT);
    assert_eq!(parse_attr(&raw, attr_size::CURRENT, 2, true), Err(AttrErr::Invalid));
}

#[test]
fn undefined_sample_type_and_read_format_bits_are_einval() {
    let mut raw = attr_bytes(attr_size::CURRENT);
    put64(&mut raw, attr_off::SAMPLE_TYPE, sample::MAX);
    assert_eq!(parse_attr(&raw, attr_size::CURRENT, 2, true), Err(AttrErr::Invalid));

    let mut raw = attr_bytes(attr_size::CURRENT);
    put64(&mut raw, attr_off::READ_FORMAT, fmt::MAX);
    assert_eq!(parse_attr(&raw, attr_size::CURRENT, 2, true), Err(AttrErr::Invalid));
}

#[test]
fn branch_stack_priv_levels_need_perfmon_when_paranoid_is_two() {
    let mut raw = attr_bytes(attr_size::CURRENT);
    put64(&mut raw, attr_off::SAMPLE_TYPE, sample::BRANCH_STACK);
    put64(&mut raw, attr_off::BRANCH_SAMPLE_TYPE, branch::KERNEL | branch::USER | (1 << 3));
    assert_eq!(parse_attr(&raw, attr_size::CURRENT, 2, false), Err(AttrErr::NeedsKernelAllow));
    assert!(parse_attr(&raw, attr_size::CURRENT, 2, true).is_ok());
    assert!(parse_attr(&raw, attr_size::CURRENT, 1, false).is_ok());
}

#[test]
fn branch_stack_needs_a_non_priv_bit() {
    let mut raw = attr_bytes(attr_size::CURRENT);
    put64(&mut raw, attr_off::SAMPLE_TYPE, sample::BRANCH_STACK);
    put64(&mut raw, attr_off::BRANCH_SAMPLE_TYPE, branch::PLM_ALL);
    assert_eq!(parse_attr(&raw, attr_size::CURRENT, 0, true), Err(AttrErr::Invalid));
}

#[test]
fn stack_user_size_must_be_u64_aligned_and_below_ushrt_max() {
    let mut raw = attr_bytes(attr_size::CURRENT);
    put64(&mut raw, attr_off::SAMPLE_TYPE, sample::STACK_USER);
    put32(&mut raw, attr_off::SAMPLE_STACK_USER, 12);
    assert_eq!(parse_attr(&raw, attr_size::CURRENT, 0, true), Err(AttrErr::Invalid));
    put32(&mut raw, attr_off::SAMPLE_STACK_USER, 16);
    assert!(parse_attr(&raw, attr_size::CURRENT, 0, true).is_ok());
    put32(&mut raw, attr_off::SAMPLE_STACK_USER, 0x1_0000);
    assert_eq!(parse_attr(&raw, attr_size::CURRENT, 0, true), Err(AttrErr::Invalid));
}

#[test]
fn regs_masks_are_validated() {
    assert!(!reg_mask_ok(0), "an empty register mask is -EINVAL");
    assert!(reg_mask_ok(1));
    let mut raw = attr_bytes(attr_size::CURRENT);
    put64(&mut raw, attr_off::SAMPLE_TYPE, sample::REGS_USER);
    put64(&mut raw, attr_off::SAMPLE_REGS_USER, 0);
    assert_eq!(parse_attr(&raw, attr_size::CURRENT, 0, true), Err(AttrErr::Invalid));
}

#[test]
fn attr_bit_combinations_linux_rejects() {
    let cases: &[(u32, u32)] = &[
        (attr_bit::INHERIT_THREAD, u32::MAX),          // inherit_thread without inherit
        (attr_bit::REMOVE_ON_EXEC, attr_bit::ENABLE_ON_EXEC),
    ];
    for &(a, b) in cases {
        let mut raw = attr_bytes(attr_size::CURRENT);
        let mut bits = 1u64 << a;
        if b != u32::MAX { bits |= 1u64 << b; }
        put64(&mut raw, attr_off::BITS, bits);
        assert_eq!(parse_attr(&raw, attr_size::CURRENT, 0, true), Err(AttrErr::Invalid),
                   "bits {a}/{b} must be rejected");
    }
    // sigtrap without remove_on_exec
    let mut raw = attr_bytes(attr_size::CURRENT);
    put64(&mut raw, attr_off::BITS, 1u64 << attr_bit::SIGTRAP);
    assert_eq!(parse_attr(&raw, attr_size::CURRENT, 0, true), Err(AttrErr::Invalid));
}

#[test]
fn sample_cgroup_is_einval_without_the_perf_cgroup_controller() {
    let mut raw = attr_bytes(attr_size::CURRENT);
    put64(&mut raw, attr_off::SAMPLE_TYPE, sample::CGROUP);
    assert_eq!(parse_attr(&raw, attr_size::CURRENT, 0, true), Err(AttrErr::Invalid));
}

#[test]
fn weight_and_weight_struct_are_mutually_exclusive() {
    let mut raw = attr_bytes(attr_size::CURRENT);
    put64(&mut raw, attr_off::SAMPLE_TYPE, sample::WEIGHT | sample::WEIGHT_STRUCT);
    assert_eq!(parse_attr(&raw, attr_size::CURRENT, 0, true), Err(AttrErr::Invalid));
}

// ---- the open ladder -----------------------------------------------------

fn sw_attr(config: u64) -> super::attr::PerfAttr {
    let mut raw = attr_bytes(attr_size::CURRENT);
    put64(&mut raw, attr_off::CONFIG, config);
    // exclude_kernel keeps an unprivileged open out of the perf_allow_kernel gate.
    put64(&mut raw, attr_off::BITS, 1u64 << attr_bit::EXCLUDE_KERNEL);
    parse_attr(&raw, attr_size::CURRENT, 2, false).expect("valid software attr")
}

#[test]
fn unknown_open_flag_is_einval() {
    let a = sw_attr(sw::CPU_CLOCK);
    assert_eq!(admit(&a, 0, -1, -1, open_flags::ALL << 1, &root_ctx()), Err(Errno::Einval));
}

#[test]
fn hardware_events_report_enoent_not_a_fabricated_counter() {
    // The whole point of the row: a guest with no PMU must answer like Linux
    // with no PMU driver registered, never with an invented value.
    for ty in [ptype::HARDWARE, ptype::HW_CACHE, ptype::RAW, ptype::TRACEPOINT,
               ptype::BREAKPOINT, ptype::MAX, ptype::MAX + 7] {
        let mut raw = attr_bytes(attr_size::CURRENT);
        put32(&mut raw, attr_off::TYPE, ty);
        put64(&mut raw, attr_off::BITS, 1u64 << attr_bit::EXCLUDE_KERNEL);
        let a = parse_attr(&raw, attr_size::CURRENT, 2, false).expect("parse");
        assert_eq!(admit(&a, 0, -1, -1, 0, &root_ctx()), Err(Errno::Enoent),
                   "perf_type_id {ty} must be -ENOENT");
    }
}

#[test]
fn software_config_past_sw_max_is_enoent() {
    let a = sw_attr(sw::MAX);
    assert_eq!(admit(&a, 0, -1, -1, 0, &root_ctx()), Err(Errno::Enoent));
    assert!(admit(&sw_attr(sw::MAX - 1), 0, -1, -1, 0, &root_ctx()).is_ok());
}

#[test]
fn exclude_kernel_clear_needs_perfmon_at_paranoid_two() {
    let mut raw = attr_bytes(attr_size::CURRENT);
    let a = parse_attr(&raw, attr_size::CURRENT, 2, false).expect("parse");
    assert_eq!(admit(&a, 0, -1, -1, 0, &user_ctx()), Err(Errno::Eacces));
    assert!(admit(&a, 0, -1, -1, 0, &root_ctx()).is_ok());
    // paranoid <= 1 lets an unprivileged caller measure the kernel.
    put64(&mut raw, attr_off::BITS, 0);
    let ctx = OpenCtx { paranoid: 1, ..user_ctx() };
    assert!(admit(&a, 0, -1, -1, 0, &ctx).is_ok());
}

#[test]
fn cpu_wide_event_needs_perfmon_at_paranoid_one_and_above() {
    let a = sw_attr(sw::CPU_CLOCK);
    let ctx = OpenCtx { paranoid: 1, ..user_ctx() };
    assert_eq!(admit(&a, -1, 0, -1, 0, &ctx), Err(Errno::Eacces));
    let ctx = OpenCtx { paranoid: 0, ..user_ctx() };
    assert!(admit(&a, -1, 0, -1, 0, &ctx).is_ok());
}

#[test]
fn cpu_wide_event_must_name_a_real_cpu() {
    let a = sw_attr(sw::CPU_CLOCK);
    let ctx = OpenCtx { paranoid: -1, ..user_ctx() };
    // pid == -1 with cpu == -1 is rejected by perf_event_alloc.
    assert_eq!(admit(&a, -1, -1, -1, 0, &ctx), Err(Errno::Einval));
    assert_eq!(admit(&a, -1, 4, -1, 0, &ctx), Err(Errno::Einval), "cpu >= nr_cpus");
    assert!(admit(&a, -1, 3, -1, 0, &ctx).is_ok());
}

#[test]
fn missing_target_pid_is_esrch() {
    let a = sw_attr(sw::TASK_CLOCK);
    let ctx = OpenCtx { task_found: false, ..root_ctx() };
    assert_eq!(admit(&a, 4242, -1, -1, 0, &ctx), Err(Errno::Esrch));
}

#[test]
fn foreign_task_without_ptrace_access_is_eacces() {
    let a = sw_attr(sw::TASK_CLOCK);
    let ctx = OpenCtx { may_access: false, ..user_ctx() };
    assert_eq!(admit(&a, 7, -1, -1, 0, &ctx), Err(Errno::Eacces));
    // CAP_PERFMON bypasses ptrace_may_access, as perf_check_permission does.
    let ctx = OpenCtx { may_access: false, ..root_ctx() };
    assert!(admit(&a, 7, -1, -1, 0, &ctx).is_ok());
}

#[test]
fn group_fd_that_is_not_a_perf_file_is_ebadf() {
    let a = sw_attr(sw::CPU_CLOCK);
    let ctx = OpenCtx { group: None, ..root_ctx() };
    assert_eq!(admit(&a, 0, -1, 3, 0, &ctx), Err(Errno::Ebadf));
}

#[test]
fn group_leader_must_not_itself_be_a_sibling() {
    let a = sw_attr(sw::CPU_CLOCK);
    let g = GroupCtx { leader_inherit: false, leader_is_sibling: true,
                       leader_tid: Some(1), leader_cpu: -1 };
    let ctx = OpenCtx { group: Some(g), ..root_ctx() };
    assert_eq!(admit(&a, 0, -1, 3, 0, &ctx), Err(Errno::Einval));
}

#[test]
fn fd_no_group_makes_a_valid_leader_fd_a_standalone_event() {
    let a = sw_attr(sw::CPU_CLOCK);
    let g = GroupCtx { leader_inherit: false, leader_is_sibling: true,
                       leader_tid: Some(99), leader_cpu: 3 };
    let ctx = OpenCtx { group: Some(g), ..root_ctx() };
    let r = admit(&a, 0, -1, 3, open_flags::FD_NO_GROUP, &ctx).expect("no-group is standalone");
    assert!(!r.join_group);
}

#[test]
fn pid_cgroup_flag_requires_both_pid_and_cpu_then_is_einval() {
    let a = sw_attr(sw::CPU_CLOCK);
    assert_eq!(admit(&a, -1, 0, -1, open_flags::PID_CGROUP, &root_ctx()), Err(Errno::Einval));
    assert_eq!(admit(&a, 5, 0, -1, open_flags::PID_CGROUP, &root_ctx()), Err(Errno::Einval));
}

#[test]
fn fd_cloexec_is_honoured() {
    let a = sw_attr(sw::CPU_CLOCK);
    assert!(!admit(&a, 0, -1, -1, 0, &root_ctx()).unwrap().cloexec);
    assert!(admit(&a, 0, -1, -1, open_flags::FD_CLOEXEC, &root_ctx()).unwrap().cloexec);
}

#[test]
fn sample_period_sign_bit_is_einval() {
    let mut raw = attr_bytes(attr_size::CURRENT);
    put64(&mut raw, attr_off::BITS, 1u64 << attr_bit::EXCLUDE_KERNEL);
    put64(&mut raw, attr_off::SAMPLE_PERIOD, 1u64 << 63);
    let a = parse_attr(&raw, attr_size::CURRENT, 2, false).expect("parse");
    assert_eq!(admit(&a, 0, -1, -1, 0, &root_ctx()), Err(Errno::Einval));
}

#[test]
fn freq_above_the_sample_rate_sysctl_is_einval() {
    let mut raw = attr_bytes(attr_size::CURRENT);
    put64(&mut raw, attr_off::BITS,
        (1u64 << attr_bit::EXCLUDE_KERNEL) | (1u64 << attr_bit::FREQ));
    put64(&mut raw, attr_off::SAMPLE_PERIOD, sched::perf_sw::sample_rate() as u64 + 1);
    let a = parse_attr(&raw, attr_size::CURRENT, 2, false).expect("parse");
    assert_eq!(admit(&a, 0, -1, -1, 0, &root_ctx()), Err(Errno::Einval));
}

#[test]
fn unknown_clockid_is_einval_and_the_five_linux_ids_are_not() {
    for id in [0, 1, 4, 7, 11] { assert!(clock_ok(id), "clockid {id}"); }
    for id in [2, 3, 5, 6, 8, 12, -1] { assert!(!clock_ok(id), "clockid {id}"); }
    let mut raw = attr_bytes(attr_size::CURRENT);
    put64(&mut raw, attr_off::BITS,
        (1u64 << attr_bit::EXCLUDE_KERNEL) | (1u64 << attr_bit::USE_CLOCKID));
    put32(&mut raw, attr_off::CLOCKID, 3);
    let a = parse_attr(&raw, attr_size::CURRENT, 2, false).expect("parse");
    assert_eq!(admit(&a, 0, -1, -1, 0, &root_ctx()), Err(Errno::Einval));
}

#[test]
fn branch_stack_on_a_software_event_is_eopnotsupp() {
    let mut raw = attr_bytes(attr_size::CURRENT);
    put64(&mut raw, attr_off::BITS, 1u64 << attr_bit::EXCLUDE_KERNEL);
    put64(&mut raw, attr_off::SAMPLE_TYPE, sample::BRANCH_STACK);
    put64(&mut raw, attr_off::BRANCH_SAMPLE_TYPE, branch::USER | (1 << 3));
    let a = parse_attr(&raw, attr_size::CURRENT, 0, true).expect("parse");
    assert_eq!(admit(&a, 0, -1, -1, 0, &root_ctx()), Err(Errno::Eopnotsupp));
}

#[test]
fn allow_helpers_match_the_paranoid_ladder() {
    assert!(allow_kernel(1, false));
    assert!(!allow_kernel(2, false));
    assert!(allow_kernel(2, true));
    assert!(allow_cpu(0, false));
    assert!(!allow_cpu(1, false));
    assert!(allow_cpu(1, true));
}

// ---- counters + read framing --------------------------------------------

#[test]
fn every_software_id_maps_to_a_source() {
    assert_eq!(sw_source(sw::CPU_CLOCK), Some(SwSource::CpuClock));
    assert_eq!(sw_source(sw::TASK_CLOCK), Some(SwSource::TaskClock));
    assert_eq!(sw_source(sw::PAGE_FAULTS_MAJ),
               Some(SwSource::TaskCount(TaskCount::PageFaultsMaj)));
    assert_eq!(sw_source(sw::DUMMY), Some(SwSource::Zero));
    assert_eq!(sw_source(sw::MAX), None);
}

#[test]
fn read_size_matches_linux_perf_event_read_size() {
    assert_eq!(read_size(0, 0), 8);
    assert_eq!(read_size(fmt::TOTAL_TIME_ENABLED | fmt::TOTAL_TIME_RUNNING, 0), 24);
    assert_eq!(read_size(fmt::ID, 0), 16);
    assert_eq!(read_size(fmt::ID | fmt::LOST, 0), 24);
    // GROUP: leading nr, then (1 + nr_siblings) entries.
    assert_eq!(read_size(fmt::GROUP, 2), 8 + 3 * 8);
    assert_eq!(read_size(fmt::GROUP | fmt::ID | fmt::TOTAL_TIME_ENABLED, 1),
               8 + 8 + 2 * 16);
}

#[test]
fn format_one_emits_exactly_read_size_bytes_in_linux_field_order() {
    let rf = fmt::TOTAL_TIME_ENABLED | fmt::TOTAL_TIME_RUNNING | fmt::ID | fmt::LOST;
    let out = format_one(rf, MemberRead { count: 7, id: 9, lost: 3 }, 100, 90);
    assert_eq!(out.len(), read_size(rf, 0));
    let w: alloc::vec::Vec<u64> = out.chunks(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
    assert_eq!(w, alloc::vec![7, 100, 90, 9, 3]);
}

#[test]
fn format_group_emits_nr_then_times_then_per_member_entries() {
    let rf = fmt::GROUP | fmt::ID | fmt::TOTAL_TIME_ENABLED;
    let m = [MemberRead { count: 1, id: 10, lost: 0 },
             MemberRead { count: 2, id: 11, lost: 0 }];
    let out = format_group(rf, &m, 50, 50);
    assert_eq!(out.len(), read_size(rf, 1));
    let w: alloc::vec::Vec<u64> = out.chunks(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
    assert_eq!(w, alloc::vec![2, 50, 1, 10, 2, 11]);
}

#[test]
fn counter_accumulates_only_while_enabled() {
    let mut c = SwCounter::new(100, 0, true);
    assert_eq!(c.count(150), 50);
    c.disable(150, 10);
    assert_eq!(c.count(999), 50, "a disabled counter must not advance");
    assert_eq!(c.time_enabled(999), 10);
    c.enable(1000, 20);
    assert_eq!(c.count(1005), 55);
    c.reset(1005);
    assert_eq!(c.count(1005), 0);
    assert_eq!(c.count(1006), 1);
}

// ---- ioctl ---------------------------------------------------------------

#[test]
fn ioctl_numbers_classify_to_every_linux_command() {
    let table = [
        (ioc::ENABLE, PerfIoctl::Enable), (ioc::DISABLE, PerfIoctl::Disable),
        (ioc::REFRESH, PerfIoctl::Refresh), (ioc::RESET, PerfIoctl::Reset),
        (ioc::PERIOD, PerfIoctl::Period), (ioc::SET_OUTPUT, PerfIoctl::SetOutput),
        (ioc::SET_FILTER, PerfIoctl::SetFilter), (ioc::ID, PerfIoctl::Id),
        (ioc::SET_BPF, PerfIoctl::SetBpf), (ioc::PAUSE_OUTPUT, PerfIoctl::PauseOutput),
        (ioc::QUERY_BPF, PerfIoctl::QueryBpf),
        (ioc::MODIFY_ATTRIBUTES, PerfIoctl::ModifyAttributes),
    ];
    for (req, want) in table { assert_eq!(classify(req), Some(want), "req {req:#x}"); }
    assert_eq!(classify(0x2410), None, "unknown '$' command is -ENOTTY");
    assert_eq!(classify(0x5401), None, "a TCGETS is -ENOTTY on a perf fd");
}

#[test]
fn period_and_refresh_rules_match_linux() {
    assert_eq!(refresh_result(true, true), Err(Errno::Einval), "inherited events");
    assert_eq!(refresh_result(false, false), Err(Errno::Einval), "non-sampling events");
    assert!(refresh_result(false, true).is_ok());

    assert_eq!(period_result(false, false, 1, 100_000), Err(Errno::Einval));
    assert_eq!(period_result(true, false, 0, 100_000), Err(Errno::Einval));
    assert_eq!(period_result(true, false, 1 << 63, 100_000), Err(Errno::Einval));
    assert_eq!(period_result(true, true, 100_001, 100_000), Err(Errno::Einval));
    assert!(period_result(true, true, 100_000, 100_000).is_ok());
    assert!(period_result(true, false, 4096, 100_000).is_ok());
}
