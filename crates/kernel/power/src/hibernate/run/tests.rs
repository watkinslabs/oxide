use super::*;
use alloc::vec::Vec;
use core::convert::Infallible;

struct Recording {
    log: Vec<&'static str>,
    fail: Option<&'static str>,
    side: Side,
    finish: FinishMode,
    fail_unmark: bool,
}

impl Recording {
    fn new(side: Side) -> Self {
        Self { log: Vec::new(), fail: None, side, finish: FinishMode::PowerDown,
            fail_unmark: false }
    }
    fn call(&mut self, name: &'static str) -> KResult<()> {
        self.log.push(name);
        if self.fail == Some(name) { Err(Error::Io) } else { Ok(()) }
    }
    fn note(&mut self, name: &'static str) { self.log.push(name); }
}

fn run_hibernate(be: &mut Recording) -> KResult<()> {
    let _guard = crate::suspend::test_lock();
    hibernate(be)
}

impl Backend for Recording {
    fn lease_acquire(&mut self) -> KResult<()> { self.call("lease") }
    fn lease_release(&mut self) { self.note("lease_release") }
    fn console_prepare(&mut self) -> KResult<()> { self.call("console") }
    fn console_restore(&mut self) { self.note("console_restore") }
    fn notify_prepare(&mut self) -> KResult<()> { self.call("notify") }
    fn notify_post(&mut self) { self.note("notify_post") }
    fn sync_filesystems(&mut self) -> KResult<()> { self.call("sync") }
    fn filesystems_freeze(&mut self) -> KResult<()> { self.call("fs_freeze") }
    fn filesystems_thaw(&mut self) { self.note("fs_thaw") }
    fn users_freeze(&mut self) -> KResult<()> { self.call("users_freeze") }
    fn users_thaw(&mut self) { self.note("users_thaw") }
    fn helpers_disable(&mut self) -> KResult<()> { self.call("helpers_disable") }
    fn helpers_enable(&mut self) { self.note("helpers_enable") }
    fn hotplug_lock(&mut self) -> KResult<()> { self.call("hotplug_lock") }
    fn hotplug_unlock(&mut self) { self.note("hotplug_unlock") }
    fn kernel_threads_freeze(&mut self) -> KResult<()> { self.call("kernel_freeze") }
    fn kernel_threads_thaw(&mut self) { self.note("kernel_thaw") }
    fn snapshot_prepare(&mut self) -> KResult<()> { self.call("snapshot") }
    fn snapshot_release(&mut self) { self.note("snapshot_release") }
    fn devices_prepare(&mut self) -> KResult<()> { self.call("dev_prepare") }
    fn devices_freeze(&mut self) -> KResult<()> { self.call("dev_freeze") }
    fn devices_late(&mut self) -> KResult<()> { self.call("dev_late") }
    fn devices_noirq(&mut self) -> KResult<()> { self.call("dev_noirq") }
    fn devices_resume_noirq(&mut self, kind: ResumeKind) { self.note(if kind == ResumeKind::Restore { "dev_restore_noirq" } else { "dev_thaw_noirq" }) }
    fn devices_resume_early(&mut self, kind: ResumeKind) { self.note(if kind == ResumeKind::Restore { "dev_restore_early" } else { "dev_thaw_early" }) }
    fn devices_resume(&mut self, kind: ResumeKind) { self.note(if kind == ResumeKind::Restore { "dev_restore" } else { "dev_thaw" }) }
    fn devices_complete(&mut self, kind: ResumeKind) { self.note(if kind == ResumeKind::Restore { "dev_restore_complete" } else { "dev_thaw_complete" }) }
    fn cpus_off(&mut self) -> KResult<()> { self.call("cpus_off") }
    fn cpus_on(&mut self) -> KResult<()> { self.call("cpus_on") }
    fn irqs_off(&mut self) -> u64 { self.note("irqs_off"); 0x55 }
    fn irqs_on(&mut self, state: u64) { assert_eq!(state, 0x55); self.note("irqs_on") }
    fn syscore_suspend(&mut self) -> KResult<()> { self.call("syscore_suspend") }
    fn syscore_resume(&mut self) { self.note("syscore_resume") }
    fn arch_snapshot_and_copy(&mut self) -> KResult<Side> { self.call("arch_snapshot")?; Ok(self.side) }
    fn serialize_image(&mut self) -> KResult<()> { self.call("serialize") }
    fn commit_marker(&mut self) -> KResult<()> { self.call("commit") }
    fn unmark_image(&mut self) -> KResult<()> {
        self.note("unmark");
        if self.fail_unmark { Err(Error::Io) } else { Ok(()) }
    }
    fn finish_mode(&self) -> FinishMode { self.finish }
    fn suspend_with_image(&mut self) -> KResult<()> { self.call("suspend_image") }
    fn prepare_test_resume(&mut self) -> KResult<()> { self.call("prepare_test") }
    fn enter_test_resume(&mut self) -> KResult<Infallible> {
        self.note("enter_test"); Err(Error::Io)
    }
    fn devices_poweroff(&mut self) -> KResult<()> { self.call("dev_poweroff") }
    fn terminal(&mut self, _claim: &crate::transition::Claim) -> KResult<Infallible> {
        self.note("terminal"); Err(Error::Io)
    }
    fn halt_with_live_image(&mut self) -> ! { panic!("live hibernation image") }
}

#[test]
fn suspend_mode_unmarks_after_wake_without_a_terminal_transition() {
    let mut be = Recording::new(Side::Original);
    be.finish = FinishMode::Suspend;
    assert_eq!(run_hibernate(&mut be), Ok(()));
    let at = be.log.iter().position(|event| *event == "suspend_image").unwrap();
    assert_eq!(&be.log[at..at + 2], ["suspend_image", "unmark"]);
    assert!(!be.log.contains(&"dev_poweroff"));
    assert!(!be.log.contains(&"terminal"));
}

#[test]
fn test_resume_consumes_then_runs_a_second_device_restore_cycle() {
    let mut be = Recording::new(Side::Original);
    be.finish = FinishMode::TestResume;
    assert_eq!(run_hibernate(&mut be), Err(Error::Io));
    let at = be.log.iter().position(|event| *event == "prepare_test").unwrap();
    assert_eq!(&be.log[at..at + 8], ["prepare_test", "dev_prepare", "dev_freeze",
        "dev_late", "dev_noirq", "cpus_off", "irqs_off", "syscore_suspend"]);
    assert!(be.log.contains(&"enter_test"));
    assert!(!be.log.contains(&"unmark"), "prepare consumed the marker");
    assert!(!be.log.contains(&"dev_poweroff"));
}

fn outer_unwind() -> [&'static str; 9] {
    ["snapshot_release", "kernel_thaw", "hotplug_unlock", "helpers_enable",
     "users_thaw", "fs_thaw", "notify_post", "console_restore", "lease_release"]
}

#[test]
fn original_side_resumes_for_io_then_unmarks_before_outer_unwind() {
    let mut be = Recording::new(Side::Original);
    assert_eq!(run_hibernate(&mut be), Err(Error::Io));
    let core = ["syscore_resume", "irqs_on", "cpus_on", "dev_thaw_noirq",
                "dev_thaw_early", "dev_thaw", "dev_thaw_complete"];
    let core_at = be.log.iter().position(|e| *e == "syscore_resume").unwrap();
    assert_eq!(&be.log[core_at..core_at + core.len()], &core);
    let tail = ["serialize", "commit", "dev_poweroff", "terminal", "unmark"];
    let tail_at = be.log.iter().position(|e| *e == "serialize").unwrap();
    assert_eq!(&be.log[tail_at..tail_at + tail.len()], &tail);
    assert_eq!(&be.log[tail_at + tail.len()..], &outer_unwind());
}

#[test]
fn failure_unwinds_only_completed_steps_once_in_reverse() {
    let mut be = Recording::new(Side::Original);
    be.fail = Some("dev_late");
    assert_eq!(run_hibernate(&mut be), Err(Error::Io));
    let failure = be.log.iter().position(|e| *e == "dev_late").unwrap();
    let expected = ["dev_thaw", "dev_thaw_complete", "snapshot_release",
        "kernel_thaw", "hotplug_unlock", "helpers_enable", "users_thaw",
        "fs_thaw", "notify_post", "console_restore", "lease_release"];
    assert_eq!(&be.log[failure + 1..], &expected);
    assert!(!be.log.contains(&"dev_thaw_early"));
}

/// A failed architecture snapshot may retain a very large preallocated copy
/// pool. Its backend owner must survive until the machine is usable again:
/// syscore, local IRQs, secondary CPUs, and devices all recover before the
/// snapshot-release callback is allowed to free those frames.
#[test]
fn failed_arch_snapshot_recovers_machine_before_releasing_snapshot_memory() {
    let mut be = Recording::new(Side::Original);
    be.fail = Some("arch_snapshot");
    assert_eq!(run_hibernate(&mut be), Err(Error::Io));
    let failure = be.log.iter().position(|event| *event == "arch_snapshot").unwrap();
    let expected = ["syscore_resume", "irqs_on", "cpus_on", "dev_thaw_noirq",
        "dev_thaw_early", "dev_thaw", "dev_thaw_complete", "snapshot_release",
        "kernel_thaw", "hotplug_unlock", "helpers_enable", "users_thaw",
        "fs_thaw", "notify_post", "console_restore", "lease_release"];
    assert_eq!(&be.log[failure + 1..], &expected);
}

#[test]
fn failed_cpu_restart_finishes_device_and_outer_unwind_without_storage() {
    let mut be = Recording::new(Side::Original);
    be.fail = Some("cpus_on");
    assert_eq!(run_hibernate(&mut be), Err(Error::Io));
    let failure = be.log.iter().position(|event| *event == "cpus_on").unwrap();
    let recovery = ["dev_thaw_noirq", "dev_thaw_early", "dev_thaw",
        "dev_thaw_complete", "snapshot_release", "kernel_thaw", "hotplug_unlock",
        "helpers_enable", "users_thaw", "fs_thaw", "notify_post",
        "console_restore", "lease_release"];
    assert_eq!(&be.log[failure + 1..], &recovery);
    for event in ["serialize", "commit", "dev_poweroff", "terminal", "unmark"] {
        assert!(!be.log.contains(&event));
    }
}

#[test]
fn restored_side_uses_restore_callbacks_and_never_writes_storage() {
    let mut be = Recording::new(Side::Restored);
    assert_eq!(run_hibernate(&mut be), Ok(()));
    for event in ["dev_restore_noirq", "dev_restore_early", "dev_restore",
                  "dev_restore_complete"] { assert!(be.log.contains(&event)); }
    for event in ["serialize", "commit", "dev_poweroff", "terminal", "unmark"] {
        assert!(!be.log.contains(&event));
    }
    assert_eq!(&be.log[be.log.len() - outer_unwind().len()..], &outer_unwind());
}

#[test]
fn marker_boundary_separates_plain_unwind_from_mandatory_unmark() {
    let mut before = Recording::new(Side::Original);
    before.fail = Some("serialize");
    assert_eq!(run_hibernate(&mut before), Err(Error::Io));
    assert!(!before.log.contains(&"commit"));
    assert!(!before.log.contains(&"unmark"));

    let mut after = Recording::new(Side::Original);
    after.fail = Some("dev_poweroff");
    assert_eq!(run_hibernate(&mut after), Err(Error::Io));
    let failure = after.log.iter().position(|e| *e == "dev_poweroff").unwrap();
    assert_eq!(after.log[failure + 1], "unmark");
    assert_eq!(&after.log[failure + 2..], &outer_unwind());
    assert!(!after.log.contains(&"terminal"));
}

#[test]
fn ambiguous_commit_failure_is_durably_unmarked_before_thaw() {
    let _guard = crate::suspend::test_lock();
    let claim = crate::transition::try_claim().unwrap();
    let mut be = Recording::new(Side::Original);
    be.fail = Some("commit");
    assert_eq!(transaction(&claim, &mut be), Err(Error::Io));
    let commit = be.log.iter().position(|event| *event == "commit").unwrap();
    assert_eq!(be.log[commit + 1], "unmark",
        "commit failure must be treated as possibly published");
    assert_eq!(&be.log[commit + 2..], &outer_unwind());
}

#[test]
#[should_panic(expected = "live hibernation image")]
fn ambiguous_commit_failure_halts_when_durable_unmark_cannot_be_proved() {
    let _guard = crate::suspend::test_lock();
    let claim = crate::transition::try_claim().unwrap();
    let mut be = Recording::new(Side::Original);
    be.fail = Some("commit");
    be.fail_unmark = true;
    let _ = transaction(&claim, &mut be);
}

#[test]
fn shared_transition_claim_refuses_a_second_writer_before_backend_work() {
    let _guard = crate::suspend::test_lock();
    let claim = crate::transition::try_claim().unwrap();
    let mut be = Recording::new(Side::Original);
    assert_eq!(hibernate(&mut be), Err(Error::Busy));
    assert!(be.log.is_empty());
    drop(claim);
}

#[test]
fn cold_restore_terminal_failure_unwinds_restore_callbacks_in_reverse() {
    let _guard = crate::suspend::test_lock();
    let claim = crate::transition::try_claim().unwrap();
    let mut be = Recording::new(Side::Original);
    assert_eq!(restore_loaded(&claim, &mut be, || Err(Error::Io)), Err(Error::Io));
    assert_eq!(be.log, ["console", "notify", "fs_freeze", "users_freeze",
        "helpers_disable", "hotplug_lock", "kernel_freeze", "dev_prepare",
        "dev_freeze", "dev_late", "dev_noirq", "cpus_off", "irqs_off",
        "syscore_suspend", "syscore_resume", "irqs_on", "cpus_on",
        "dev_thaw_noirq", "dev_thaw_early", "dev_thaw",
        "dev_thaw_complete", "kernel_thaw", "hotplug_unlock",
        "helpers_enable", "users_thaw", "fs_thaw", "notify_post",
        "console_restore"]);
}

#[test]
fn cold_restore_failure_unwinds_only_completed_fresh_kernel_phases() {
    let _guard = crate::suspend::test_lock();
    let claim = crate::transition::try_claim().unwrap();
    let mut be = Recording::new(Side::Original);
    be.fail = Some("dev_late");
    assert_eq!(restore_loaded(&claim, &mut be, || panic!("terminal reached")), Err(Error::Io));
    let failure = be.log.iter().position(|event| *event == "dev_late").unwrap();
    assert_eq!(&be.log[failure + 1..], ["dev_thaw", "dev_thaw_complete",
        "kernel_thaw", "hotplug_unlock", "helpers_enable", "users_thaw",
        "fs_thaw", "notify_post", "console_restore"]);
    assert!(!be.log.contains(&"dev_thaw_early"));
}
