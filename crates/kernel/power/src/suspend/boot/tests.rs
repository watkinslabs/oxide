use super::*;

// The hook set is assembled in several passes, from subsystems that initialise
// at different points in the boot. The failure this guards against is a later
// pass clearing an earlier one's hooks — which would leave a suspend that runs
// but skips, say, every device, silently.

fn a() -> KResult<()> { Ok(()) }
fn b() {}

#[test]
fn a_later_pass_does_not_clear_an_earlier_one() {
    let _g = crate::suspend::test_lock();
    wire::set_hooks(SuspendHooks::default());
    set_sync_hook(a);
    assert!(wire::hooks().sync_filesystems.is_some());

    set_cpu_hooks(a, b);
    assert!(wire::hooks().sync_filesystems.is_some(), "the CPU pass cleared the sync hook");
    assert!(wire::hooks().disable_secondary_cpus.is_some());

    set_device_hooks(DeviceHooks {
        dpm_suspend: Some(a), dpm_resume: Some(b), ..DeviceHooks::default()
    });
    assert!(wire::hooks().sync_filesystems.is_some(), "the device pass cleared the sync hook");
    assert!(wire::hooks().disable_secondary_cpus.is_some(),
        "the device pass cleared the CPU hooks");
    assert!(wire::hooks().dpm_suspend.is_some());
    assert!(wire::hooks().dpm_resume.is_some());

    wire::set_hooks(SuspendHooks::default());
}

#[test]
fn the_device_pass_installs_every_phase_it_is_given() {
    let _g = crate::suspend::test_lock();
    wire::set_hooks(SuspendHooks::default());
    set_device_hooks(DeviceHooks {
        console_suspend: Some(b), console_resume: Some(b),
        dpm_prepare: Some(a), dpm_suspend: Some(a),
        dpm_suspend_late: Some(a), dpm_suspend_noirq: Some(a),
        dpm_resume_noirq: Some(b), dpm_resume_early: Some(b),
        dpm_resume: Some(b), dpm_complete: Some(b),
    });
    let h = wire::hooks();
    assert!(h.console_suspend.is_some() && h.console_resume.is_some());
    assert!(h.dpm_prepare.is_some() && h.dpm_suspend.is_some());
    assert!(h.dpm_suspend_late.is_some() && h.dpm_suspend_noirq.is_some());
    assert!(h.dpm_resume_noirq.is_some() && h.dpm_resume_early.is_some());
    assert!(h.dpm_resume.is_some() && h.dpm_complete.is_some());
    wire::set_hooks(SuspendHooks::default());
}

#[test]
fn an_unwired_device_pass_leaves_the_phases_absent_rather_than_stubbed() {
    let _g = crate::suspend::test_lock();
    wire::set_hooks(SuspendHooks::default());
    set_device_hooks(DeviceHooks::default());
    assert!(wire::hooks().dpm_suspend.is_none());
}
