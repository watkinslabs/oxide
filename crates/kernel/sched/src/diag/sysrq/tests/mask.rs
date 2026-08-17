use crate::diag::sysrq::mask::{effective_mask, mask_allows, ENABLE_ALL, ENABLE_BOOT, ENABLE_DUMP};
use crate::diag::sysrq::table::Cmd;

/// A distribution's `sysctl.d` lowers `kernel.sysrq` after the boot line asked
/// for it, and the keys are then refused on the one machine that needs them.
/// The boot parameter is what userspace cannot overwrite.
#[test]
fn the_boot_parameter_overrides_a_sysctl_that_refuses_everything() {
    let refuse_all = 0;
    assert!(!mask_allows(refuse_all, Cmd::ShowTasks), "the sysctl alone refuses the dump");
    assert!(mask_allows(effective_mask(refuse_all, true), Cmd::ShowTasks));
    assert!(mask_allows(effective_mask(refuse_all, true), Cmd::Crash));
    assert!(mask_allows(effective_mask(refuse_all, true), Cmd::Reboot));
}

/// ...and without it the sysctl still decides, in both directions.
#[test]
fn without_the_boot_parameter_the_sysctl_still_decides() {
    assert_eq!(effective_mask(ENABLE_DUMP, false), ENABLE_DUMP);
    assert!(!mask_allows(effective_mask(ENABLE_DUMP, false), Cmd::Reboot));
    assert!(mask_allows(effective_mask(ENABLE_DUMP, false), Cmd::ShowTasks));
    assert_eq!(effective_mask(0, false), 0);
}

/// `1` means all of them. Read as a bit pattern it enables the loglevel group
/// and nothing else, which is the setting nearly every machine runs.
#[test]
fn a_mask_of_one_enables_every_command() {
    for cmd in [Cmd::Crash, Cmd::Reboot, Cmd::PowerOff, Cmd::ShowTasks,
                Cmd::ShowBlocked, Cmd::ShowBacktraceAllCpus, Cmd::ShowRegisters] {
        assert!(mask_allows(ENABLE_ALL, cmd), "{cmd:?} refused under the enable-all mask");
    }
}

#[test]
fn a_zero_mask_refuses_every_command() {
    for cmd in [Cmd::Crash, Cmd::Reboot, Cmd::ShowTasks, Cmd::Help] {
        assert!(!mask_allows(0, cmd), "{cmd:?} ran under a zero mask");
    }
}

/// The groups are independent: a machine that allows dumps must not thereby
/// allow a reboot.
#[test]
fn the_enable_groups_do_not_leak_into_each_other() {
    assert!(mask_allows(ENABLE_DUMP, Cmd::Crash));
    assert!(!mask_allows(ENABLE_DUMP, Cmd::Reboot));
    assert!(mask_allows(ENABLE_BOOT, Cmd::Reboot));
    assert!(!mask_allows(ENABLE_BOOT, Cmd::ShowTasks));
}
