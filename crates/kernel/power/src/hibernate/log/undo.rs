//! Allocation-free diagnostics for reverse hibernation transaction boundaries.

use super::super::sequence::Undo;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UndoBoundary { Begin, End }

#[cfg(feature = "debug-hibernate")]
/// # C: O(1)
pub fn undo(action: Undo, boundary: UndoBoundary) {
    klog::write_raw(b"[hibernate] undo=");
    klog::write_raw(action_name(action));
    klog::write_raw(b" boundary=");
    klog::write_raw(match boundary {
        UndoBoundary::Begin => b"begin", UndoBoundary::End => b"end",
    });
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
/// # C: O(1)
pub fn undo(_: Undo, _: UndoBoundary) {}

#[cfg(any(test, feature = "debug-hibernate"))]
fn action_name(action: Undo) -> &'static [u8] {
    match action {
        Undo::LeaseRelease => b"lease_release",
        Undo::ConsoleRestore => b"console_restore",
        Undo::NotifyPost => b"notify_post",
        Undo::FilesystemsThaw => b"filesystems_thaw",
        Undo::UsersThaw => b"users_thaw",
        Undo::HelpersEnable => b"helpers_enable",
        Undo::HotplugUnlock => b"hotplug_unlock",
        Undo::KernelThreadsThaw => b"kernel_threads_thaw",
        Undo::SnapshotRelease => b"snapshot_release",
        Undo::DevicesComplete => b"devices_complete",
        Undo::DevicesResume => b"devices_resume",
        Undo::DevicesResumeEarly => b"devices_resume_early",
        Undo::DevicesResumeNoirq => b"devices_resume_noirq",
        Undo::CpusOn => b"cpus_on",
        Undo::IrqsOn => b"irqs_on",
        Undo::SyscoreResume => b"syscore_resume",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_reverse_boundary_has_a_nonempty_unique_name() {
        let actions = [
            Undo::LeaseRelease, Undo::ConsoleRestore, Undo::NotifyPost,
            Undo::FilesystemsThaw, Undo::UsersThaw, Undo::HelpersEnable,
            Undo::HotplugUnlock, Undo::KernelThreadsThaw, Undo::SnapshotRelease,
            Undo::DevicesComplete, Undo::DevicesResume, Undo::DevicesResumeEarly,
            Undo::DevicesResumeNoirq, Undo::CpusOn, Undo::IrqsOn,
            Undo::SyscoreResume,
        ];
        for (index, action) in actions.iter().enumerate() {
            let name = action_name(*action);
            assert!(!name.is_empty());
            assert!(!actions[..index].iter().any(|other| action_name(*other) == name));
        }
        assert_ne!(UndoBoundary::Begin, UndoBoundary::End);
    }
}
