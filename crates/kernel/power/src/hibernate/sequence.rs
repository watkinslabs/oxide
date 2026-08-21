//! Checkable write phases and reversible pairings (`32b§7`).

/// Forward operations in execution order.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Step {
    Lease, Console, Notify, Sync, Filesystems, Users, Helpers, Hotplug,
    KernelThreads, Snapshot, DevicesPrepare, DevicesFreeze, DevicesLate,
    DevicesNoirq, Cpus, Irqs, Syscore, ArchSnapshot, Serialize, Commit,
    DevicesPoweroff, Terminal,
}

/// Reverse operation contributed by a successfully completed forward step.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Undo {
    LeaseRelease, ConsoleRestore, NotifyPost, FilesystemsThaw, UsersThaw,
    HelpersEnable, HotplugUnlock, KernelThreadsThaw, SnapshotRelease,
    DevicesComplete, DevicesResume, DevicesResumeEarly, DevicesResumeNoirq,
    CpusOn, IrqsOn, SyscoreResume,
}

/// Complete forward order, including irreversible durability boundaries.
pub const FORWARD: [Step; 22] = [
    Step::Lease, Step::Console, Step::Notify, Step::Sync, Step::Filesystems,
    Step::Users, Step::Helpers, Step::Hotplug, Step::KernelThreads,
    Step::Snapshot, Step::DevicesPrepare, Step::DevicesFreeze,
    Step::DevicesLate, Step::DevicesNoirq, Step::Cpus, Step::Irqs,
    Step::Syscore, Step::ArchSnapshot, Step::Serialize, Step::Commit,
    Step::DevicesPoweroff, Step::Terminal,
];

/// Reverse action installed only after `step` succeeds.
/// # C: O(1)
pub fn undo_for(step: Step) -> Option<Undo> {
    Some(match step {
        Step::Lease => Undo::LeaseRelease,
        Step::Console => Undo::ConsoleRestore,
        Step::Notify => Undo::NotifyPost,
        Step::Filesystems => Undo::FilesystemsThaw,
        Step::Users => Undo::UsersThaw,
        Step::Helpers => Undo::HelpersEnable,
        Step::Hotplug => Undo::HotplugUnlock,
        Step::KernelThreads => Undo::KernelThreadsThaw,
        Step::Snapshot => Undo::SnapshotRelease,
        Step::DevicesPrepare => Undo::DevicesComplete,
        Step::DevicesFreeze => Undo::DevicesResume,
        Step::DevicesLate => Undo::DevicesResumeEarly,
        Step::DevicesNoirq => Undo::DevicesResumeNoirq,
        Step::Cpus => Undo::CpusOn,
        Step::Irqs => Undo::IrqsOn,
        Step::Syscore => Undo::SyscoreResume,
        Step::Sync | Step::ArchSnapshot | Step::Serialize | Step::Commit |
        Step::DevicesPoweroff | Step::Terminal => return None,
    })
}
