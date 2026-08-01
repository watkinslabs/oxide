// The two `fanotify_init` arguments whose whole effect is a VALUE a reader sees
// on every event: `FAN_REPORT_TID`'s choice of reported id, and
// `event_f_flags`' open mode for each descriptor a group mints.
//
// Both decisions used to live inside `#[cfg(target_os = "oxide-kernel")]`
// functions, where a `#[cfg(test)] mod tests` compiles to nothing and the hosted
// suite reports "ok" having built none of it. Neither had ever executed a single
// assertion. They are pure functions over sampled facts here, with no target
// gate, so the gated call sites are left holding only the sampling (`docs/53`).

use vfs::OpenFlags;

/// `FAN_CLOEXEC`-equivalent bit inside `event_f_flags`. It does NOT belong in
/// the description's own flags: it is a property of the DESCRIPTOR TABLE SLOT,
/// applied after the fd is installed. Leaving it in the open mode makes every
/// event fd claim a flag `fcntl(F_GETFL)` never reports.
const EVENT_F_SLOT_FLAGS: u32 = OpenFlags::O_CLOEXEC.bits();

/// The open mode a group's event descriptors carry, from its `event_f_flags`.
///
/// This is the whole point of `fanotify_init`'s second argument: a daemon that
/// asked for `O_RDWR` descriptors and silently received read-only ones fails on
/// its first write to one.
/// # C: O(1)
pub(crate) fn event_open_flags(event_f_flags: u32) -> OpenFlags {
    OpenFlags::from_bits_truncate(event_f_flags & !EVENT_F_SLOT_FLAGS)
}

/// Whether an installed event descriptor must be marked close-on-exec.
/// # C: O(1)
pub(crate) fn event_fd_cloexec(event_f_flags: u32) -> bool {
    event_f_flags & EVENT_F_SLOT_FLAGS != 0
}

/// The id reported for the acting process.
///
/// `FAN_REPORT_TID` selects the acting THREAD's id; without it the id is the
/// thread group's, which is what a daemon matching against `/proc/<pid>`
/// expects. A thread inside a pid namespace reports the id VISIBLE in that
/// namespace, falling back to the global one only when it has no visible id —
/// a reported id userspace cannot act on is worse than no id at all.
/// # C: O(1)
pub(crate) fn select_reported_pid(reports_tid: bool, visible_pid: u32, vtid: u32, tid: u32) -> u32 {
    if !reports_tid { return visible_pid; }
    if vtid != 0 { vtid } else { tid }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Without `FAN_REPORT_TID` every thread of a process reports the SAME id,
    /// its thread group's — which is what makes the field usable as a
    /// `/proc/<pid>` key. # C: O(1)
    #[test]
    fn a_group_without_report_tid_reports_the_thread_group() {
        assert_eq!(select_reported_pid(false, 100, 7, 7), 100);
        assert_eq!(select_reported_pid(false, 100, 0, 104), 100,
                   "the thread's own ids are not consulted at all");
    }

    /// With it, two threads of one process are distinguishable. # C: O(1)
    #[test]
    fn report_tid_reports_the_acting_thread() {
        assert_eq!(select_reported_pid(true, 100, 104, 104), 104);
        assert_ne!(select_reported_pid(true, 100, 104, 104),
                   select_reported_pid(true, 100, 105, 105));
    }

    /// A namespaced thread reports the id visible in its namespace; the global
    /// id is the fallback for a thread that has none. # C: O(1)
    #[test]
    fn report_tid_prefers_the_namespace_visible_id() {
        assert_eq!(select_reported_pid(true, 100, 3, 90210), 3);
        assert_eq!(select_reported_pid(true, 100, 0, 90210), 90210);
    }

    /// The access mode reaches the descriptor. A group that asked for `O_RDWR`
    /// and silently got `O_RDONLY` fails on its first write to an event fd.
    /// # C: O(1)
    #[test]
    fn the_requested_access_mode_reaches_the_event_descriptor() {
        assert!(event_open_flags(OpenFlags::O_RDWR.bits()).contains(OpenFlags::O_RDWR));
        assert!(event_open_flags(OpenFlags::O_WRONLY.bits()).contains(OpenFlags::O_WRONLY));
        // O_RDONLY is the zero mode: the absence of the other two.
        let ro = event_open_flags(0);
        assert!(!ro.contains(OpenFlags::O_WRONLY) && !ro.contains(OpenFlags::O_RDWR));
    }

    /// The status flags a caller may set ride along on the description.
    /// # C: O(1)
    #[test]
    fn status_flags_ride_along_on_the_description() {
        let f = event_open_flags(
            OpenFlags::O_RDWR.bits() | OpenFlags::O_NONBLOCK.bits() | OpenFlags::O_APPEND.bits());
        assert!(f.contains(OpenFlags::O_NONBLOCK));
        assert!(f.contains(OpenFlags::O_APPEND));
        assert!(f.contains(OpenFlags::O_RDWR));
    }

    /// `O_CLOEXEC` is a descriptor-table property, not a description flag, so it
    /// is stripped from the open mode and applied to the installed slot instead.
    /// Left in the mode, every event fd reports a flag `fcntl(F_GETFL)` never
    /// returns. # C: O(1)
    #[test]
    fn cloexec_is_a_slot_property_not_a_description_flag() {
        let req = OpenFlags::O_RDWR.bits() | OpenFlags::O_CLOEXEC.bits();
        assert!(!event_open_flags(req).contains(OpenFlags::O_CLOEXEC),
                "stripped from the description");
        assert!(event_fd_cloexec(req), "and applied to the descriptor instead");
        assert!(!event_fd_cloexec(OpenFlags::O_RDWR.bits()));
    }
}
