// Unpublished native child executable identity, shared with canonical procfs readers.
extern crate alloc;
use alloc::string::String;

/// Publish image metadata before the child enters the task registry.
///
/// `windows_path` is the image name the NT request carried. It names the file
/// as Windows code sees it and is the right thing for `comm`, but it is not
/// necessarily a host pathname, so `exe` is published only from
/// `host_path` — the path this launch actually resolved and opened. A child
/// whose image came from somewhere with no host pathname keeps no `exe` at
/// all rather than reporting one that never existed.
/// # C: O(windows_path.len() + host_path.len())
pub(super) fn publish(child: &sched::Task, windows_path: &str, host_path: Option<&str>,
                      command_line: &str) {
    if let Some(host_path) = host_path.filter(|path| !path.is_empty()) {
        child.set_exe_path(Some(String::from(host_path)));
        // SAFETY: the caller owns this unpublished child's prepared address space;
        // no concurrent exec can replace its mm while identity is being installed.
        if let Some(mm) = unsafe { child.mm_ref() } { mm.set_exe_path(String::from(host_path)); }
    }
    // An NT command line is one string, not a vector, so it is published as the
    // single entry it is. Leaving it unset would make every Windows process
    // show an empty /proc/<pid>/cmdline to ordinary Linux tools.
    if !command_line.is_empty() { child.set_cmdline(Some(String::from(command_line))); }
    child.set_comm_exec(crate::nt_process_naming::comm_of(windows_path));
}

