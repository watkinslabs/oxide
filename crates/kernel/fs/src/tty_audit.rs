// Wiring between the read path and the terminal-input auditor.
//
// The audit subsystem reads no task and the filesystem layer knows no audit
// state, so the identity a record is attributed to is gathered exactly here,
// in the one layer that can see both.

use audit::tty::Devno;
use audit::TtyActor;

/// Install the read-path hook and the arm notifier. Boot, once.
/// # C: O(1)
pub fn install() {
    vfs::set_tty_audit_hook(on_tty_read);
    audit::tty::set_arm_notifier(vfs::arm_tty_audit);
    // A mask can only be set through the audit socket, which cannot have been
    // spoken to before this point; arming from the current state anyway keeps
    // the flag a function of the state rather than of boot order.
    vfs::arm_tty_audit(audit::tty::armed());
}

/// Bytes a task just read from a terminal.
/// # C: O(len)
fn on_tty_read(f: vfs::TtyAuditFacts, data: &[u8]) {
    let Some(cur) = sched::current() else { return };
    let comm = cur.comm_bytes();
    let a = actor(cur, trim(&comm));
    let dev = Devno { major: f.major, minor: f.minor };
    audit::tty::add_data(tgid(cur), a, dev, f.icanon, f.echo, f.pty_master, data);
    // A completed canonical line is a record boundary the line discipline
    // already decided: flushing on it is what makes an audit log read as the
    // lines a person typed instead of arbitrary buffer-sized fragments.
    if f.icanon && data.last() == Some(&b'\n') { let _ = audit::tty::push(tgid(cur), a); }
}

/// The last thread of a group is exiting: write out its final partial line.
/// Without this the tail of every audited session is silently discarded.
/// # C: O(len)
pub fn on_group_exit(task: &sched::Task) {
    // The buffer belongs to the thread GROUP, so one thread of a live process
    // exiting must not take the group's transcript with it.
    if !task.thread_group.is_single_member() { return; }
    if !audit::tty::armed() { return; }
    let comm = task.comm_bytes();
    audit::tty::exit(tgid(task), actor(task, trim(&comm)));
}

/// A new thread group inherits its parent's mask.
/// # C: O(log N_groups)
pub fn on_fork(parent: &sched::Task, child_tgid: u32) {
    if !audit::tty::armed() { return; }
    audit::tty::fork(tgid(parent), child_tgid);
}

/// The command name without its NUL padding. # C: O(TASK_COMM_LEN)
fn trim(b: &[u8]) -> &[u8] { &b[..b.iter().position(|c| *c == 0).unwrap_or(b.len())] }

/// # C: O(1)
fn tgid(t: &sched::Task) -> u32 { t.visible_pid() }

/// # C: O(1)
fn actor<'a>(t: &sched::Task, comm: &'a [u8]) -> TtyActor<'a> {
    let (auid, ses) = t.audit_identity();
    TtyActor {
        pid: t.visible_pid(),
        uid: t.creds.euid.load(core::sync::atomic::Ordering::Acquire),
        auid,
        ses,
        comm,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sched::{SchedClass, Task};

    #[test]
    fn tty_attribution_reads_the_tasks_canonical_login_identity() {
        let task = Task::new(8201, "bash", SchedClass::Normal { weight: 1024 });
        let unset = actor(&task, b"bash");
        assert_eq!((unset.auid, unset.ses), (u32::MAX, u32::MAX));
        task.set_audit_identity(1000, 23);
        let set = actor(&task, b"bash");
        assert_eq!((set.auid, set.ses), (1000, 23));
    }
}
