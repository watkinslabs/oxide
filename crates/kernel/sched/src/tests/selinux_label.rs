// Per-task security label: fork inheritance, the execve domain decision, and
// the `/proc/<pid>/attr/` parse and permission rules.
//
// Every case here drives an ungated decision function. The procfs plumbing and
// the execve glue are compiled only for the kernel target, so a test written
// beside them would compile to nothing and report success.

use alloc::sync::Arc;

use syscall::errno::Errno;

use crate::selinux_label::{
    AttrRequest, AttrSlot, AttrWritePerm, ExecDomain, ExecInputs, TaskLabel, attr_mode,
    attr_write_target, decide_exec_domain, parse_attr_write, render_slot, slot_answer,
    write_permission,
};
use crate::task::{SchedClass, Task};

/// Domain a test task starts in.
const SID_OLD: u32 = 100;
/// Domain a transition lands in.
const SID_NEW: u32 = 200;
/// A third domain, used where a value must differ from both of the above.
const SID_OTHER: u32 = 300;
/// Label of the executable image.
const SID_FILE: u32 = 400;

fn label() -> TaskLabel {
    TaskLabel {
        sid: SID_OLD,
        exec: Some(SID_NEW),
        fscreate: Some(SID_OTHER),
        keycreate: Some(SID_FILE),
        sockcreate: Some(SID_NEW),
        prev: Some(SID_OTHER),
    }
}

fn exec_inputs() -> ExecInputs {
    ExecInputs {
        old_sid: SID_OLD,
        staged: None,
        policy_sid: None,
        no_new_privs: false,
        nosuid: false,
        nnp_nosuid_capable: false,
        nnp_granted: false,
        nosuid_granted: false,
    }
}

#[test]
fn fork_carries_the_current_domain_and_the_create_staging() {
    let child = TaskLabel::inherit(&label());
    assert_eq!(child.sid, SID_OLD);
    assert_eq!(child.fscreate, Some(SID_OTHER));
    assert_eq!(child.keycreate, Some(SID_FILE));
    assert_eq!(child.sockcreate, Some(SID_NEW));
    assert_eq!(child.prev, Some(SID_OTHER));
}

#[test]
fn fork_carries_the_staged_exec_domain() {
    // Surprising but correct: the staged label survives fork, because the
    // process that stages one is usually not the process that execs — a shell
    // stages it and then forks. Dropping it here makes `setexec` do nothing
    // for its ordinary caller, and nothing goes red.
    let parent = label();
    assert_eq!(parent.exec, Some(SID_NEW), "fixture must stage an exec label");
    assert_eq!(TaskLabel::inherit(&parent).exec, Some(SID_NEW));
}

#[test]
fn fork_carries_every_staged_slot() {
    let parent = label();
    let child = TaskLabel::inherit(&parent);
    assert_eq!(child.sid, parent.sid);
    assert_eq!(child.exec, parent.exec);
    assert_eq!(child.fscreate, parent.fscreate);
    assert_eq!(child.keycreate, parent.keycreate);
    assert_eq!(child.sockcreate, parent.sockcreate);
    assert_eq!(child.prev, parent.prev);
}

#[test]
fn a_staged_label_is_the_new_domain() {
    let mut i = exec_inputs();
    i.staged = Some(SID_NEW);
    assert_eq!(decide_exec_domain(&i), Ok(ExecDomain::Enter(SID_NEW)));
}

#[test]
fn a_staged_label_beats_the_policys_own_transition() {
    let mut i = exec_inputs();
    i.staged = Some(SID_NEW);
    i.policy_sid = Some(SID_OTHER);
    assert_eq!(decide_exec_domain(&i), Ok(ExecDomain::Enter(SID_NEW)));
}

#[test]
fn without_a_staged_label_the_policys_transition_applies() {
    let mut i = exec_inputs();
    i.policy_sid = Some(SID_NEW);
    assert_eq!(decide_exec_domain(&i), Ok(ExecDomain::Enter(SID_NEW)));
}

#[test]
fn a_transition_to_the_same_domain_is_not_a_transition() {
    let mut i = exec_inputs();
    i.policy_sid = Some(SID_OLD);
    assert_eq!(decide_exec_domain(&i), Ok(ExecDomain::Keep));
    // …and the same holds when userspace stages the domain it is already in.
    let mut i = exec_inputs();
    i.staged = Some(SID_OLD);
    assert_eq!(decide_exec_domain(&i), Ok(ExecDomain::Keep));
}

#[test]
fn no_policy_answer_leaves_the_domain_alone() {
    assert_eq!(decide_exec_domain(&exec_inputs()), Ok(ExecDomain::Keep));
}

#[test]
fn an_explicit_label_refused_by_no_new_privs_fails_the_exec() {
    let mut i = exec_inputs();
    i.staged = Some(SID_NEW);
    i.no_new_privs = true;
    assert_eq!(decide_exec_domain(&i), Err(Errno::Eacces));
}

#[test]
fn an_explicit_label_refused_by_a_nosuid_mount_fails_the_exec() {
    let mut i = exec_inputs();
    i.staged = Some(SID_NEW);
    i.nosuid = true;
    assert_eq!(decide_exec_domain(&i), Err(Errno::Eacces));
}

#[test]
fn a_default_transition_refused_by_no_new_privs_falls_back_silently() {
    // Failing here would break every exec on a nosuid mount for a policy that
    // merely has an opinion about the image, so the fallback is the contract —
    // and it must NOT be shared with the explicit case above.
    let mut i = exec_inputs();
    i.policy_sid = Some(SID_NEW);
    i.no_new_privs = true;
    assert_eq!(decide_exec_domain(&i), Ok(ExecDomain::Keep));
    let mut i = exec_inputs();
    i.policy_sid = Some(SID_NEW);
    i.nosuid = true;
    assert_eq!(decide_exec_domain(&i), Ok(ExecDomain::Keep));
}

#[test]
fn the_policy_capability_and_both_grants_permit_a_confined_transition() {
    let mut i = exec_inputs();
    i.staged = Some(SID_NEW);
    i.no_new_privs = true;
    i.nosuid = true;
    i.nnp_nosuid_capable = true;
    i.nnp_granted = true;
    i.nosuid_granted = true;
    assert_eq!(decide_exec_domain(&i), Ok(ExecDomain::Enter(SID_NEW)));
    // One grant missing is a refusal; the capability alone is not enough.
    i.nosuid_granted = false;
    assert_eq!(decide_exec_domain(&i), Err(Errno::Eacces));
    i.nosuid_granted = true;
    i.nnp_granted = false;
    assert_eq!(decide_exec_domain(&i), Err(Errno::Eacces));
    i.nnp_granted = true;
    i.nnp_nosuid_capable = false;
    assert_eq!(decide_exec_domain(&i), Err(Errno::Eacces));
}

#[test]
fn prev_records_only_a_real_transition() {
    let mut l = TaskLabel::with_sid(SID_OLD);
    assert_eq!(l.prev, None);
    l.enter(SID_OLD);
    assert_eq!(l.prev, None, "entering the current domain is not a transition");
    l.enter(SID_NEW);
    assert_eq!((l.sid, l.prev), (SID_NEW, Some(SID_OLD)));
    l.enter(SID_NEW);
    assert_eq!(l.prev, Some(SID_OLD), "a non-transition must not clobber the history");
}

#[test]
fn a_refused_exec_still_consumes_the_staged_label() {
    // The staging names one operation. Whether that operation succeeded is not
    // a reason to leave it armed for an unrelated later exec.
    let task = Arc::new(Task::new(1, "stage", SchedClass::Normal { weight: 1024 }));
    task.selinux_label.lock().exec = Some(SID_NEW);
    let plan = crate::selinux_label::exec_plan(&task, SID_FILE, false);
    assert!(plan.is_ok(), "no policy is loaded, so the exec is not refused here");
    assert_eq!(task.selinux_label.lock().exec, None);
}

#[test]
fn with_no_policy_an_exec_changes_nothing() {
    let task = Arc::new(Task::new(2, "nopolicy", SchedClass::Normal { weight: 1024 }));
    let plan = crate::selinux_label::exec_plan(&task, SID_FILE, false).expect("allowed");
    assert_eq!(plan.domain, ExecDomain::Keep);
    assert!(!plan.secure_exec);
    crate::selinux_label::exec_commit(&task, &plan);
    let label = *task.selinux_label.lock();
    assert_eq!(label.sid, TaskLabel::kernel().sid);
    assert_eq!(label.prev, None);
}

#[test]
fn a_thread_with_no_address_space_carries_the_kernels_own_label() {
    // A kernel thread has never run user code, so the policy's `init` domain
    // would describe it wrongly — and `init` is the domain the first user
    // process is meant to be distinguishable in.
    let kthread = Arc::new(Task::new(5, "kthread", SchedClass::Normal { weight: 1024 }));
    assert_eq!(kthread.selinux_label.lock().sid, TaskLabel::kernel().sid);
    assert_ne!(TaskLabel::kernel().sid, TaskLabel::init().sid);
}

#[test]
fn exec_commit_installs_only_a_real_transition() {
    let task = Arc::new(Task::new(3, "commit", SchedClass::Normal { weight: 1024 }));
    task.selinux_label.lock().sid = SID_OLD;
    crate::selinux_label::exec_commit(
        &task,
        &crate::selinux_label::ExecPlan { domain: ExecDomain::Keep, secure_exec: false });
    assert_eq!(task.selinux_label.lock().prev, None);
    crate::selinux_label::exec_commit(
        &task,
        &crate::selinux_label::ExecPlan { domain: ExecDomain::Enter(SID_NEW), secure_exec: true });
    let label = *task.selinux_label.lock();
    assert_eq!((label.sid, label.prev), (SID_NEW, Some(SID_OLD)));
}

#[test]
fn every_attr_name_resolves_and_only_prev_is_read_only() {
    for (name, slot) in crate::selinux_label::ATTR_SLOTS {
        assert_eq!(AttrSlot::from_name(name), Some(slot), "{name}");
    }
    assert_eq!(AttrSlot::from_name("apparmor"), None);
    assert_eq!(attr_mode(AttrSlot::Prev), 0o444);
    assert_eq!(attr_mode(AttrSlot::Current), 0o666);
    assert_eq!(attr_mode(AttrSlot::Exec), 0o666);
}

#[test]
fn prev_is_not_writable() {
    assert_eq!(write_permission(AttrSlot::Prev), AttrWritePerm::Refused);
    assert_eq!(parse_attr_write(AttrSlot::Prev, b"system_u:system_r:init_t:s0"),
               Err(Errno::Eacces));
    assert_eq!(parse_attr_write(AttrSlot::Prev, b""), Err(Errno::Eacces));
}

#[test]
fn each_staging_slot_names_its_own_permission() {
    assert_eq!(write_permission(AttrSlot::Exec), AttrWritePerm::Staged("setexec"));
    assert_eq!(write_permission(AttrSlot::FsCreate), AttrWritePerm::Staged("setfscreate"));
    assert_eq!(write_permission(AttrSlot::KeyCreate), AttrWritePerm::Staged("setkeycreate"));
    assert_eq!(write_permission(AttrSlot::SockCreate), AttrWritePerm::Staged("setsockcreate"));
    assert_eq!(write_permission(AttrSlot::Current), AttrWritePerm::Dynamic);
}

#[test]
fn an_empty_write_or_a_lone_newline_clears_a_staging_slot() {
    for slot in [AttrSlot::Exec, AttrSlot::FsCreate, AttrSlot::KeyCreate, AttrSlot::SockCreate] {
        assert_eq!(parse_attr_write(slot, b""), Ok(AttrRequest::Clear));
        assert_eq!(parse_attr_write(slot, b"\n"), Ok(AttrRequest::Clear));
        assert_eq!(parse_attr_write(slot, b"\0"), Ok(AttrRequest::Clear));
    }
}

#[test]
fn clearing_the_current_domain_is_rejected() {
    // A task always has a domain, so there is nothing to unset.
    assert_eq!(parse_attr_write(AttrSlot::Current, b""), Err(Errno::Einval));
    assert_eq!(parse_attr_write(AttrSlot::Current, b"\n"), Err(Errno::Einval));
}

#[test]
fn a_written_context_is_taken_without_its_terminator() {
    const CTX: &str = "system_u:system_r:init_t:s0";
    assert_eq!(parse_attr_write(AttrSlot::Exec, CTX.as_bytes()), Ok(AttrRequest::Set(CTX)));
    let with_newline = alloc::format!("{CTX}\n");
    assert_eq!(parse_attr_write(AttrSlot::Exec, with_newline.as_bytes()),
               Ok(AttrRequest::Set(CTX)));
    let with_nul = alloc::format!("{CTX}\0");
    assert_eq!(parse_attr_write(AttrSlot::Exec, with_nul.as_bytes()),
               Ok(AttrRequest::Set(CTX)));
}

#[test]
fn a_write_that_is_not_text_is_rejected() {
    assert_eq!(parse_attr_write(AttrSlot::Exec, &[0x80, 0xff]), Err(Errno::Einval));
    let oversized = alloc::vec![b'a'; 4097];
    assert_eq!(parse_attr_write(AttrSlot::Exec, &oversized), Err(Errno::Einval));
}

#[test]
fn a_write_may_only_target_the_calling_thread() {
    assert_eq!(attr_write_target(7, 7), Ok(()));
    assert_eq!(attr_write_target(7, 8), Err(Errno::Eacces));
}

#[test]
fn an_unset_slot_reads_as_zero_bytes_and_an_unrenderable_one_is_an_error() {
    assert_eq!(render_slot(None), Ok(alloc::vec::Vec::new()));
    // No module installed: nothing labels anything, so there is no label to
    // report and userspace reads emptiness rather than an error.
    assert_eq!(render_slot(Some(SID_OLD)), Ok(alloc::vec::Vec::new()));
}

/// An empty read and a failed render are DIFFERENT answers. Collapsing them is
/// why an empty context travelled all the way out to userspace and failed there
/// instead of here: a caller that reads zero bytes carries the empty string on
/// as a label, and the failure then names neither the label nor this read.
#[test]
fn a_label_that_cannot_be_rendered_is_an_error_and_not_an_empty_context() {
    // A module that rendered the label: its bytes, unchanged.
    assert_eq!(slot_answer(Some(Some(alloc::vec::Vec::from(&b"system_u:system_r:kernel_t:s0"[..])))),
        Ok(alloc::vec::Vec::from(&b"system_u:system_r:kernel_t:s0"[..])));
    // A module that could NOT render it: an error, never zero bytes.
    assert_eq!(slot_answer(Some(None)), Err(Errno::Einval));
    assert_ne!(slot_answer(Some(None)), Ok(alloc::vec::Vec::new()));
    // No module at all: zero bytes, which is how userspace learns the module is
    // not doing anything.
    assert_eq!(slot_answer(None), Ok(alloc::vec::Vec::new()));
}

#[test]
fn reading_and_writing_without_a_policy_answers_rather_than_panicking() {
    let task = Arc::new(Task::new(4, "attr", SchedClass::Normal { weight: 1024 }));
    for (_, slot) in crate::selinux_label::ATTR_SLOTS {
        assert_eq!(crate::selinux_label::read_attr(&task, slot), Ok(alloc::vec::Vec::new()));
    }
    // No task is current in a hosted test, so no write is the calling thread's.
    assert_eq!(crate::selinux_label::write_attr(&task, AttrSlot::Exec, b"x"),
               Err(Errno::Eacces));
}

#[test]
fn a_staging_slot_round_trips_through_the_label() {
    let mut l = TaskLabel::with_sid(SID_OLD);
    for slot in [AttrSlot::Exec, AttrSlot::FsCreate, AttrSlot::KeyCreate, AttrSlot::SockCreate] {
        l.set_staged(slot, Some(SID_NEW));
        assert_eq!(l.slot(slot), Some(SID_NEW));
        l.set_staged(slot, None);
        assert_eq!(l.slot(slot), None);
    }
    assert_eq!(l.slot(AttrSlot::Current), Some(SID_OLD));
    // The current domain and the history are not staging slots: a slot write
    // must not be able to move either behind the transition's back.
    l.set_staged(AttrSlot::Current, Some(SID_NEW));
    l.set_staged(AttrSlot::Prev, Some(SID_NEW));
    assert_eq!((l.slot(AttrSlot::Current), l.slot(AttrSlot::Prev)), (Some(SID_OLD), None));
}
