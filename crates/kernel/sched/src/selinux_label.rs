// Per-task security label: the subject half of the mandatory-access-control
// module (`62§9`).
//
// The label is a handle into the policy's SID table, not a reference to a
// policy object. A policy reload replaces the tables under a running task, so
// the task keeps the number and resolves it at each use; keeping a resolved
// context here would be a second copy of what the security server owns and
// could disagree with it.
//
// Module manifest:
//   label — the per-task label struct, its construction and its fork rule
//   exec  — the execve domain-transition decision and its live glue
//   attr  — the `/proc/<pid>/attr/` slot, parse, render and permission rules
//   policy — the class and permission names this subsystem asks about

mod label;
mod exec;
mod attr;
mod policy;

pub use label::TaskLabel;
pub use exec::{ExecDomain, ExecInputs, ExecPlan, decide_exec_domain, image_sid};
pub use attr::{
    ATTR_SLOTS, AttrRequest, AttrSlot, AttrWritePerm, attr_mode, attr_write_target,
    parse_attr_write, render_slot, write_permission,
};
// Naming the CALLING task needs a scheduler, so the live half rides the same
// gate `live` does.
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub use exec::{exec_commit, exec_plan};
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub use attr::{read_attr, write_attr};
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub use label::{current_fscreate_sid, current_sid, current_sockcreate_sid};
