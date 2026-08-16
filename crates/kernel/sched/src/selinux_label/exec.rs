// The `execve` domain transition.
//
// The decision is a function over values (`decide_exec_domain`) so it is
// hosted-testable; the glue below only gathers the live inputs, runs the
// permission checks the outcome implies, and stores the result.

use selinux::sidtab::Sid;
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
use selinux::uapi::policycap::POLICYDB_CAP_NNP_NOSUID_TRANSITION;
use syscall::errno::Errno;

#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
use super::policy::{
    self, CLASS_FILE, CLASS_PROCESS, CLASS_PROCESS2, PERM_ENTRYPOINT, PERM_EXECUTE_NO_TRANS,
    PERM_NNP_TRANSITION, PERM_NOATSECURE, PERM_NOSUID_TRANSITION, PERM_TRANSITION,
};

/// Everything the domain decision reads.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ExecInputs {
    /// Domain the task is in now.
    pub old_sid: Sid,
    /// Domain userspace staged through `/proc/self/attr/exec`, if any.
    pub staged: Option<Sid>,
    /// Domain the policy's own transition rule computes, if a policy answered.
    pub policy_sid: Option<Sid>,
    /// Whether the task set no-new-privileges.
    pub no_new_privs: bool,
    /// Whether the image's mount forbids privilege elevation.
    pub nosuid: bool,
    /// Whether the policy opted in to transitions under the two conditions above.
    pub nnp_nosuid_capable: bool,
    /// Whether `process2:nnp_transition` is granted old → new.
    pub nnp_granted: bool,
    /// Whether `process2:nosuid_transition` is granted old → new.
    pub nosuid_granted: bool,
}

/// What the `execve` does to the task's domain.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ExecDomain {
    /// Stay where the task already is.
    Keep,
    /// Enter this domain.
    Enter(Sid),
}

/// Decide the domain an `execve` lands in. # C: O(1)
///
/// A staged label beats the policy's own transition, because userspace asked
/// for it explicitly. A candidate equal to the current domain is NOT a
/// transition: the permission that governs it is the one for running an image
/// in place, and demanding `process:transition` from a domain to itself would
/// refuse every ordinary exec.
///
/// The no-new-privileges and `nosuid` refusal is asymmetric on purpose. An
/// explicit request that cannot be honoured is an error, because silently
/// running the program somewhere else is not what was asked for. The policy's
/// own default falling back to the current domain is not, because failing it
/// would break every exec on a `nosuid` mount for a policy that merely has an
/// opinion about the image.
pub fn decide_exec_domain(i: &ExecInputs) -> Result<ExecDomain, Errno> {
    let explicit = i.staged.is_some();
    let candidate = i.staged.or(i.policy_sid).unwrap_or(i.old_sid);
    if candidate == i.old_sid { return Ok(ExecDomain::Keep); }
    if (i.no_new_privs || i.nosuid) && !nnp_nosuid_permits(i) {
        if explicit { return Err(Errno::Eacces); }
        return Ok(ExecDomain::Keep);
    }
    Ok(ExecDomain::Enter(candidate))
}

/// Whether a transition survives no-new-privileges or a `nosuid` mount. # C: O(1)
///
/// A policy that has not opted in refuses outright: the opt-in is how a policy
/// states that its domains are safe to enter under those conditions, and
/// assuming it would let a `nosuid` mount confer a domain change.
fn nnp_nosuid_permits(i: &ExecInputs) -> bool {
    if !i.nnp_nosuid_capable { return false; }
    if i.no_new_privs && !i.nnp_granted { return false; }
    if i.nosuid && !i.nosuid_granted { return false; }
    true
}

/// The outcome of the decision, held between the point it can still fail and
/// the point of no return where it is installed.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ExecPlan {
    /// Domain the new image runs in.
    pub domain: ExecDomain,
    /// Whether the image must be treated as a privilege boundary.
    pub secure_exec: bool,
}

impl ExecPlan {
    /// A plan that changes nothing, for a boot with no security module. # C: O(1)
    pub const fn inert() -> Self { Self { domain: ExecDomain::Keep, secure_exec: false } }
}

/// Decide this `execve`'s domain against the live policy and task state.
///
/// The staged `exec` label is consumed here, before the decision can fail, so
/// a refused exec does not leave it armed for the next one — it named a single
/// operation, and that operation has now happened.
/// # C: O(rules)
/// # Lk: takes the task's label lock, releases it before any check
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub fn exec_plan(task: &crate::Task, file_sid: Sid, nosuid: bool) -> Result<ExecPlan, Errno> {
    let (old, staged) = {
        let mut label = task.selinux_label.lock();
        let staged = label.exec.take();
        (label.sid, staged)
    };
    if !selinux_runtime::active() { return Ok(ExecPlan::inert()); }

    let class_process = selinux::uapi::classmap::class_by_name(CLASS_PROCESS);
    let policy_sid = match (staged, class_process) {
        (None, Some(c)) => selinux_runtime::with(|s| s.transition_sid(old, file_sid, c, None))
            .and_then(|r| r.ok()),
        _ => None,
    };
    let candidate = staged.or(policy_sid).unwrap_or(old);
    let no_new_privs = task.no_new_privs.load(core::sync::atomic::Ordering::Acquire);
    let inputs = ExecInputs {
        old_sid: old,
        staged,
        policy_sid,
        no_new_privs,
        nosuid,
        nnp_nosuid_capable: policy::policycap(POLICYDB_CAP_NNP_NOSUID_TRANSITION),
        nnp_granted: policy::granted(old, candidate, CLASS_PROCESS2, PERM_NNP_TRANSITION),
        nosuid_granted: policy::granted(old, candidate, CLASS_PROCESS2, PERM_NOSUID_TRANSITION),
    };
    let domain = decide_exec_domain(&inputs)?;
    let secure_exec = match domain {
        ExecDomain::Keep => {
            policy::check(old, file_sid, CLASS_FILE, PERM_EXECUTE_NO_TRANS)?;
            false
        }
        ExecDomain::Enter(new) => {
            policy::check(old, new, CLASS_PROCESS, PERM_TRANSITION)?;
            policy::check(new, file_sid, CLASS_FILE, PERM_ENTRYPOINT)?;
            // A domain change is a privilege boundary unless the policy says
            // this particular one is not: the new domain must not inherit the
            // caller's environment-derived state by default.
            !policy::granted(old, new, CLASS_PROCESS, PERM_NOATSECURE)
        }
    };
    Ok(ExecPlan { domain, secure_exec })
}

/// Install a decided domain. Runs past the point of no return. # C: O(1)
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub fn exec_commit(task: &crate::Task, plan: &ExecPlan) {
    let ExecDomain::Enter(new) = plan.domain else { return };
    task.selinux_label.lock().enter(new);
}

/// Label an executable image carries, or the unlabelled SID. # C: O(1)
pub fn image_sid(written: Option<&str>) -> Sid {
    match written {
        Some(text) => selinux_runtime::label::sid_from_context_or_unlabeled(text),
        None => selinux_runtime::label::unlabeled_sid(),
    }
}
