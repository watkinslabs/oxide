// 446 landlock_restrict_self — one syscall, one file (docs/53 §0). Snapshot the
// ruleset into a new layer on top of whatever the thread already enforces.

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;

use syscall::SyscallArgs;
use syscall::errno::Errno;

use ::landlock::abi;
use ::landlock::logging::{self, LogConfig};
use ::landlock::{Domain, DomainDetails};

/// `sys_landlock_restrict_self(ruleset_fd, flags)` — slot 446.
///
/// The resulting domain is a fresh immutable snapshot with one more layer than
/// before. Two consequences the shim depends on: the ruleset fd stays writable
/// but can no longer affect what is enforced, and the new domain is at least as
/// restrictive as the old one because layers are only appended.
/// # C: O(N_rules + N_threads)
pub fn sys_landlock_restrict_self(args: &SyscallArgs) -> i64 {
    let fd    = args.a0 as i32;
    let flags = args.a1 as u32;

    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    let nnp = cur.no_new_privs.load(Ordering::Acquire);
    if let Err(e) = abi::restrict_self_precheck(nnp, cap_sys_admin_in_own_user_ns(&cur), flags) {
        return -(e.as_i32() as i64);
    }
    let plan = abi::restrict_plan(fd, flags, nnp);
    // The denial-reporting reader has to be live before any domain can deny
    // anything; installing it here rather than from a boot hook keeps the
    // landlock crate free of a boot-order slot, and no domain can exist before
    // the first call to this syscall.
    ::landlock::audit::set_exec_layers_source(current_exec_layers);
    let log_state = cur.landlock_log_state.load(Ordering::Acquire);

    // A pure logging-configuration change installs no layer: it only asks that
    // the layers stacked from here on stay silent, which is how a launcher
    // quietens the sandbox it is about to hand to a child.
    if !plan.needs_ruleset {
        cur.landlock_log_state.store(
            logging::state_after_restrict(log_state, flags, None), Ordering::Release);
        if plan.propagate_no_new_privs {
            if let Err(sched::landlock_tsync::StartError::Restart) =
                sched::landlock_tsync::restrict_siblings(cur, None, true)
            {
                return syscall::restart::restart_nointr();
            }
        }
        return 0;
    }

    let rs = match crate::landlock::ruleset_from_fd(fd) {
        Ok(r) => r, Err(e) => return -(e.as_i32() as i64),
    };
    let parent = crate::landlock::current_domain();
    let log = LogConfig::from_flags(flags, logging::state_allows_subdomains(log_state));
    let dom = match Domain::merge_logged(parent.as_ref(), &rs, log, details(&cur)) {
        Ok(d) => d, Err(e) => return -(e.as_i32() as i64),
    };
    cur.landlock_log_state.store(
        logging::state_after_restrict(log_state, flags, Some(dom.num_layers() - 1)),
        Ordering::Release);
    if plan.tsync {
        if let Err(sched::landlock_tsync::StartError::Restart) =
            sched::landlock_tsync::restrict_siblings(
                cur, Some(dom), plan.propagate_no_new_privs)
        {
            return syscall::restart::restart_nointr();
        }
    } else if let Err(e) = crate::landlock::set_current_domain(dom) {
        return -(e.as_i32() as i64);
    }
    0
}

/// Whether the caller holds the administrative capability **in its own user
/// namespace**, which is the alternative to `no_new_privs` for enforcing a
/// policy. Testing the capability without resolving the namespace would let a
/// thread that is only root inside an unprivileged user namespace enforce a
/// policy a later set-user-ID exec still runs under.
/// # C: O(N_userns_depth)
fn cap_sys_admin_in_own_user_ns(cur: &sched::Task) -> bool {
    match cur.namespace_owner(namespace_identity::NamespaceKind::User) {
        Some(own) => nscg::proc_ns::has_cap_for(cur, &own.pin(), sched::cap::SYS_ADMIN),
        None => cur.has_cap(sched::cap::SYS_ADMIN),
    }
}

/// Who is enforcing this layer, for the record that describes the domain once.
/// Captured at enforcement because the layer is immutable afterwards and the
/// thread that built it may be gone by the time a denial names it.
/// # C: O(1)
fn details(cur: &sched::Task) -> DomainDetails {
    DomainDetails {
        pid: cur.visible_pid(),
        uid: cur.creds.euid.load(Ordering::Acquire),
        exe: cur.exe_path().map(|p| p.into_bytes()).unwrap_or_default(),
        comm: cur.comm().into_bytes(),
    }
}

/// Layer levels the CURRENT execution enforced. Read by the denial path to
/// decide which of the two per-execution logging flags applies.
/// # C: O(1)
fn current_exec_layers() -> u32 {
    match sched::live::current() {
        Some(c) => ::landlock::logging::exec_layers(c.landlock_log_state.load(Ordering::Acquire)),
        None => 0,
    }
}
