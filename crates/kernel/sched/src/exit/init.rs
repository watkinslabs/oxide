// Init death (Linux `kernel/exit.c` `do_exit`, `kernel/pid_namespace.c`
// `zap_pid_ns_processes`).
//
//   if (unlikely(is_global_init(tsk)))
//           panic("Attempted to kill init! exitcode=0x%08x\n", ...);
//
// Only the LAST thread of init triggers it (`group_dead`): a `pthread_exit`
// from one of init's threads is ordinary. A pid-namespace init that dies takes
// the whole namespace with it — every remaining member gets SIGKILL and the
// namespace stops accepting new members — but the machine keeps running.

/// Consequence of a thread group's final exit.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum InitExit {
    /// Ordinary process death.
    None,
    /// Global PID 1 died: unrecoverable.
    PanicMachine,
    /// A pid-namespace init died: SIGKILL every remaining member.
    ZapNamespace,
}

/// Linux's init-death triage for the final thread of a group.
/// `is_global_init` is true only for the init of the INITIAL pid namespace.
/// # C: O(1)
pub const fn init_exit(group_dead: bool, is_global_init: bool, is_ns_init: bool) -> InitExit {
    if !group_dead { return InitExit::None; }
    if is_global_init { return InitExit::PanicMachine; }
    if is_ns_init { return InitExit::ZapNamespace; }
    InitExit::None
}
