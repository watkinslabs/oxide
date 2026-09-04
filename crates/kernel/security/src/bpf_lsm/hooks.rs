//! The LSM hook stubs this kernel publishes as BPF attach targets.
//!
//! One row per hook that a call site in this kernel actually reaches. A
//! hook with no call site is not listed, so it is neither declared in the
//! kernel's own type information nor resolvable as an attach target — a
//! program can never be admitted against a hook that would never run.

/// Every hook a BPF LSM program can attach to here.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Hook {
    FileOpen,
    TaskSetNice,
    TaskSetScheduler,
}

/// Return contract of one hook, which fixes the range a program attached
/// to it may exit with.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Ret {
    /// `0` on success, a negative errno on refusal.
    Errno,
    /// `0` or `1`.
    Bool,
    /// No return value; the exit register carries no meaning.
    Void,
}

/// Kernel type carried by one hook argument.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ArgType {
    Int,
    Task,
    Opaque(&'static str),
}

/// One named function-prototype parameter. Names and types are distinct:
/// BTF consumers expect Linux's `p`/`nice` parameter names while the first
/// parameter's type is `struct task_struct *`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Arg {
    pub name: &'static str,
    pub ty: ArgType,
}

/// One hook stub's published shape.
pub struct Spec {
    /// Name of the stub function the attach target must resolve to.
    pub stub: &'static str,
    /// Named, typed hook arguments in prototype order.
    pub args: &'static [Arg],
    pub ret: Ret,
}

/// Published hooks, in the order the kernel's type information declares
/// them.
pub const HOOKS: &[(Hook, Spec)] = &[
    (Hook::FileOpen, Spec { stub: "bpf_lsm_file_open", args: &[
        Arg { name: "file", ty: ArgType::Opaque("file") },
    ], ret: Ret::Errno }),
    (Hook::TaskSetNice, Spec {
        stub: "bpf_lsm_task_setnice", args: &[
            Arg { name: "p", ty: ArgType::Task },
            Arg { name: "nice", ty: ArgType::Int },
        ], ret: Ret::Errno,
    }),
    (Hook::TaskSetScheduler, Spec {
        stub: "bpf_lsm_task_setscheduler", args: &[
            Arg { name: "p", ty: ArgType::Task },
        ], ret: Ret::Errno,
    }),
];

/// Row index of each hook in `HOOKS`. The match is exhaustive, so a new
/// variant cannot be added without giving it a published row.
const FILE_OPEN_ROW: usize = 0;
const TASK_SETNICE_ROW: usize = 1;
const TASK_SETSCHEDULER_ROW: usize = 2;

/// Published shape of one hook. # C: O(1)
pub fn spec(hook: Hook) -> &'static Spec {
    match hook {
        Hook::FileOpen => &HOOKS[FILE_OPEN_ROW].1,
        Hook::TaskSetNice => &HOOKS[TASK_SETNICE_ROW].1,
        Hook::TaskSetScheduler => &HOOKS[TASK_SETSCHEDULER_ROW].1,
    }
}

/// Resolve a stub function name to the hook it stands for. # C: O(hook count)
pub fn hook_by_stub_name(name: &[u8]) -> Option<Hook> {
    HOOKS.iter().find(|(_, spec)| spec.stub.as_bytes() == name).map(|(hook, _)| *hook)
}

/// Bytes of hook context the runner publishes: one slot per argument plus
/// the pending-return slot that follows them. # C: O(hook count)
pub fn context_bytes(hook: Hook) -> usize {
    (spec(hook).args.len() + 1) * SLOT_BYTES
}

/// Width of one hook-context slot. Arguments and the return slot are
/// register-wide regardless of their declared type.
pub const SLOT_BYTES: usize = 8;

/// Stable fields of the concrete `task_struct` view published to BPF. The
/// Rust scheduler task is deliberately not exposed as an ABI layout.
pub mod task_struct {
    pub const PID: usize = 0;
    pub const TGID: usize = 4;
    pub const SIZE: usize = 8;
    pub const WORD: usize = 4;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Prefix the reference gives every attachable LSM stub.
    const STUB_PREFIX: &str = "bpf_lsm_";

    #[test] fn every_stub_carries_the_prefix() {
        for (_, spec) in HOOKS { assert!(spec.stub.starts_with(STUB_PREFIX), "{}", spec.stub); }
    }

    #[test] fn stub_names_are_unique() {
        for (at, (_, spec)) in HOOKS.iter().enumerate() {
            assert!(HOOKS[..at].iter().all(|(_, other)| other.stub != spec.stub));
        }
    }

    #[test] fn each_row_index_names_its_own_hook() {
        assert_eq!(HOOKS[FILE_OPEN_ROW].0, Hook::FileOpen);
        assert_eq!(HOOKS[TASK_SETNICE_ROW].0, Hook::TaskSetNice);
        assert_eq!(HOOKS[TASK_SETSCHEDULER_ROW].0, Hook::TaskSetScheduler);
        for (at, (hook, _)) in HOOKS.iter().enumerate() {
            assert_eq!(spec(*hook).stub, HOOKS[at].1.stub);
        }
    }

    #[test] fn stub_name_resolves_to_its_hook() {
        assert_eq!(hook_by_stub_name(b"bpf_lsm_file_open"), Some(Hook::FileOpen));
        assert_eq!(hook_by_stub_name(b"bpf_lsm_task_setnice"), Some(Hook::TaskSetNice));
        assert_eq!(hook_by_stub_name(b"bpf_lsm_task_setscheduler"), Some(Hook::TaskSetScheduler));
    }

    #[test] fn unpublished_stub_names_resolve_to_nothing() {
        // Real reference hook stubs this kernel does not implement, and a
        // near-miss of a published one. None may resolve.
        for name in [&b"bpf_lsm_file_alloc_security"[..], b"bpf_lsm_bprm_check_security",
            b"bpf_lsm_task_alloc", b"bpf_lsm_task_setioprio", b"bpf_lsm_file_ope",
            b"bpf_lsm_file_open2", b""] {
            assert_eq!(hook_by_stub_name(name), None);
        }
    }

    #[test] fn file_open_publishes_one_argument_and_an_errno_return() {
        let spec = spec(Hook::FileOpen);
        assert_eq!(spec.args.len(), 1);
        assert_eq!(spec.ret, Ret::Errno);
        assert_eq!(context_bytes(Hook::FileOpen), 16);
    }

    #[test] fn task_hooks_publish_their_kernel_argument_shapes() {
        let nice = spec(Hook::TaskSetNice);
        assert_eq!(nice.args, &[
            Arg { name: "p", ty: ArgType::Task },
            Arg { name: "nice", ty: ArgType::Int },
        ]);
        assert_eq!(nice.ret, Ret::Errno);
        assert_eq!(context_bytes(Hook::TaskSetNice), 24);
        let scheduler = spec(Hook::TaskSetScheduler);
        assert_eq!(scheduler.args, &[Arg { name: "p", ty: ArgType::Task }]);
        assert_eq!(scheduler.ret, Ret::Errno);
        assert_eq!(context_bytes(Hook::TaskSetScheduler), 16);
    }
}
