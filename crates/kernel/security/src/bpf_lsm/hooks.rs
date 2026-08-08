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

/// One hook stub's published shape.
pub struct Spec {
    /// Name of the stub function the attach target must resolve to.
    pub stub: &'static str,
    /// Type names of the hook's arguments, in order. The count is what
    /// bounds context addressing; the names are what the kernel's own type
    /// information declares each argument as.
    pub args: &'static [&'static str],
    pub ret: Ret,
}

/// Published hooks, in the order the kernel's type information declares
/// them.
pub const HOOKS: &[(Hook, Spec)] = &[
    (Hook::FileOpen, Spec { stub: "bpf_lsm_file_open", args: &["file"], ret: Ret::Errno }),
];

/// Row index of each hook in `HOOKS`. The match is exhaustive, so a new
/// variant cannot be added without giving it a published row.
const FILE_OPEN_ROW: usize = 0;

/// Published shape of one hook. # C: O(1)
pub fn spec(hook: Hook) -> &'static Spec {
    match hook {
        Hook::FileOpen => &HOOKS[FILE_OPEN_ROW].1,
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
        for (at, (hook, _)) in HOOKS.iter().enumerate() {
            assert_eq!(spec(*hook).stub, HOOKS[at].1.stub);
        }
    }

    #[test] fn stub_name_resolves_to_its_hook() {
        assert_eq!(hook_by_stub_name(b"bpf_lsm_file_open"), Some(Hook::FileOpen));
    }

    #[test] fn unpublished_stub_names_resolve_to_nothing() {
        // Real reference hook stubs this kernel does not implement, and a
        // near-miss of a published one. None may resolve.
        for name in [&b"bpf_lsm_file_alloc_security"[..], b"bpf_lsm_bprm_check_security",
            b"bpf_lsm_task_alloc", b"bpf_lsm_file_ope", b"bpf_lsm_file_open2", b""] {
            assert_eq!(hook_by_stub_name(name), None);
        }
    }

    #[test] fn file_open_publishes_one_argument_and_an_errno_return() {
        let spec = spec(Hook::FileOpen);
        assert_eq!(spec.args.len(), 1);
        assert_eq!(spec.ret, Ret::Errno);
        assert_eq!(context_bytes(Hook::FileOpen), 16);
    }
}
