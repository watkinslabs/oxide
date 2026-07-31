// clone(2) 56 / fork(2) 57 / vfork(2) 58 / clone3(2) 435 — the DECISION half.
//
// The slot files are `#![cfg(target_os = "oxide-kernel")]`, so nothing in them
// can be unit-tested (CLAUDE.md phantom-test rule). Every rule whose only
// observable form is an errno or an errno ORDER lives here instead: the
// `CLONE_*` bit names, the `struct clone_args` versioned layout, the
// `clone3` size/tail/field ladder, and the flag-combination matrix both
// entry points share.
//
// Module manifest:
// - `tests` — the hosted contract for every rule below.

use syscall::errno::Errno;

/// clone(2) low byte: the signal the child sends its parent on exit.
/// `clone3` moves it to `clone_args::exit_signal` and REUSES `CLONE_NEWTIME`
/// inside this window, so the two must never be folded into one word without
/// knowing which entry point produced them.
pub const CSIGNAL: u64 = 0xff;

pub const CLONE_VM:             u64 = 0x0000_0100;
pub const CLONE_FS:             u64 = 0x0000_0200;
pub const CLONE_FILES:          u64 = 0x0000_0400;
pub const CLONE_SIGHAND:        u64 = 0x0000_0800;
pub const CLONE_PIDFD:          u64 = 0x0000_1000;
pub const CLONE_PTRACE:         u64 = 0x0000_2000;
pub const CLONE_VFORK:          u64 = 0x0000_4000;
pub const CLONE_PARENT:         u64 = 0x0000_8000;
pub const CLONE_THREAD:         u64 = 0x0001_0000;
pub const CLONE_NEWNS:          u64 = 0x0002_0000;
pub const CLONE_SYSVSEM:        u64 = 0x0004_0000;
pub const CLONE_SETTLS:         u64 = 0x0008_0000;
pub const CLONE_PARENT_SETTID:  u64 = 0x0010_0000;
pub const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
pub const CLONE_DETACHED:       u64 = 0x0040_0000;
pub const CLONE_UNTRACED:       u64 = 0x0080_0000;
pub const CLONE_CHILD_SETTID:   u64 = 0x0100_0000;
pub const CLONE_NEWCGROUP:      u64 = 0x0200_0000;
pub const CLONE_NEWUTS:         u64 = 0x0400_0000;
pub const CLONE_NEWIPC:         u64 = 0x0800_0000;
pub const CLONE_NEWUSER:        u64 = 0x1000_0000;
pub const CLONE_NEWPID:         u64 = 0x2000_0000;
pub const CLONE_NEWNET:         u64 = 0x4000_0000;
pub const CLONE_IO:             u64 = 0x8000_0000;
/// Shares the `CSIGNAL` window, so it is reachable through `clone3`/`unshare`
/// only — a legacy `clone(2)` low byte of `0x80` is exit_signal 128, which is
/// not a valid signal.
pub const CLONE_NEWTIME:        u64 = 0x0000_0080;
pub const CLONE_CLEAR_SIGHAND:  u64 = 1 << 32;
pub const CLONE_INTO_CGROUP:    u64 = 1 << 33;

/// Every bit a legacy `clone(2)` can carry.
pub const CLONE_LEGACY_FLAGS: u64 = 0xffff_ffff;
/// Every bit `clone3` accepts.
pub const CLONE3_KNOWN_FLAGS: u64 = CLONE_LEGACY_FLAGS | CLONE_CLEAR_SIGHAND | CLONE_INTO_CGROUP;

/// `fork(2)`: no sharing, `SIGCHLD` on exit.
pub const FORK_EXIT_SIGNAL: u32 = 17;
/// `vfork(2)`: `CLONE_VFORK | CLONE_VM`, `SIGCHLD` on exit.
pub const VFORK_FLAGS: u64 = CLONE_VFORK | CLONE_VM;

/// `struct clone_args` versioned sizes. A caller's `size` selects the version;
/// fields past it read as zero and unknown bytes past the LAST version must be
/// zero.
pub const CLONE_ARGS_SIZE_VER0: usize = 64; // ..tls
pub const CLONE_ARGS_SIZE_VER1: usize = 80; // ..set_tid_size
pub const CLONE_ARGS_SIZE_VER2: usize = 88; // ..cgroup
/// Largest `size` accepted at all; anything above is `E2BIG`.
pub const CLONE_ARGS_SIZE_MAX: usize = 4096;
/// Longest `set_tid` array: one requested pid per pid-namespace level.
pub const MAX_PID_NS_LEVEL: usize = 32;

/// `struct clone_args` field offsets, in `u64` slots.
pub mod slot {
    pub const FLAGS: usize = 0;
    pub const PIDFD: usize = 1;
    pub const CHILD_TID: usize = 2;
    pub const PARENT_TID: usize = 3;
    pub const EXIT_SIGNAL: usize = 4;
    pub const STACK: usize = 5;
    pub const STACK_SIZE: usize = 6;
    pub const TLS: usize = 7;
    pub const SET_TID: usize = 8;
    pub const SET_TID_SIZE: usize = 9;
    pub const CGROUP: usize = 10;
}

/// Decoded `struct clone_args`, already zero-extended to `CLONE_ARGS_SIZE_VER2`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CloneArgs {
    pub flags: u64,
    pub pidfd: u64,
    pub child_tid: u64,
    pub parent_tid: u64,
    pub exit_signal: u64,
    pub stack: u64,
    pub stack_size: u64,
    pub tls: u64,
    pub set_tid: u64,
    pub set_tid_size: u64,
    pub cgroup: u64,
}

impl CloneArgs {
    /// Rebuild from the 11 `u64` slots a caller-sized copy produced.
    /// # C: O(1)
    pub fn from_slots(w: &[u64; 11]) -> Self {
        Self {
            flags: w[slot::FLAGS], pidfd: w[slot::PIDFD], child_tid: w[slot::CHILD_TID],
            parent_tid: w[slot::PARENT_TID], exit_signal: w[slot::EXIT_SIGNAL],
            stack: w[slot::STACK], stack_size: w[slot::STACK_SIZE], tls: w[slot::TLS],
            set_tid: w[slot::SET_TID], set_tid_size: w[slot::SET_TID_SIZE],
            cgroup: w[slot::CGROUP],
        }
    }
}

/// `clone3`'s `size` gate, in the order the two errnos are actually produced:
/// oversize is `E2BIG` and is decided BEFORE undersize's `EINVAL`, so a caller
/// passing a wild size sees `E2BIG`, not `EINVAL`.
/// # C: O(1)
pub fn clone3_size_ok(size: usize) -> Result<(), Errno> {
    if size > CLONE_ARGS_SIZE_MAX { return Err(Errno::E2big); }
    if size < CLONE_ARGS_SIZE_VER0 { return Err(Errno::Einval); }
    Ok(())
}

/// Field-level rules applied straight after the struct copy, before any flag
/// combination is looked at.
///
/// `tail_zero` reports whether the bytes past `CLONE_ARGS_SIZE_VER2` — present
/// only when the caller declared a size this kernel does not know — were all
/// zero. A non-zero unknown field is `E2BIG`: the caller asked for a feature
/// that does not exist here.
/// # C: O(1)
pub fn clone3_fields_ok(a: &CloneArgs, size: usize, tail_zero: bool) -> Result<(), Errno> {
    if size > CLONE_ARGS_SIZE_VER2 && !tail_zero { return Err(Errno::E2big); }
    if a.set_tid_size > MAX_PID_NS_LEVEL as u64 { return Err(Errno::Einval); }
    if a.set_tid == 0 && a.set_tid_size > 0 { return Err(Errno::Einval); }
    if a.set_tid != 0 && a.set_tid_size == 0 { return Err(Errno::Einval); }
    // exit_signal lives in its own u64 here; only the CSIGNAL window is
    // representable, and the value itself is signal-checked later alongside
    // the legacy entry point's low byte.
    if (a.exit_signal & !CSIGNAL) != 0 { return Err(Errno::Einval); }
    if (a.flags & CLONE_INTO_CGROUP) != 0
        && (a.cgroup > i32::MAX as u64 || size < CLONE_ARGS_SIZE_VER2) {
        return Err(Errno::Einval);
    }
    Ok(())
}

/// The `clone3`-only flag rules. `stack_ok` is the caller's `access_ok` verdict
/// for `[stack, stack+stack_size)`; a stack outside the user range is `EINVAL`
/// here, NOT `EFAULT` — nothing has been dereferenced yet.
/// # C: O(1)
pub fn clone3_flags_ok(a: &CloneArgs, stack_ok: bool) -> Result<(), Errno> {
    if (a.flags & !CLONE3_KNOWN_FLAGS) != 0 { return Err(Errno::Einval); }
    // `CLONE_DETACHED` and the exit-signal window are reserved for future
    // `clone3` growth. `CLONE_NEWTIME` is carved out of that window because it
    // was assigned there before the reservation.
    if (a.flags & (CLONE_DETACHED | (CSIGNAL & !CLONE_NEWTIME))) != 0 { return Err(Errno::Einval); }
    if (a.flags & (CLONE_SIGHAND | CLONE_CLEAR_SIGHAND)) == (CLONE_SIGHAND | CLONE_CLEAR_SIGHAND) {
        return Err(Errno::Einval);
    }
    if (a.flags & (CLONE_THREAD | CLONE_PARENT)) != 0 && a.exit_signal != 0 {
        return Err(Errno::Einval);
    }
    if a.stack == 0 {
        if a.stack_size != 0 { return Err(Errno::Einval); }
    } else {
        if a.stack_size == 0 { return Err(Errno::Einval); }
        if !stack_ok { return Err(Errno::Einval); }
    }
    Ok(())
}

/// The child's initial stack pointer for a `clone3` request: stacks grow down
/// on both supported arches, so the kernel — not the caller — adds the length.
/// # C: O(1)
pub fn clone3_child_sp(a: &CloneArgs) -> u64 {
    if a.stack == 0 { 0 } else { a.stack.wrapping_add(a.stack_size) }
}

/// Split a legacy `clone(2)` flag word into (clone flags, exit signal). The low
/// byte is the exit signal there, so `CLONE_NEWTIME` is unreachable — a `0x80`
/// low byte is exit signal 128, rejected as an invalid signal.
/// # C: O(1)
pub fn split_legacy_flags(raw: u64) -> (u64, u32) {
    ((raw & !CSIGNAL) & CLONE_LEGACY_FLAGS, (raw & CSIGNAL) as u32)
}

/// Facts about the CALLER that two of the rules below need, gathered by the
/// slot file and passed in so the rules stay testable.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CloneCaller {
    /// The caller is its pid namespace's init, which cannot be killed by
    /// signals it did not ask for. Such a task must not gain siblings: a
    /// sibling of init is reaped by nothing and would strand as a zombie.
    pub is_ns_init: bool,
}

/// The flag-combination matrix both entry points share, plus the exit-signal
/// range check and the pidfd/parent_tid aliasing rule.
///
/// `pidfd_aliases_parent_tid` is the caller's comparison of the two user
/// pointers; a legacy `clone(2)` passes the SAME register for both, so it is
/// always true there when both flags are set.
/// # C: O(1)
pub fn validate_clone(flags: u64, exit_signal: u32, caller: CloneCaller,
                      pidfd_aliases_parent_tid: bool) -> Result<(), Errno> {
    if (flags & CLONE_PIDFD) != 0 && (flags & CLONE_PARENT_SETTID) != 0
        && pidfd_aliases_parent_tid {
        return Err(Errno::Einval);
    }
    if !valid_exit_signal(exit_signal) { return Err(Errno::Einval); }
    // A shared root directory across a mount- or user-namespace boundary would
    // let the child's namespace mutate the parent's view of `/`.
    if (flags & (CLONE_NEWNS | CLONE_FS)) == (CLONE_NEWNS | CLONE_FS) { return Err(Errno::Einval); }
    if (flags & (CLONE_NEWUSER | CLONE_FS)) == (CLONE_NEWUSER | CLONE_FS) { return Err(Errno::Einval); }
    // A thread group shares signal disposition, and shared disposition implies
    // a shared address space.
    if (flags & CLONE_THREAD) != 0 && (flags & CLONE_SIGHAND) == 0 { return Err(Errno::Einval); }
    if (flags & CLONE_SIGHAND) != 0 && (flags & CLONE_VM) == 0 { return Err(Errno::Einval); }
    if (flags & CLONE_PARENT) != 0 && caller.is_ns_init { return Err(Errno::Einval); }
    // A thread cannot live in a different pid or user namespace than the group
    // it is joining.
    if (flags & CLONE_THREAD) != 0 && (flags & (CLONE_NEWUSER | CLONE_NEWPID)) != 0 {
        return Err(Errno::Einval);
    }
    // Reserved so the bit can grow a meaning for pidfd callers.
    if (flags & CLONE_PIDFD) != 0 && (flags & CLONE_DETACHED) != 0 { return Err(Errno::Einval); }
    if (flags & CLONE_SIGHAND) != 0 && (flags & CLONE_CLEAR_SIGHAND) != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// `exit_signal` accepts 0 ("send nothing") plus every real signal number.
/// # C: O(1)
pub fn valid_exit_signal(exit_signal: u32) -> bool {
    exit_signal == 0 || sched::clone_exit_signal(exit_signal as u8).is_some()
}

/// One fully-decoded clone request, however it was expressed. `clone(2)` and
/// `clone3(2)` differ only in how the caller spells these fields, so the shared
/// core takes exactly this and nothing arch- or entry-point-specific.
#[derive(Copy, Clone, Debug)]
pub struct CloneRequest<'a> {
    /// `CLONE_*` bits WITHOUT the legacy exit-signal byte.
    pub flags: u64,
    /// Signal the child sends its parent on exit; 0 sends nothing.
    pub exit_signal: u32,
    /// Child's initial user stack pointer; 0 means "resume on the parent's".
    pub child_stack: u64,
    /// `CLONE_PARENT_SETTID` destination, in the CALLER's address space.
    pub parent_tid: u64,
    /// `CLONE_PIDFD` destination, in the caller's address space.
    pub pidfd: u64,
    /// `CLONE_CHILD_SETTID`/`CLONE_CHILD_CLEARTID` address, in the CHILD's.
    pub child_tid: u64,
    /// `CLONE_SETTLS` payload.
    pub tls: u64,
    /// `CLONE_INTO_CGROUP` target, already resolved from its descriptor.
    pub into_cgroup: Option<u64>,
    /// `clone3` `set_tid[]`: the pid the child takes in each pid namespace,
    /// innermost first. Empty means "allocate".
    pub set_tid: &'a [u32],
}

impl CloneRequest<'_> {
    /// Whether the two user pointers a legacy caller would have passed in one
    /// register actually name the same address.
    /// # C: O(1)
    pub fn pidfd_aliases_parent_tid(&self) -> bool { self.pidfd == self.parent_tid }
}

/// Highest pid number a task can be given, one past the largest legal value.
pub const PID_MAX_LIMIT: u32 = 4_194_304;

/// `clone3` `set_tid[]` value rules, independent of who is asking: one entry
/// per pid namespace the child will be visible in, innermost first, each a
/// usable pid number. Asking for more levels than exist has no meaning.
/// # C: O(N_requested)
pub fn set_tid_values_ok(requested: &[u32], ns_depth: usize) -> Result<(), Errno> {
    if requested.len() > ns_depth { return Err(Errno::Einval); }
    for pid in requested {
        if *pid == 0 || *pid >= PID_MAX_LIMIT { return Err(Errno::Einval); }
    }
    Ok(())
}

/// Whether this request needs a `pidfd` slot published into the parent, and
/// whether that descriptor names a THREAD rather than a process. A
/// `CLONE_THREAD` pidfd is legal and refers to the new thread itself.
/// # C: O(1)
pub fn pidfd_is_thread(flags: u64) -> bool { (flags & CLONE_THREAD) != 0 }

#[cfg(test)]
#[path = "clone_abi/tests.rs"] mod tests;
