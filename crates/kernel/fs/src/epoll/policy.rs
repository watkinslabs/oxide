// epoll DECISION LOGIC — the pure rules `epoll_ctl(2)` and the epoll file's
// ioctl apply, with no user memory, no fd table and no target gate, so the
// error ladder and its ORDER are hosted-testable.
//
// The `epoll/syscalls.rs` side owns only the fd resolution, the usercopy and
// the interest-list mutation; every "which errno, and which one first" answer
// lives here.

use syscall::errno::Errno;

/// `EPOLL_CTL_ADD`.
pub const EPOLL_CTL_ADD: i32 = 1;
/// `EPOLL_CTL_DEL`.
pub const EPOLL_CTL_DEL: i32 = 2;
/// `EPOLL_CTL_MOD`.
pub const EPOLL_CTL_MOD: i32 = 3;

/// `EPOLLET` — edge-triggered.
pub const EPOLLET: u32 = 0x8000_0000;
/// `EPOLLONESHOT` — disarm after one report, rearmed by `EPOLL_CTL_MOD`.
pub const EPOLLONESHOT: u32 = 0x4000_0000;
/// `EPOLLWAKEUP` — hold a wakeup source across the report; needs
/// `CAP_BLOCK_SUSPEND`, and is silently dropped without it.
pub const EPOLLWAKEUP: u32 = 0x2000_0000;
/// `EPOLLEXCLUSIVE` — wake one waiter per readiness edge.
pub const EPOLLEXCLUSIVE: u32 = 0x1000_0000;

/// Bits `EPOLLEXCLUSIVE` may be combined with: `EPOLLIN|EPOLLOUT|EPOLLERR|
/// EPOLLHUP|EPOLLWAKEUP|EPOLLET|EPOLLEXCLUSIVE`. `EPOLLPRI` is NOT among them.
pub const EPOLLEXCLUSIVE_OK_BITS: u32 = vfs::POLL_IN | vfs::POLL_OUT
    | vfs::POLL_ERR | vfs::POLL_HUP | EPOLLWAKEUP | EPOLLET | EPOLLEXCLUSIVE;

/// Bits an interest always reports whether or not the caller asked for them.
pub const EPOLL_ALWAYS_REPORTED: u32 = vfs::POLL_ERR | vfs::POLL_HUP;

/// Longest chain of epoll files an interest may join.
pub const EP_MAX_NESTS: usize = 4;

/// `ep_op_has_event(op)` — does this operation carry a user `epoll_event`?
/// Only `EPOLL_CTL_DEL` does not, which is why a NULL/invalid `event` pointer
/// is accepted for a delete and faults for the other two. # C: O(1)
pub fn op_has_event(op: i32) -> bool { op != EPOLL_CTL_DEL }

/// Properties of the `epoll_ctl` target that decide the error ladder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CtlTarget {
    /// `file_can_poll(tf->file)` — the target implements a readiness op.
    pub can_poll: bool,
    /// `is_file_epoll(tf->file)` — the target is itself an epoll file.
    pub is_epoll: bool,
    /// The target description IS the epoll description named by `epfd`.
    pub is_self: bool,
}

/// `ep_take_care_of_epollwakeup`: `EPOLLWAKEUP` without `CAP_BLOCK_SUSPEND` is
/// dropped from the mask, never reported as an error. # C: O(1)
pub fn take_care_of_epollwakeup(events: u32, may_block_suspend: bool) -> u32 {
    if may_block_suspend { events } else { events & !EPOLLWAKEUP }
}

/// `do_epoll_ctl_file`'s admission ladder, in Linux's order, returning the
/// event mask the interest is stored with.
///
/// Order matters to any caller that trips more than one condition at once:
/// a non-pollable target is `EPERM` even when it is also the epoll file
/// itself; `EPOLLWAKEUP` is stripped before the `EPOLLEXCLUSIVE` mask check
/// sees the mask; the self/not-an-epoll `EINVAL` precedes every
/// `EPOLLEXCLUSIVE` rule; and an unknown `op` is rejected LAST, after the
/// target has already been vetted.
///
/// `EPOLLERR`/`EPOLLHUP` are folded in for `ADD`/`MOD` because Linux stores
/// them in `epi->event.events`, which is the mask `/proc/<pid>/fdinfo`
/// reports back. # C: O(1)
pub fn ctl_precheck(op: i32, f_is_epoll: bool, t: CtlTarget, events: u32,
                    may_block_suspend: bool) -> Result<u32, Errno> {
    if !t.can_poll { return Err(Errno::Eperm); }
    let mut events = if op_has_event(op) {
        take_care_of_epollwakeup(events, may_block_suspend)
    } else { 0 };
    if t.is_self || !f_is_epoll { return Err(Errno::Einval); }
    if op_has_event(op) && events & EPOLLEXCLUSIVE != 0 {
        if op == EPOLL_CTL_MOD { return Err(Errno::Einval); }
        if op == EPOLL_CTL_ADD && (t.is_epoll || events & !EPOLLEXCLUSIVE_OK_BITS != 0) {
            return Err(Errno::Einval);
        }
    }
    match op {
        EPOLL_CTL_ADD | EPOLL_CTL_MOD => { events |= EPOLL_ALWAYS_REPORTED; Ok(events) }
        EPOLL_CTL_DEL => Ok(0),
        _ => Err(Errno::Einval),
    }
}

/// `ep_loop_check`'s verdict: `depth + 1 + upwards_depth > EP_MAX_NESTS` is a
/// chain too long to insert. `down_depth` is how far the tree BELOW the target
/// epoll reaches; `up_depth` is how far the epolls watching the destination
/// reach above it. Counting only one direction admits a chain that Linux
/// rejects, because either end can be extended after the other was built.
/// # C: O(1)
pub fn nesting_admits(down_depth: usize, up_depth: usize) -> bool {
    down_depth <= EP_MAX_NESTS && down_depth + 1 + up_depth <= EP_MAX_NESTS
}

/// `struct epoll_params` byte length (`__u32 + __u16 + __u8 + __u8`).
pub const EPOLL_PARAMS_BYTES: u64 = 8;

/// `EPIOCSPARAMS` — `_IOW(EPOLL_IOC_TYPE, 0x01, struct epoll_params)`.
pub const EPIOCSPARAMS: u64 = 0x4008_8A01;
/// `EPIOCGPARAMS` — `_IOR(EPOLL_IOC_TYPE, 0x02, struct epoll_params)`.
pub const EPIOCGPARAMS: u64 = 0x8008_8A02;

/// What `ep_eventpoll_ioctl` does with a command that reached an epoll file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpollIoctl {
    /// Store the busy-poll parameters.
    SetParams,
    /// Report the busy-poll parameters.
    GetParams,
    /// `EINVAL` — an epoll file's operations reject every other command,
    /// including the ones a chardev or a regular file would answer. This is
    /// only reachable because the generic ioctl stage hands an anon-inode fd
    /// straight to its own operations.
    Invalid,
}

/// `ep_eventpoll_ioctl`'s command decode. # C: O(1)
pub fn epoll_ioctl(req: u64) -> EpollIoctl {
    match req {
        EPIOCSPARAMS => EpollIoctl::SetParams,
        EPIOCGPARAMS => EpollIoctl::GetParams,
        _ => EpollIoctl::Invalid,
    }
}

/// `NAPI_POLL_WEIGHT` — the budget above which `EPIOCSPARAMS` needs
/// `CAP_NET_ADMIN`.
pub const NAPI_POLL_WEIGHT: u16 = 64;

/// `EPIOCSPARAMS` admission: the pad byte must be zero, `busy_poll_usecs` must
/// fit a signed 32-bit value, `prefer_busy_poll` is a boolean, and a budget
/// above one NAPI poll weight is privileged. # C: O(1)
pub fn validate_epoll_params(busy_poll_usecs: u32, busy_poll_budget: u16,
                             prefer_busy_poll: u8, pad: u8,
                             cap_net_admin: bool) -> Result<(), Errno> {
    if pad != 0 { return Err(Errno::Einval); }
    if busy_poll_usecs > i32::MAX as u32 { return Err(Errno::Einval); }
    if prefer_busy_poll > 1 { return Err(Errno::Einval); }
    if busy_poll_budget > NAPI_POLL_WEIGHT && !cap_net_admin { return Err(Errno::Eperm); }
    Ok(())
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
