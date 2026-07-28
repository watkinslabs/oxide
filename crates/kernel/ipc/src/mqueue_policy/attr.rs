//! `struct mq_attr` validation, the per-namespace queue admission gate, and
//! the RLIMIT_MSGQUEUE charge — Linux `mqueue_create_attr`
//! (`ipc/mqueue.c:566-608`) and `mqueue_get_inode` (`:289-401`).

use syscall::errno::Errno;

use super::limits::{
    DFLT_MSG, DFLT_MSGMAX, DFLT_MSGSIZE, DFLT_MSGSIZEMAX, DFLT_QUEUESMAX, HARD_MSGMAX,
    HARD_MSGSIZEMAX, MQ_PRIO_MAX, MSG_MSG_BYTES, MSG_TREE_NODE_BYTES,
};
use super::open::O_NONBLOCK;

/// The five per-IPC-namespace mqueue sysctls (`/proc/sys/fs/mqueue/`).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MqSysctls {
    pub queues_max: u32,
    pub msg_max: i64,
    pub msgsize_max: i64,
    pub msg_default: i64,
    pub msgsize_default: i64,
}

impl MqSysctls {
    /// `ipc/namespace.c` `create_ipc_ns` initial values. # C: O(1)
    pub const fn linux_defaults() -> Self {
        Self {
            queues_max: DFLT_QUEUESMAX,
            msg_max: DFLT_MSGMAX,
            msgsize_max: DFLT_MSGSIZEMAX,
            msg_default: DFLT_MSG,
            msgsize_default: DFLT_MSGSIZE,
        }
    }
}

impl Default for MqSysctls {
    fn default() -> Self { Self::linux_defaults() }
}

/// Validated creation parameters plus the RLIMIT_MSGQUEUE charge they incur.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MqCreate {
    pub maxmsg: i64,
    pub msgsize: i64,
    /// Linux `mq_bytes` (`ipc/mqueue.c:364-370`) — what the queue costs the
    /// creating user's `RLIMIT_MSGQUEUE` budget for as long as it exists.
    pub mq_bytes: u64,
}

/// Linux `mqueue_create_attr` (`ipc/mqueue.c:581-585`): a namespace already at
/// `queues_max` refuses a new queue with `ENOSPC`, and `CAP_SYS_RESOURCE`
/// bypasses it. Runs BEFORE any attr validation, so a bad `mq_attr` on a full
/// namespace still reports `ENOSPC`.
/// # C: O(1)
pub fn admit_new_queue(count: u32, queues_max: u32, cap_sys_resource: bool) -> Result<(), Errno> {
    if count >= queues_max && !cap_sys_resource { return Err(Errno::Enospc); }
    Ok(())
}

/// Linux `mqueue_get_inode` (`ipc/mqueue.c:326-370`). `attr` is the caller's
/// `(mq_maxmsg, mq_msgsize)` when `mq_open` was handed a non-NULL `u_attr`;
/// `None` takes the namespace defaults. Linux does NOT clamp an out-of-range
/// request — it rejects it:
///
/// * `mq_maxmsg <= 0` or `mq_msgsize <= 0` → `EINVAL`
/// * over `HARD_MSGMAX` / `HARD_MSGSIZEMAX` with `CAP_SYS_RESOURCE` → `EINVAL`
/// * over `msg_max` / `msgsize_max` without it → `EINVAL`
/// * `msgsize > ULONG_MAX / maxmsg`, or the tree overhead overflowing the
///   product → `EOVERFLOW`
/// # C: O(1)
pub fn validate_attr(attr: Option<(i64, i64)>, ns: &MqSysctls, cap_sys_resource: bool)
    -> Result<MqCreate, Errno>
{
    let mut maxmsg = if ns.msg_max < ns.msg_default { ns.msg_max } else { ns.msg_default };
    let mut msgsize = if ns.msgsize_max < ns.msgsize_default { ns.msgsize_max } else { ns.msgsize_default };
    if let Some((a_maxmsg, a_msgsize)) = attr { maxmsg = a_maxmsg; msgsize = a_msgsize; }

    if maxmsg <= 0 || msgsize <= 0 { return Err(Errno::Einval); }
    if cap_sys_resource {
        if maxmsg > HARD_MSGMAX || msgsize > HARD_MSGSIZEMAX { return Err(Errno::Einval); }
    } else if maxmsg > ns.msg_max || msgsize > ns.msgsize_max {
        return Err(Errno::Einval);
    }

    let (maxmsg_u, msgsize_u) = (maxmsg as u64, msgsize as u64);
    if msgsize_u > u64::MAX / maxmsg_u { return Err(Errno::Eoverflow); }
    let prio_nodes = if maxmsg_u < MQ_PRIO_MAX as u64 { maxmsg_u } else { MQ_PRIO_MAX as u64 };
    let treesize = maxmsg_u * MSG_MSG_BYTES as u64 + prio_nodes * MSG_TREE_NODE_BYTES as u64;
    let bytes = maxmsg_u * msgsize_u;
    let Some(mq_bytes) = bytes.checked_add(treesize) else { return Err(Errno::Eoverflow) };
    Ok(MqCreate { maxmsg, msgsize, mq_bytes })
}

/// Linux `inc_rlimit_ucounts` gate (`ipc/mqueue.c:371-387`): the new queue's
/// charge must keep the creating user's accumulated mqueue bytes within
/// `RLIMIT_MSGQUEUE`. Over it is `EMFILE` (`mqueue.c:383`) — not `EAGAIN`, and
/// not `ENOMEM`. Returns the new accumulated total on success.
/// # C: O(1)
pub fn charge_msgqueue(current_bytes: u64, add: u64, rlimit_cur: u64) -> Result<u64, Errno> {
    let Some(total) = current_bytes.checked_add(add) else { return Err(Errno::Emfile) };
    if total > rlimit_cur { return Err(Errno::Emfile); }
    Ok(total)
}

/// Linux `do_mq_getsetattr` (`ipc/mqueue.c:1392-1393`): the ONLY bit a caller
/// may set in `mq_attr.mq_flags` is `O_NONBLOCK`; anything else is `EINVAL`.
/// The test runs before the descriptor lookup, so it beats `EBADF`.
/// Returns the requested `O_NONBLOCK` state.
/// # C: O(1)
pub fn setattr_flags(mq_flags: i64) -> Result<bool, Errno> {
    if mq_flags & !(O_NONBLOCK as i64) != 0 { return Err(Errno::Einval); }
    Ok(mq_flags & O_NONBLOCK as i64 != 0)
}
