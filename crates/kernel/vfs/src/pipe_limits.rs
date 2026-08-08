// Pipe RESOURCE ACCOUNTING — the `fs.pipe-max-size`,
// `fs.pipe-user-pages-soft` and `fs.pipe-user-pages-hard` tunables, and the
// per-user page charge every live pipe ring is booked against.
//
// Lives in the shared VFS layer for the same reason `crate::epoll_limits` and
// `crate::fsnotify` do: procfs binds the sysctl leaves and cannot depend on the
// fs crate (fs already depends on procfs), so this is the only place both sides
// can reach. The charge itself is per uid — one account per user, not per
// namespace — which is where the reference keeps it.
//
// No target gate: every admission decision here is hosted-testable.

use core::sync::atomic::{AtomicI64, Ordering};
use alloc::vec::Vec;
use sync::{Spinlock, TaskList as TaskListClass};

/// Ring pages a pipe is created with, and the unit every charge is counted in.
pub const PIPE_DEF_BUFFERS: i64 = 16;
/// Ring pages a pipe is cut down to once its owner is past the soft limit.
pub const PIPE_MIN_DEF_BUFFERS: i64 = 2;
/// Bytes per accounted page.
pub const PIPE_PAGE_BYTES: i64 = 4096;
/// Descriptor budget the default soft limit is derived from: a user may hold
/// default-sized pipes on every descriptor an ordinary process may open.
const INR_OPEN_CUR: i64 = 1024;

/// `fs.pipe-max-size` default — how far `F_SETPIPE_SZ` may raise one pipe
/// without `CAP_SYS_RESOURCE`.
pub const PIPE_MAX_SIZE_DEFAULT: i64 = 1024 * PIPE_PAGE_BYTES;
/// `fs.pipe-user-pages-soft` default. Past it a new pipe is still created, at
/// [`PIPE_MIN_DEF_BUFFERS`] pages instead of [`PIPE_DEF_BUFFERS`].
pub const PIPE_USER_PAGES_SOFT_DEFAULT: i64 = PIPE_DEF_BUFFERS * INR_OPEN_CUR;
/// `fs.pipe-user-pages-hard` default. Zero disables the limit entirely, which
/// is what an unconfigured system runs with.
pub const PIPE_USER_PAGES_HARD_DEFAULT: i64 = 0;

static MAX_SIZE: AtomicI64 = AtomicI64::new(PIPE_MAX_SIZE_DEFAULT);
static USER_PAGES_SOFT: AtomicI64 = AtomicI64::new(PIPE_USER_PAGES_SOFT_DEFAULT);
static USER_PAGES_HARD: AtomicI64 = AtomicI64::new(PIPE_USER_PAGES_HARD_DEFAULT);

/// `fs.pipe-max-size`, in bytes. # C: O(1)
pub fn max_size() -> i64 { MAX_SIZE.load(Ordering::Relaxed) }
/// # C: O(1)
pub fn set_max_size(v: i64) { MAX_SIZE.store(v, Ordering::Relaxed); }
/// `fs.pipe-user-pages-soft`. # C: O(1)
pub fn user_pages_soft() -> i64 { USER_PAGES_SOFT.load(Ordering::Relaxed) }
/// # C: O(1)
pub fn set_user_pages_soft(v: i64) { USER_PAGES_SOFT.store(v, Ordering::Relaxed); }
/// `fs.pipe-user-pages-hard`. # C: O(1)
pub fn user_pages_hard() -> i64 { USER_PAGES_HARD.load(Ordering::Relaxed) }
/// # C: O(1)
pub fn set_user_pages_hard(v: i64) { USER_PAGES_HARD.store(v, Ordering::Relaxed); }

/// Is `user_bufs` past the soft limit? A limit of zero is no limit.
/// # C: O(1)
pub fn too_many_soft(user_bufs: i64) -> bool {
    let soft = user_pages_soft();
    soft != 0 && user_bufs > soft
}

/// Is `user_bufs` past the hard limit? A limit of zero is no limit.
/// # C: O(1)
pub fn too_many_hard(user_bufs: i64) -> bool {
    let hard = user_pages_hard();
    hard != 0 && user_bufs > hard
}

/// One user's live pipe-page charge.
struct UserBufs { uid: u32, pages: i64 }

static CHARGES: Spinlock<Vec<UserBufs>, TaskListClass> = Spinlock::new(Vec::new());

/// Move `uid`'s charge from `old` to `new` pages and report the resulting
/// total. Both directions go through here, so a release is a charge of less.
/// # C: O(N_users)
pub fn account(uid: u32, old: i64, new: i64) -> i64 {
    let mut g = CHARGES.lock();
    let idx = match g.iter().position(|c| c.uid == uid) {
        Some(i) => i,
        None => { g.push(UserBufs { uid, pages: 0 }); g.len() - 1 }
    };
    g[idx].pages += new - old;
    if g[idx].pages < 0 { g[idx].pages = 0; }
    let total = g[idx].pages;
    if total == 0 { g.remove(idx); }
    total
}

/// Live charge for `uid`. # C: O(N_users)
pub fn charged(uid: u32) -> i64 {
    let g = CHARGES.lock();
    g.iter().find(|c| c.uid == uid).map(|c| c.pages).unwrap_or(0)
}

/// A caller's standing for the two admission ladders below.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PipeCaps {
    /// `CAP_SYS_RESOURCE`: may pass `fs.pipe-max-size` outright.
    pub sys_resource: bool,
    /// Neither `CAP_SYS_RESOURCE` nor `CAP_SYS_ADMIN`: the per-user page
    /// limits apply.
    pub unprivileged: bool,
}

impl PipeCaps {
    /// Standing of a caller holding neither capability. # C: O(1)
    pub const fn unprivileged() -> Self { Self { sys_resource: false, unprivileged: true } }
    /// Standing of a caller holding both. # C: O(1)
    pub const fn privileged() -> Self { Self { sys_resource: true, unprivileged: false } }
}

/// Pages a new pipe is created with, given the pages its owner already holds.
///
/// The ladder, in order: start at the default size, clamped to the tunable
/// ceiling for a caller without `CAP_SYS_RESOURCE`; if the resulting total is
/// past the soft limit, cut the new pipe down to the minimum instead of
/// refusing it; if the total is STILL past the hard limit, refuse the pipe
/// altogether. Both limits are ignored for a privileged caller. `None` is the
/// refusal — the reference fails the whole pipe allocation there.
/// # C: O(1)
pub fn alloc_pages(already_charged: i64, caps: PipeCaps) -> Option<i64> {
    let mut pages = PIPE_DEF_BUFFERS;
    let ceiling = max_size() / PIPE_PAGE_BYTES;
    if pages > ceiling && !caps.sys_resource { pages = ceiling; }
    if pages <= 0 { return None; }
    let mut total = already_charged + pages;
    if too_many_soft(total) && caps.unprivileged {
        pages = PIPE_MIN_DEF_BUFFERS;
        total = already_charged + pages;
    }
    if too_many_hard(total) && caps.unprivileged { return None; }
    Some(pages)
}

/// Verdict of `F_SETPIPE_SZ` on a pipe currently holding `cur_pages`, for a
/// request of `want_pages`.
///
/// Shrinking is always allowed, even for an owner already over a limit. Growing
/// past the tunable ceiling needs `CAP_SYS_RESOURCE`, and growing past either
/// per-user limit is refused for an unprivileged owner — both with `EPERM`,
/// never a silent clamp: handing back a smaller pipe than was asked for turns a
/// program that sized its pipe for a batch into one that deadlocks on it.
/// # C: O(1)
pub fn resize_ok(cur_pages: i64, want_pages: i64, already_charged: i64, caps: PipeCaps)
    -> Result<(), crate::VfsError>
{
    if want_pages <= cur_pages { return Ok(()); }
    if want_pages * PIPE_PAGE_BYTES > max_size() && !caps.sys_resource {
        return Err(crate::VfsError::Eperm);
    }
    let total = already_charged - cur_pages + want_pages;
    if (too_many_hard(total) || too_many_soft(total)) && caps.unprivileged {
        return Err(crate::VfsError::Eperm);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
