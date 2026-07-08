# Handoff — B664 child-exit epoll-notify (advances sysinit); ext4 stack pending merge

## STATUS
Branch **B664-epoll-notify-child-exit** (commit 710d9781), based on origin/main
f34dee98 + unmerged B661 (signalfd) + B663 (comm) + B664. 9 commits ahead of main.

### B664 — confirmed correct, load-bearing
`crates/kernel/sched/src/live/zombies.rs`: `park_zombie` AND `reparent_children`
now call `notify_epoll_waiters()` (bumps GLOBAL_EPOLL_GEN via the installed
broadcast hook). A child going Zombie makes its pidfd poll-ready and its
parent's SIGCHLD signalfd level-ready, but neither path advanced the epoll
readiness generation → an EPOLLET-registered pidfd/signalfd computed
`new_edges==0` in `scan_once` and re-parked without reading. Without the gen
bump, systemd never woke on child-exit edges → sysinit oneshot services
(journal-flush etc.) hung their start timeout.

**Verified from boot log gfx3** (`scratchpad/gfx3.log`): with B664, the
`[wait4 reap]` trace shows init (tid 3235774466) reaping the sysinit children
tids 34–53 at t=8.4–10.3s, and units Finish (sysctl, remount-fs, random-seed,
journal-flush, udev-trigger, userdbd). Before B664 those reaps never fire.

### Dump "zombies" = benign pidfd-pin artifact (NOT a leak)
`reap_one` removes from ZOMBIES + `drop(t)`, but each open pidfd holds
`Arc<Task>` (PidfdInode.target), so a reaped child lingers as a Zombie-state
entry in `registry::try_snapshot()` until systemd closes the pidfd. Linux-
correct (pidfd keeps struct pid alive post-reap). The 13 "zombies" in the
195s task dump were ALL already reaped by 10.3s — a red herring.

## NEXT BLOCKER (desktop, standing goal)
`systemd-tmpfiles-setup-dev-early.service` process (tid 43, /usr/bin/systemd-
tmpfiles) is genuinely **wedged in epoll_wait** (~3790 syscalls then parked,
never reaped, state S) → sysinit.target never completes → boot stalls at ~10s,
never reaching gdm. `sh` (tid 33) also parked in pselect6.

DISCREPANCY to resolve: B650 state.md claimed boot reached gdm at 160s; current
main+fixes hangs at tmpfiles ~10s. Both my boots (gfx2,gfx3) hang there, so
NOT pure flake. Unknown whether cause is (a) my B661/B663 fixes, (b) a post-B650
main regression, or (c) intermittent. B664 only ADDS safe spurious wakes so is
an unlikely wedge cause. **Do NOT declare tmpfiles the root blocker from these
boots** — needs a clean origin/main baseline boot + a trace of which fd tid 43
polls (varlink→userdbd? inotify? udev?), when boots are acceptable.

## UNMERGED BACKLOG (all based on/near origin/main, none merged)
- B664 (this) — sched epoll-notify. Ready to PR (stacked on B661).
- B661-signalfd-sigchld-reap — signalfd has_zombies + rt_sigqueue wake.
- B663-task-comm-from-exec — ps/procfs/dump names from exe basename.
- ext4 stack (hosted-tested, per scratch/ext4fix.md on B662 branch):
  B656 mtime-on-write, B657 s_state lifecycle, B658 extent-descent-bound,
  B659 rmdir-reclaim, B660 msync-EIO, B662 FS_IOC_*FLAGS. B662 is 17 ahead
  (cumulative). Need boot-verify + PRs in dependency order.

## FIRST TASK NEXT SESSION
Per user's explicit redirect: build ext4fix queue (hosted, no boots).
Plan: `git show B662-ext4-fs-ioc-flags:scratch/ext4fix.md`. Next unclaimed
item = **C1 FIEMAP** (scoped): override `fiemap()` in ext4 regular.rs (needs a
physical-aware extent collector — existing `collect_leaf_extents` drops phys;
add one returning (logical, phys, len, unwritten)) + wire `FS_IOC_FIEMAP`
ioctl in syscalls/016_ioctl (copy struct in, call inode.fiemap, copy extents
out) + hosted test. VFS `FiemapExtent` struct + `fiemap` i_op already exist
(default Eopnotsupp).
