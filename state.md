# Handoff — desktop blocker pinpointed (af_unix socket-activation) + ext4 C1/B9 done

## DESKTOP (standing goal) — blocker precisely identified, NOT fixed
Live-gnome boot stalls ~10s in sysinit, never reaches gdm/graphics.
- **B664** (`B664-epoll-notify-child-exit`, unmerged) IS correct + load-bearing:
  child-exit epoll-notify makes systemd wake + reap sysinit services (verified
  `[wait4 reap]` 8–10s; journal-flush now Finishes). Dump "zombies" = benign
  pidfd-pin artifact, not a leak.
- **Real blocker (trace-confirmed):** `systemd-tmpfiles-setup-dev-early` wedged
  in epoll_wait on a varlink query to `systemd-userdbd.socket` (socket-activated,
  userdbd up 10.3s but idle). tmpfiles connects (POLLOUT ok) + sends, but the
  reply (POLLIN) never comes; it retries every ~15s (fresh socket+timerfd; the
  timerfd fd7 is just its retry backstop, working fine); a reply trickles at ~40s.
  → **af_unix socket-activation listener accept-readiness not reliably waking the
  accepting service's epoll.** `UnixRegistry::connect` does accept_q push +
  accept_waiters.wake_all() + notify_subs(); listener poll() correctly returns
  POLL_IN on non-empty accept_q (sock/io.rs:166). Suspect an EPOLLET edge
  suppressed for userdbd's epoll (connect bumps a poll_subs gen the service's
  epoll entry doesn't watch) so the 20ms level-rescan can't rescue it.
  Full detail in memory [[desktop-blocker-tmpfiles-userdbd]].
- **Next step needs boots** (a trace of userdbd's accept + the connect peer path,
  or a hosted repro of listener→multi-subscriber wake). User has been averse to
  boot churn — get the go-ahead before the next trace boot.
- Diagnostic traces are on disposable branch `int-diag-tmpfiles` (not for merge);
  trace logs saved: scratchpad/tmpf.log, tmpf2.log.

## EXT4 (per user's explicit "build ext4" — hosted, no boots)
This session, both committed + hosted-verified + both arches build:
- **C1 FIEMAP** (`B665-ext4-fiemap`): physical extent-map walker + FS_IOC_FIEMAP
  ioctl; 5 hosted tests.
- **B9 external xattr block** (`B666-ext4-xattr-external`): store_xattrs spills
  to i_file_acl block (e_hash/h_hash/h_checksum), e2fsck-clean; 4 hosted tests.
Full done list (11 items, all unmerged): A1 B656 · A2 B657 · A3 B659 · A4 B658 ·
B2/B4/B7 B662 · B3 B660 · C1 B665 · B9 B666. Plan: `scratch/ext4fix.md`.
Queue TODO: A5/A6/B6 jbd2, B1 mount-csum (boot-risky); B8 backup-SB; B10
inline_data; C2 punch/collapse/insert; C3 htree; C4 mballoc; C5 (crtime→statx
btime, huge_file i_blocks, 64bit fields); C6 jbd2 batching.

## UNMERGED BACKLOG — needs merging (grows every session)
Desktop: B661, B663, B664. ext4: B656–B660, B662, B665, B666 (stacked).
None on origin/main. `make smoke` (console-login profile, ~1min, NOT the hung
gnome boot) gates a kernel push — should pass. Merge in dependency order when ready.

## FIRST TASK NEXT SESSION
Decide with user: (a) fix the af_unix socket-activation blocker (needs trace
boots) to advance the desktop, or (b) keep grinding ext4 (boot-free). If (b),
next completable item = C5 crtime→STATX_BTIME (add crtime to ext4 Inode + plumb
VFS Kstat btime) or B10 inline_data.
