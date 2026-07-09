# Handoff — goals 1&2 done+merged; goal 3 (desktop) deadlock persists

## DONE this session (merged to main, e3f9242e)
- **GOAL 1 — console 100% Linux-compat**: F694 (prior) — N_TTY/VT/fbcon verified
  real; `console=` cmdline classes. console.md analysis is accurate.
- **GOAL 2 — ext4 correctness complete**: **F696** (PR #2863, merged). Closed the
  metadata_csum read-verify chain begun in F695:
  - external extent-block `et_checksum` (resolve_pblock, now reads interior nodes
    via the shadow-coherent `read_metadata_block` so in-flight journal scopes
    don't false-reject);
  - linear-dir dirent tails (lookup_in_dir; htree dirs skipped — dx_csum is
    backlog);
  - block + inode alloc bitmaps (balloc/ialloc, uninit-group-aware).
  - Inode carries ino+gen (stamped by read_inode). Negative test
    `corrupt_external_extent_block_tail_is_rejected`.
  - Verified: full ext4 suite green; x86 lite boot clean through journal-flush,
    **0 false BadChecksum**; both arches build. arm lite image not built locally.
  - Remaining ext4 = genuine features/perf/crash-only (mballoc, htree-create, ACL,
    inline_data, punch/collapse, jbd2 commit csums) — none block the desktop.
    Tracked in `scratch/ext4fix.md`.

## GOAL 3 — live-gnome boot (ACTIVE, NOT fixed)
Boot reaches ~9.8s (userdbd Started, journal-flush Finished), then **idle-quiet /
deadlocked** — all tasks blocked, guest clock stops advancing (no output for the
remaining ~100s of a 110s boot). Same frontier as prior sessions:
tmpfiles↔userdbd varlink query never completes → sysinit stalls → no getty/graphics.

### Hypothesis TESTED + DISPROVEN this session
- **Suspect:** `UnixListener::notify_subs` (net/src/unix_sock/listener.rs:44-50) is
  the ONLY readiness-wake path missing the global-rescan backstop that every
  sibling has (cf. `wake_peer_subs` events.rs:12-24 → `sched::live::notify_epoll_waiters()`).
  For an EPOLLET listener whose POLLIN is already `et_seen`, a new connection is
  reported only if `gen_edge` (epoll.rs:501-518): the fd's poll_subs gen advanced
  (needs notify_subs' Weak to upgrade) OR GLOBAL_EPOLL_GEN advanced (needs the
  global fallback). If notify_subs no-ops, the connection is silently suppressed.
  `broadcast_wake_all_epolls` (epoll.rs:110-115) bumps GLOBAL_EPOLL_GEN — the
  fallback would provably cover the EPOLLET case.
- **Applied** the fallback (mirroring wake_peer_subs), built both arches, booted.
- **Result: NO CHANGE** — boot still deadlocks at ~9.8s. **Reverted** (unproven
  boot-path change; wake path is `cfg(oxide-kernel)`-only so no hosted test
  possible). So notify_subs is NOT the blocker (or not the only one): most likely
  the listener's `subs` Weak IS alive (systemd + userdbd share the same
  Arc<InetSocket>/poll_subs across the socket-activation fd handoff), notify fires,
  gen advances — and the deadlock is elsewhere (reply direction? userdbd's own
  event loop? a different blocked resource).

### Next step needs LIVE INSPECTION — blocked on tooling
- **qemu MCP is NOT connected this session** (`mcp__qemu__*` unavailable), so the
  CLAUDE.md-recommended warm-VM breakpoint+inspect can't run here.
- Boot-per-hypothesis trace loops are user-forbidden (memory [[no-repeated-long-boots]]).
- **Need from user (pick one):** (a) enable the qemu MCP so we can boot once, break
  at the stall, dump task states / who's blocked on which fd; or (b) authorize a
  bounded trace-boot budget (klog in notify_subs upgrade-success + subscriber count,
  connect enqueue, userdbd accept, and the connected-socket reply wake) to locate
  the actual blocked-on resource.
- Prior detail: memory [[desktop-blocker-tmpfiles-userdbd]], [[qemu-vsock-cid-and-sigchld-reap]].

## First command next session
    OXIDE_QUICKBOOT_PROFILE=lite make qemu-x86 SMP=2   # reproduce ~9.8s stall; then inspect via qemu MCP
