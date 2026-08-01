# state.md — session hand-off

Main `757173e79`, clean: 0 open PRs, 0 lane worktrees, 0 QEMU. Syscall matrix
**IMPL 281 / NEEDS-REWORK 17 / PARTIAL 64 / LINUX-ENOSYS 22** of 385.

`scratch/known_issues.md` is now the ledger of record (CLAUDE.md hard rule): every
finding gets a row in the PR that finds it, flipped to `FIXED <sha>`, never deleted.
**Read it before picking up work** — it holds the open items this file only summarises.

## Headline: GNOME is usable, and three security holes are closed

| Fix | PR |
|---|---|
| **Ring-3 LPE**: `CR4.FSGSBASE=1` with no `swapgs` anywhere, so `GS_BASE` pointed at the kernel per-CPU area in ring 3 — unprivileged `wrgsbase` gave the next `syscall`'s `mov gs:[16],rsp` an attacker base = arbitrary kernel write + stack pivot | #4299 |
| **Landlock sandbox could widen itself from the inside**: enforcement read through to the live, still-writable ruleset, so a sandboxed thread could `add_rule` on the fd it had enforced. Also: `restrict_self` required neither `no_new_privs` nor `CAP_SYS_ADMIN` | #4319 |
| **Recycled tid inherited the previous occupant's keys**: `inherit_session` had no caller outside its own test | #4318 |

GNOME desktop fixes: the guest was never offered an **absolute pointer** (#4305); the
connector published **exactly one mode** and `SET_SCANOUT` ran *before* `TRANSFER`,
binding the display to an unwritten buffer every frame (#4306); damage rectangles
(#4309); EDID never fetched (#4312); and **left-click** — `EpollFileOps` implemented
`poll()` but not `poll_deadline_ns`, so a compositor waiting on an epoll fd parked past
libinput's 12 ms debounce timerfd, stranding every button release until unrelated input
woke the loop. Every click read as a long press (#4313). Verified to userspace: single
click opens GNOME Terminal to a `bash-5.2$` prompt.

## The defect class that dominated this session

**Verification that returns green without exercising what it claims.** Four instances:

1. A branch that **did not compile** passed every local gate — the break was inside
   `debug_boot! { … }` and nothing in the routine set compiles feature-gated code.
   Fixed: `make feature-gate` (both arches, `debug-all`). CI already covered it; the
   gap was the merge path, which does not wait on CI.
2. `procfs/ctl.rs` is target-gated, so `cargo check` compiled none of it.
3. A **set**-based check used on a question of **multiplicity** — it reported "none
   dropped" while 8 tests were duplicated, 7 of the pairs with *different* bodies.
4. A skeptical check wrong in the skeptical direction: "my `--features` flag was
   ignored" was itself an assumption. `xtask kernel` does honour it — settled in one
   command against a deliberately invalid value.

Corollary: **`N/0 passed` in `net` is weaker than it looks.** The suite has
pre-existing cross-test races on `main` (~17% of runs fail). Six clean runs at ~90% is
unremarkable, not evidence of stability.

## Next up

1. `scratch/known_issues.md` open rows — start there, not here.
2. **`drain_loopback()` runs a full receive traversal inline on the caller's stack**,
   32 call sites; Linux queues to the per-CPU backlog and drains in NET_RX softirq.
   Worth ~2768 B on every such chain. aarch64 margin is **312 B**, thin.
   *Negative result:* a runtime re-entrancy guard cannot help — the depth walker
   follows static call edges; only breaking the edge via the softirq's function
   pointer works.
3. The `net` suite's parallel instability, including a test binary found **spinning at
   ~43 cores for 20 minutes**, orphaned from a run that had reported completion.
4. 17 `NEEDS-REWORK` rows — deliberately not closed, gaps named inline in the matrix.
5. Files: nautilus does not launch from the dash (Terminal does) — app-launch, not click.

## Traps that cost real time

- **Matrix columns**: status at awk `$9` / python `f[8]`, branch `$10`, notes `$13`.
  Python's split index is one *less* than awk's field number; getting it wrong
  overwrote the branch column on four rows.
- **Merged branches reappear on the remote** when a lane pushes after its PR merges.
  Check `git branch -r` after every merge; `--delete-branch` alone is not enough.
- **Never touch another lane's worktree.** Merging `main` into one twice caused churn;
  removing one mid-boot orphaned a QEMU against a deleted directory.
- **Conflict resolution is where coverage dies silently.** One resolution nearly
  re-introduced a bug `main` had just fixed (`set_ptrace_scope` losing its EINVAL);
  another nearly reverted two `/proc` leaves to constants and deleted two more.
  Diff hook *bodies* across both sides; verify by count, never by set.
- Boot-smoke deletes its log on completion. A build failure under `debug-boot` dies
  before QEMU starts, so the log is empty and reads like a boot failure.
