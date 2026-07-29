# jizzo.md — session hand-off

`main` = `da96554ee`, clean: 0 open PRs, 1 worktree, no stray branches, no stray qemu.
Both arches build, boot-smoke PASS both, all build configs at **0 warnings**.

## Start here: the live issue

User's boot still logs, repeatedly, from **gnome-shell** (pid varies, ~4450):

```
[34.9] [B288 dgram /run/systemd/journal/socket pid=4450] MESSAGE=Failed to dispatch fd source: Invalid argument
```

**Established (don't re-derive):**
- The string `"Failed to dispatch fd source: %s"` lives in **libmutter** — one hit in the rootfs image, adjacent to `Meta::SeatImpl::dispatch_libinput()` and `[mutter] MetaThreadImpl '%s' fd source`. It is mutter's **impl-thread fd source**, NOT journald.
- The emitting pid is gnome-shell: the same pid also emits `Failed to initialize accelerated iGPU/dGPU framebuffer sharing` and `Failed to launch ibus-daemon`.
- A sysrq task dump caught **two** processes pinned at 100% CPU, state `R`: gnome-shell's **KMS thread** on `sendmsg` (236,548 calls / 3.7s) and **systemd-journald** on `recvmsg` (165,557 / 3.7s). Both fixed (#4149/#4150/#4151/#4152) — needs re-measuring to confirm.

**Retracted theories — do not revisit without new evidence:**
- libinput / `epoll_wait` returning EINVAL. `epoll_wait` cannot EINVAL for `maxevents=32`; an ungated tracer recorded **zero** EINVAL returns to gnome-shell up to the freeze.
- "stale artifacts". `make qemu-x86` runs `xtask grub` → `cmd_kernel()` → builds and boots what it built. It does **not** read `target/artifacts/`. That path is `make boot`/imagectl only.
- inotify record layout. Matches `round_event_name_len` exactly.

## The tool that made this findable

`[EINVAL nr= tid= a0=..a5= fdpath= comm=]` — every syscall returning EINVAL, bounded 4000, rides `debug-boot` so plain `make qemu-x86` emits it. `readlink` and `PR_CAPBSET_READ` are filtered (both correct, both high-volume, both ate the budget before the desktop started).

```
make qemu-x86
grep EINVAL boot.txt | grep -vE 'a0=0000000000000017|nr=89' | sort -u
```

It found and proved every syscall fix below, each verified by the count going to **0** against real systemd rather than by a unit test standing in for one.

**Wart:** it resolves `a0` as an fd unconditionally, so non-fd syscalls print a bogus `fdpath` (`bpf(cmd=5)` → `fdpath=anon_inode:[signalfd]`). Gate it to fd-taking syscalls.

## Open, ranked

1. **Four EINVALs never diagnosed** — need the argument lines, `nr=` alone is not enough:
   `read`(0), `mmap`(9), `timerfd_settime`(286), `pidfd_open`(434).
   `timerfd_settime` matters most — mutter's frame clock. Its three EINVAL paths all look Linux-correct by inspection (flag mask = `TFD_SETTIME_FLAGS`, non-timerfd fd = `isatimerfd`, timespec = `timespec64_valid`); which fires depends on `a1`/`a2`.
2. **Why `inotify_rm_watch`(255) and `fsconfig`(431) survived their fixes** in the user's log. Either their build predates #4161/#4159, or both fixes missed the real case. Resolve before assuming either.
3. **Re-land devcgroup** (reverted in `55371377b`). See Hazards §1 — it needs a live-gnome boot, not boot-smoke.
4. **`wmem` accounting leak in my own #4150** — `net/unix_sock/dgram.rs` charges `owner.wmem` pre-BPF-truncation, credits back post-truncation. Doc comment marks the site.
5. **`scratch/sweep.md`** — 12 ranked missing-wiring items with Linux citations, Status + Branch per row. Top entries:
   - `xtask --rebuild-vendor`/`--rebuild-rootfs`/`--skip-rootfs` **parsed by nothing**; qemu-mcp translates the knob into a flag `xtask grub` ignores. Agents asking for a vendor rebuild have been booting stale artifacts.
   - `bridge_answer_arp` — complete ARP responder, zero call sites.
   - `SA_RESTORER` unchecked on x86_64 (Linux `force_sigsegv`s; aarch64 computes it then `let _ = restorer;`).
   - AHCI has no interrupt path at all; never checks `CAP.S64A` while writing PxCLBU/PxFBU.
   - `sock_diag` has no `sdiag_family` dispatch — `ss -x` gets an inet reply.
6. **PSI still divergent:** Linux allows one trigger per fd and returns **EBUSY** for a second (`psi.c:1564`); we push into a Vec unconditionally.
7. **fanotify user-notif**, `CGROUP_SKB`/`SOCK_ADDR`/`LSM` bpf prog types — each needs its own run site before admitting a load would mean anything.

## Merged this session

| PR | What |
|---|---|
| 4143 | ext4 `create`/`mkdir`/`tmpfile` stopped re-reading the inode they just wrote (the journald EIO) |
| 4144 | `sys_close_shape` race + a wrong `cloexec` assertion |
| 4145, 4155, 4166 | docs: EIO resolution, succinct rule, sweep ledger |
| 4146 | `fsnotify_change` fired from `notify_change`, not 3 legacy syscall slots |
| 4147 | DELETE_SELF moved to the dcache; both `link_count` legs |
| 4148 | inotify blocks like `inotify_read` instead of spinning |
| 4149, 4150 | AF_UNIX symmetric-pair flow control + real `sk_wmem_alloc` |
| 4151, 4152 | EOF-not-EAGAIN on shut-down recv; nine copies of that decision → one |
| 4153, 4156, 4157 | the EINVAL ledger |
| 4154 | `F_DUPFD_QUERY` (182→0) |
| 4159 | `fsconfig FSCONFIG_SET_FD` — a stub, removed |
| 4160 | PSI trigger parsing (4→0) |
| 4161 | inotify mark destruction + `inotify_merge` + cgroupfs inode collision |
| 4158, 4163, 4164, 4165 | warnings 470/454/3178 → 0 |
| — | **revert** of 4162 (devcgroup) |

## Hazards that cost real time

1. **The gate must match the failure class the change introduces.** I merged devcgroup — the first change able to *deny* an open — behind a `basic.target` boot-smoke that never exercises device policy. It killed the graphical target. boot-smoke is necessary, not sufficient.
2. **`nr=` without args is not a diagnosis.** Three theories died guessing from a syscall number. `readlink` on a directory and `PR_CAPBSET_READ` past `CAP_LAST_CAP` are EINVAL in Linux too — a hit is not a bug.
3. **Read the Makefile before asserting what a command does.** The stale-artifacts claim was wrong and wasted a cycle.
4. **Hosted builds hide kernel-target breaks.** `recv_empty` compiled hosted and failed the kernel target until re-exported. Always build both arches before pushing.
5. **One worktree per lane.** Five agents ended up editing `wt-C239` simultaneously; it built, but nobody could commit by lane without splitting by path.
6. **`metadata/index.md` is not safe to auto-resolve.** A regex resolution pasted the `B` row over the whole `C` row, deleting that counter. Resolve it by hand.
7. **Agents merged their own PRs** despite explicit instructions not to, and twice misreported merge state. Verify with `gh pr view` rather than trusting the report.
8. **An intermittent single-test failure** (`ext4`, `vfs`, `sched::bh`, `s470_listns`) appears ~1 run in 3 and passes on re-run and under `--test-threads=1`. Order-dependent global state, tracked by `B1444`/`B1446`. Re-run before believing it.

## The structural finding, still holding

**The dominant defect is one decision implemented in N places and fixed in one of them** — not missing code. Every fix this session was that shape:

- empty-receive: one decision, **nine** copies, fixed in one → shipped three times
- `fire_attrib`: three callers, all in syscall slots aarch64 does not have
- AF_UNIX flow control: one Linux condition, applied on one of two sides
- DELETE_SELF: owned by `unlink(2)` instead of the dcache, so `rmdir` never reported it
- ext4 create: re-read what it had just written, a round trip Linux never makes

When a bug recurs, look for the duplicate decision before looking for a new bug. Linux's answer is almost always "one place, below every caller".
