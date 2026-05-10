# State 2026-05-10 (session 6)

## Branch

`main` at `c28d83e`. F156 + 5 structure-migration PRs landed today.

## Migration progress against docs/52a

| PR | Branch | Stage | Moved | LOC |
|---|---|---|---|---:|
| #920 | F156-mm-linux-conformance | (rmap+arm) | (boot fixes + rmap subsystem) | — |
| #921 | D56-stage-a | A | classification artifact `52a` | spec |
| #922 | R01-stage-b0-foundations | B-0 | `boot-info` + `pmm-setup` (new crates) | 638 |
| #923 | R02-stage-b1-vfs-fold | B-1 | `inode_times` → vfs, `syscall_nrs` → syscall | 456 |
| #924 | R03-stage-b1-pipe-cpu | B-1 | `pipe` + `cpu` (new crates) | 391 |
| #925 | R04-stage-b2-ipc-fold | B-2 | `sysv_shm` → ipc | 215 |
| #926 | R05-stage-b0-sched | B-0 | `kthread` → sched | 158 |

`kernel/src` shrunk by ~1700 LOC of domain code, replaced by ~50 LOC of
`52§8.2` re-export shims. Each PR independently green on all 6 CI
checks. Each merge into main verified with hosted tests + both-arch
release+debug-all builds.

## What still blocks the migration

1. **sched consolidation** (B-0 finale). `kernel/src/sched/` subdir
   has 8 files (1480 LOC) plus `ksched`/`preempt`/`sched_stop`.
   Internally references `crate::sched::*` (intra-cluster) and
   externally `crate::lapic` + `crate::smp` (mis-shelved arch
   pieces). Needs ~80 intra-cluster ref rewrites + lapic/smp move
   first. Tracked for R06+.

2. **xattr_overlay / posix_mq / coredump / flock / futex / perf /
   hostname / keyring** — all call `crate::sched::current()` and/or
   `crate::devfs::*` directly. Either the runtime singletons need
   to expose hook traits (interface refactor) OR sched/devfs need
   to be promoted to importable crates first.

3. **52a §13 OQ still open**: devfs standalone vs vfs-fold; smoke
   binaries integration-test vs runtime-smoke; signal crate naming;
   syscall dispatch table assembly target.

## Open arm interactivity issue (parked)

ARM boots through to `oxide login:`, init forks (sys_clone child_tid=
4096) and the child reaches execve cleanly. Keystrokes after the
prompt aren't reaching busybox — likely getty/tty wiring on arm
(child is alive: clones, opens, execs). Comes back after structure
migration settles.

## First task next session

```
git log --oneline main | head -10  # verify above PRs
```

Two paths from here, your call:
- Continue migration: R06 = `lapic`/`smp` → hal-x86_64 (unblocks
  sched consolidation, then sched finale, then everything else
  that's blocked on sched)
- Switch back to arm interactivity: instrument the getty/tty
  pipeline to find why stdin isn't reaching the shell
