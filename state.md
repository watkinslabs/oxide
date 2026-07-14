# state - network completion

Update: 2026-07-14.

## Current lane

- `main`: `c8c7180a`, synchronized with `origin/main` when B841 branched.
- N01-N02 and N03.1-N03.7 are merged.
- N03.7 final-drop teardown merged in PR #3107 at `71457583`.
- N03.8.1 lifecycle and teardown race proof is implemented on
  `B841-netns-lifecycle-race-proof`; commit/PR/merge remains.

## Implemented

- Concrete network namespace owners are retained by tasks, namespace fds,
  INET/UNIX/PACKET/NETLINK/VSOCK sockets, and accepted sockets.
- Final owner drop signals a process-context reaper exactly once.
- Teardown quiesces interfaces before removing address, neighbor, multicast,
  fragment, route/rule, transport, UNIX, sysctl, and registry state.
- Dead or claimed numeric namespace IDs cannot recreate canonical state.
- Persistent devices are retired and returned to the initial namespace;
  namespace-owned virtual devices are destroyed.
- Callback/registry/reaper transitions share production logic with Loom models.
- Reaper notification uses monotonic publication/consumption generations; harvest
  cannot erase a concurrent final-drop notification before park.

## Verification

- Loom runner: net 518 and network-namespace 6; zero failures.
- Hosted: net 515, sched 140, network-namespace 3, xtask; zero failures.
- `make x86` and `make arm` passed.
- N03.7 smoke reached `basic.target`: x86 70s, ARM 129s.
- `git diff --check`, length lint, and changed-file code lint passed.

## Remaining network work

- B841 N03.8.1 commit, PR, merge, and closure.
- N03.8.2-N03.8.5: ingress lease, loopback owner pin, atomic SIOCGSKNS fd
  install, and full retained-owner schedule matrix.
- N04-N24 and the completion gate in `scratch/network-plan.md`.
- Correct stale syscall matrix evidence/status while executing the owning lanes.

## First resume command

`cd /home/nd/oxide/kernel && git pull --ff-only && rg -n 'N03.8' scratch/network-plan.md`
