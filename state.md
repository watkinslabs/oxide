# state - network completion

Update: 2026-07-14.

## Current lane

- `main`: `71457583`, synchronized with `origin/main`.
- N01-N02 and N03.1-N03.7 are merged.
- N03.7 final-drop teardown merged in PR #3107 at `71457583`.
- N03.8 lifecycle and teardown race proof is the next unclaimed lane.

## Implemented

- Concrete network namespace owners are retained by tasks, namespace fds,
  INET/UNIX/PACKET/NETLINK/VSOCK sockets, and accepted sockets.
- Final owner drop signals a process-context reaper exactly once.
- Teardown quiesces interfaces before removing address, neighbor, multicast,
  fragment, route/rule, transport, UNIX, sysctl, and registry state.
- Dead or claimed numeric namespace IDs cannot recreate canonical state.
- Persistent devices are retired and returned to the initial namespace;
  namespace-owned virtual devices are destroyed.

## Verification

- Hosted: net 513, procfs 47, sched 137, syscalls 53, softirq 6,
  network-namespace 3, drv-virtio-net 19, sysfs 48; zero failures.
- Integrated affected-package checks passed.
- `make x86` and `make arm` passed.
- Smoke reached `basic.target`: x86 70s, ARM 129s.
- `git diff --check` and length lint passed.

## Remaining network work

- N03.8 lifecycle/teardown race proof.
- N04-N24 and the completion gate in `scratch/network-plan.md`.
- Correct stale syscall matrix evidence/status while executing the owning lanes.

## First resume command

`cd /home/nd/oxide/kernel && git pull --ff-only && rg -n 'N03.8' scratch/network-plan.md`
