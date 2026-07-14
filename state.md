# state - network completion

Update: 2026-07-14.

## Current lane

- `main`: `8c077249`, synchronized with `origin/main` after B843 merged.
- N01-N02, N03.1-N03.8.2, and N03.8.6 are merged.
- N03.7 final-drop teardown merged in PR #3107 at `71457583`.
- N03.8.1 lifecycle and teardown race proof merged in PR #3109 at `7d6c2abb`.
- N03.8.2 physical ingress owner lease merged in PR #3111 at `f8d5c20a`.
- N03.8.6 namespace-aware Virtio uninstall merged in PR #3113 at `8c077249`.

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
- Physical RX holds a concrete namespace-owner generation lease across AF_PACKET
  and L3 delivery; Virtio drops old descriptor completions after reassignment.
- Physical uninstall follows the canonical current namespace generation and
  cannot free Virtio queues/runtime before interface unpublication completes.
- Resume-pending generations admit RX before `NetRx` wakeup but reject uninstall
  claims until device resume completes.

## Verification

- Loom runner: net 525 and network-namespace 6; zero failures.
- Hosted: net 522, Virtio net 24, network-namespace 3; zero failures.
- `make x86` and `make arm` passed.
- N03.7 smoke reached `basic.target`: x86 70s, ARM 129s.
- `git diff --check`, length lint, and changed-file code lint passed.

## Remaining network work

- N03.8.3-N03.8.5 and N03.8.7: loopback owner pin, atomic SIOCGSKNS fd install,
  retained-owner schedule matrix, and control-plane mutation/teardown
  serialization.
- N04-N24 and the completion gate in `scratch/network-plan.md`.
- Correct stale syscall matrix evidence/status while executing the owning lanes.

## First resume command

`cd /home/nd/oxide/kernel && git pull --ff-only && rg -n 'N03.8' scratch/network-plan.md`
