# state - network completion

Update: 2026-07-15.

## Current lane

- `main`: `00304977`, synchronized with `origin/main` after D223 merged.
- B845 multicast syscall-policy ownership and unbound-membership proof is active
  on `B845-network-mcast-work-functions`.
- N01-N02, N03.1-N03.8.2, N03.8.6, and N03.8.7 are merged.
- N03.7 final-drop teardown merged in PR #3107 at `71457583`.
- N03.8.1 lifecycle and teardown race proof merged in PR #3109 at `7d6c2abb`.
- N03.8.2 physical ingress owner lease merged in PR #3111 at `f8d5c20a`.
- N03.8.6 namespace-aware Virtio uninstall merged in PR #3113 at `8c077249`.
- N03.8.7 control-plane/lifecycle serialization merged in PR #3115 at
  `11b75c13`.

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
- Per-stack RTNL and exact interface-generation leases serialize link, address,
  route, rule, multicast, RA/DAD, notification, and driver-effect work against
  move, unregister, teardown, and ifindex reuse.
- Canonical route/rule/address state implements true ECMP aliases, deletable
  built-in rules, IPv4 peer addresses, exact netlink selectors, and Linux ioctl
  errors without shadow registries.

## Verification

- Loom runner: net 525 and network-namespace 6; zero failures.
- Hosted: net 598, netlink 89, syscalls 53, Virtio net 25,
  network-namespace 3, netdev modules 4; zero failures.
- `make x86` and `make arm` passed.
- N03.7 smoke reached `basic.target`: x86 70s, ARM 129s.
- `git diff --check`, length lint, and changed-file code lint passed.

## Remaining network work

- N03.8.3-N03.8.5: loopback owner pin, atomic SIOCGSKNS fd install, and
  retained-owner schedule matrix.
- N04-N24 and the completion gate in `scratch/network-plan.md`.
- Correct stale syscall matrix evidence/status while executing the owning lanes.

## First resume command

`cd /home/nd/oxide/kernel && git pull --ff-only && rg -n 'N03.8' scratch/network-plan.md`
