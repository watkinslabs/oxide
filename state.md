# state.md — session hand-off

Main `2b69e2921`. Tree clean, 0 open PRs, 0 stray QEMU. 13,228 tests / 0 failed,
both arches build warning-free, boot smokes PASS.

## What this session fixed

Networking was dead for all unicast traffic and DNS did not resolve. Root cause
and every follow-on defect found on the way:

| PR | Fix |
|---|---|
| 4514 | **A zero `RTA_GATEWAY` was stored as a gateway.** Every on-link transmit solicited `who-has 0.0.0.0`, ARP never resolved, and the guest received only its 2 broadcast DHCP replies for its whole life. The reference reads a zero nexthop as directly-connected. |
| 4516 | A packet parked on an unresolved neighbour was re-dispatched with **no link-layer address** — the thing it waited for. First packet to every new neighbour was lost. |
| 4518, 4519 | **One neighbour subsystem for both families.** IPv6 had a bare `BTreeMap` beside IPv4's state machine: no NUD states, no policy, no unresolved queue. Now `net::neigh` generic over the address; the driver's private table and 2 of 3 copies of the RFC 2464 mapping deleted. |
| 4510 | `RTM_NEWADDR` discarded `IFA_BROADCAST` and never parsed `IFA_PROTO`/`IFA_RT_PRIORITY`; the dump synthesized a broadcast. NetworkManager re-applied the address every 4 s forever. Lifetimes are now aged. |
| 4504–4506 | rtnetlink notifications carried the process-global device id while dumps carried the namespace ifindex; `setsockopt(SOL_NETLINK)` returned success for 8 options it never implemented; `RTM_GETADDR` ignored `ifa_index`. |
| 4507, 4508 | All 82 raw user-pointer dereferences in DRM — any process with a DRM fd could halt the CPU with a bogus ioctl pointer. Lint added. |
| 4512, 4520, 4521 | `/proc/net/netlink` and `/proc/net/snmp` were stubs reporting nothing and zeroes; both now report real state. An ICMP match arm used an unqualified constant, making it a catch-all binding. |
| 4509, 4513, 4515 | rtnetlink multicast trace; virtio-net carrier from `VIRTIO_NET_F_STATUS`; `OXIDE_QEMU_PCAP` and `OXIDE_CMDLINE_EXTRA`. |

Verified on the guest: `ping` 0% loss both hosts, `ip neigh` REACHABLE/STALE,
`dig @10.0.2.3 example.com` returns addresses.

## The one thing still broken: systemd-resolved allocates no DNS scope

`getent hosts` and `ping <name>` fail; `dig` against the server works. resolved
shows `Link 2 (eth0)`, `DNS Servers: 10.0.2.3`, `Default Route: yes`, but
`Current Scopes: none`. **Restarting resolved fixes it** — scopes appear and it
puts real query packets on the wire.

NOT root-caused. What is measured, so it is not re-investigated:

- Kernel-side delivery is correct. resolved subscribes via `NETLINK_ADD_MEMBERSHIP`
  to groups 1/5/9 exactly as its source does; every notification reaches it
  (`[NL-MCAST … subscribed=2 reached=2]`, 63/63) and is read, not queued
  (`/proc/net/netlink` shows its socket `Rmem=0 Drops=0`).
- Notification content is correct: `ip monitor` decodes the right ifindex, global
  scope, `UP,LOWER_UP`, operstate up — every field `link_relevant()` gates on.
- Not a networkd-managed-link problem: no `systemd-networkd.service` in the image.
- **D-Bus latency is intermittent and unexplained.** Same `Peer.Ping` into
  resolved: 0.031 s on one boot, `Connection timed out` (>25 s) on the next.
  logind and systemd1 answered in 0.05–0.07 s on the fast boot. Two samples only —
  a distribution was not obtained (see harness limit below).

Best remaining hypothesis, untested: resolved's event loop wakes unreliably,
which would explain both the D-Bus timeouts and a notification read but never
acted on. Next step is to quantify the latency distribution, then test epoll
wake delivery on the fds resolved uses.

## Harness limits that cost time this session

- **Guest serial RX duplicates characters on long typed lines** — `sleep 1`
  arrived as `sleep 11`, `busctl` as `busscl`, `--system` as `--systemm`. Any
  console-driven probe must use short commands, and a corrupted command produces
  a false result. This blocked the latency measurement above.
- `/dev/console` is `tty0` (last `console=` wins), so a service logging to the
  console does not reach the serial log. `SYSTEMD_LOG_TARGET=kmsg` does.
- `/proc/net/snmp` was a hardcoded zero table and produced a wrong conclusion
  mid-investigation. Fixed; check what a `/proc` file actually implements before
  drawing inferences from it.

## Two process failures worth not repeating

1. **`git add` aborts the whole staging operation on one stale pathspec.** A
   commit merged containing only a file rename while every gate was green in the
   worktree — on code that never landed — and `main` went red. Reverted in
   `f1ab81fb6`. Verify the staged set against the working set, and `git show
   --stat HEAD`, before pushing.
2. **Nothing ratchets compiler warnings.** An ICMP catch-all binding merged with
   three warnings naming it and every gate green. A warnings ratchet like
   spec-lint's is filed.

## First task next session

    git pull
    tools/issues.sh --count

Then quantify the resolved D-Bus latency with SHORT serial commands (one
`busctl` call per typed line, results appended to a file, read at the end).
