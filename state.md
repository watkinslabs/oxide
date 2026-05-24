# state — hand-off

Branch: main (clean). spec-lint clean, 1151 hosted tests pass,
both arches build, x86 smoke 16s + arm smoke 20s green.

## Session tally (PRs #1199–#1204)

| PR    | What |
|-------|------|
| F137  | AF_PACKET RX delivery: virtio-net rx tap copies each L2 frame into matching `SockKind::Packet` queues; bind registers the socket in `PACKET_REGISTRY` (Weak); `recvfrom` pops one frame. ETH_P_ALL + exact-protocol filter; 64-frame backlog cap. |
| F138  | SIOCSIFADDR propagates new IPv4 into the virtio-net rx softirq's stashed `our_ip` so the in-driver ARP responder answers who-has queries for the leased address. New `set_softirq_ip(ip)` + `softirq_iface_id()` helpers. |
| F139  | `recvfrom` fills sockaddr_ll for AF_PACKET sockets (family=17, proto be, ifindex, hatype=ETHER, pkttype broadcast/host, halen=6, addr=src MAC). New `af_packet::write_sockaddr_ll` helper keeps net.rs under the 1000-line cap. |
| F140  | `af_packet_smoke` now exercises the RX path via `recvfrom(MSG_DONTWAIT)` — EAGAIN is the happy path; if a frame arrives, validates sockaddr_ll.sll_family. |
| F141  | Replace upstream dhcpcd with busybox `udhcpc` (already in the vendored busybox). New /sbin/udhcpc + /sbin/udhcpd hardlinks. Background launch in rcS, gated behind /etc/oxide-udhcpc-enable so default boot stays fast. |
| F142  | Admit `socket(AF_INET, SOCK_RAW, …)` and `socket(AF_INET6, SOCK_RAW, …)` as UDP shells. udhcpc / libc getifaddrs open RAW only as ioctl handles for SIOCGIF*. |

## DHCP-stack status

| Stage | Status |
|-------|--------|
| AF_PACKET socket/bind/sendto | ✅ F131/F135 |
| AF_PACKET RX delivery        | ✅ F137 |
| AF_PACKET sockaddr_ll fill   | ✅ F139 |
| AF_INET SOCK_RAW (ioctl handle) | ✅ F142 |
| SIOCSIFADDR → ARP responder IP | ✅ F138 |
| dhcpcd 10.3.2 launch         | ✅ B46/B47/F132/F133/F134 (reaches login) |
| dhcpcd → lease               | ❌ wedges post-lease-setup; switched to udhcpc per F141 |
| udhcpc launch (OXIDE_UDHCPC_ENABLE=1) | ✅ starts, logs "udhcpc: started, v1.37.0" |
| udhcpc fork+exec /bin/true (deconfig handler) | ❌ wait4 wedges — child likely Zombies but parent never reaps |
| udhcpc DISCOVER on wire      | blocked behind wait4 wedge |

## Open next (priority order)

1. **wait4 / fork+exec /bin/true reaper wedge**. Repro: enable
   `OXIDE_UDHCPC_ENABLE=1`. udhcpc forks, child execs /bin/true,
   parent calls wait4 — and parks forever. /bin/true is a busybox
   hardlink that exits 0 immediately. Most likely the child's
   Zombie state isn't visible to `sched::live::reap_one` —
   either the reap_one filter mismatches the child's tid/pgid or
   the Zombie set/get is racing. Same wedge probably bites every
   userspace program that does fork+exec+wait4 on a fast child.
2. **AF_UNIX socket-path tmpfs materialisation** — F132's `chmod`-
   tolerance is a hack; bind(AF_UNIX) should create a socket-type
   tmpfs inode at the path.
3. **arm tickless idle** — F130's arm path busy-spins. WFI with
   DAIF.I=1 (SVC-syscall invariant) wedged on QEMU virt; need a
   safe daifclr+wfi+daifset pattern that matches CNTV INTID 27
   wake.
4. **K10 eBPF verifier**, **K13 DRM atomic modeset**,
   **per-fd targeted epoll wakes** — big tickets.

## Discipline notes

- Pre-push hook gates kernel-surface pushes — install once per
  clone: `git config core.hooksPath .githooks`
- Never rebase a published branch
- Never delete branches
- spec-lint clean before every commit + PR
- Never commit directly to main

## First task next session

```
git pull && cargo run -p xtask -- spec-lint && cargo test --all 2>&1 | grep "test result" | head -5
make smoke-x86 SMOKE_TIMEOUT=300
make smoke-arm SMOKE_TIMEOUT=300
```

Then pick item 1 (wait4 reaper wedge):
- Add `klog::write_raw(b"reap_one: matched tid=X\n")` in
  `sched::live::reap_one` happy path
- Add `klog::write_raw(b"set_state(Zombie)")` in sys_exit
- Boot with OXIDE_UDHCPC_ENABLE=1; check whether the child's
  exit message appears before wait4 parks
- If yes: reap_one filter wrong (wrong tid / pid comparison)
- If no: sys_exit isn't marking Zombie or marking under a
  different identity than the parent expects
