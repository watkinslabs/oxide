# state — hand-off

Branch: main (clean). spec-lint clean, 1151 hosted tests pass,
both arches build, x86 smoke 16s + arm smoke 20s green.

## Session tally (PRs #1194–#1196)

| PR    | What |
|-------|------|
| F133  | `sys_sendto` netlink shim must come before `socket_from_fd`; new `net_trace::trace_enotsock_at(fd, site)` debug hook (cfg-gated under `debug-irq`). Closed the "if_discover: Not a socket" blocker — dhcpcd's `bpf_open → if_linksocket → sendto(NETLINK_ROUTE, RTM_GETLINK)` now succeeds. |
| F134  | `net::sock::sendto` AF_UNIX SOCK_SEQPACKET / SOCK_STREAM socketpair branch. Was returning EADDRNOTAVAIL because the call fell through to the AF_INET UDP arm with no dest. dhcpcd's launcher→grandchild fork-fd exit-status handshake now completes; `oxide login:` reached with dhcpcd enabled. |
| F135  | `NetDev::xmit_raw(frame)` trait method for L2-already-framed TX (AF_PACKET / bpf); VirtioNetDev overrides to skip the header-build prepend. `af_packet::sendto` routes through `xmit_raw`. Adds modern virtio-net to the standard qemu launcher (both arches) — slirp NAT gives the guest 10.0.2.x with a DHCP server at 10.0.2.2. Ships opt-in `/bin/af_packet_smoke` probe. |

## dhcpcd progress (cumulative)

| Stage | Status |
|-------|--------|
| double-fork daemon | ✅ B46/B47 |
| /var/db, /var/run mkdir | ✅ B47 |
| control_open + chmod | ✅ B48/F132 |
| SIOC* ioctls | ✅ B48 |
| netlink bind/getsockname/setsockopt/sendto/recvfrom | ✅ F132/F133 |
| AF_PACKET socket/bind/sendto | ✅ F131/F135 (admit + parse, but see TX hang below) |
| SOCK_SEQPACKET socketpair sendto | ✅ F134 |
| dhcpcd reaches `oxide login:` | ✅ all smokes + dhcpcd daemonise complete, login prompt up |
| **DHCPDISCOVER actually on the wire** | **blocked: AF_PACKET sendto hangs in `tx_frame`'s MMIO kick when called from user-syscall context (IF=0); boot-context kick works fine. Likely a kernel-half PT-clone race when user PTs are created.** |

## Open next (priority order)

1. **AF_PACKET MMIO-write-in-user-syscall hang**. Repro:
   `/bin/af_packet_smoke` from rcS hangs forever inside
   `drv_virtio_net::modern::tx_frame` immediately after writing
   to `s.q1_notify_va` (the queue-1 doorbell at
   `fffffd000000d004` — a Device-attr MMIO mapping). The
   kernel-context boot probe writes the same VA fine. Theory:
   the user PT cloned from master copies PML4 entries 256..512,
   but the VIRTIO_BAR_VA_BASE (`0xffff_fd00_0000_0000`) arena's
   lower-level PTs may have been added to master AFTER init's
   user PT was created, leaving the user PT pointing at a
   stale PDPT/PD/PT chain. Confirm by adding a kernel-side
   `translate(0xfffffd000000d004)` from user-syscall context
   and comparing to boot-context translate.
2. **AF_PACKET RX delivery** — currently AF_PACKET sockets'
   rx queue stays empty (`recvfrom` returns EAGAIN forever).
   Once (1) lands and DHCPDISCOVER goes out, slirp will reply;
   our virtio-net rx-ring handler needs to demux frames and
   push into matching AF_PACKET socket queues.
3. **ARP responder** for SIOCSIFADDR-set addresses.
4. **AF_UNIX socket-path tmpfs materialisation** — F132's
   `chmod`-tolerance is a hack; bind(AF_UNIX) should create a
   socket-type tmpfs inode at the path.
5. **arm tickless idle** — F130's arm side busy-spins.
6. **K10 eBPF verifier**, **K13 DRM atomic modeset**,
   **per-fd epoll wakes** — big tickets.

## Discipline notes

- Pre-push hook gates kernel-surface pushes — install once per
  clone: `git config core.hooksPath .githooks`
- Never rebase a published branch
- Never delete branches
- spec-lint clean before every commit + PR
- Never commit directly to main

## First task next session

```
git pull && cargo run -p xtask -- spec-lint && cargo test --all 2>&1 | tail -5
make smoke-x86 SMOKE_TIMEOUT=300
make smoke-arm SMOKE_TIMEOUT=300
```

Then pick item 1 (AF_PACKET MMIO hang in user-syscall context):
- Add a kernel-side test that calls `MmuOps::translate(fffffd000000d004)`
  from inside `sys_ioctl` or similar user-syscall entry.
- Compare result to the same translate during boot.
- If user-syscall context returns None, the user PT genuinely
  doesn't have the mapping → fix `new_user_pml4` to force a
  full kernel-half PDPT-chain populate at clone time.
- If translate succeeds, the hang is at the device level and
  the boot probe's TX is the only thing keeping the queue
  alive; need real virtio-net IRQ handler before the second
  TX can complete.
