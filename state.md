# state — hand-off

Branch: main (clean). spec-lint clean, 1151 hosted tests pass,
both arches build, x86 smoke 16s + arm smoke 20s green.

## Session tally (PRs #1199–#1219)

Network stack went from "AF_PACKET sendto admitted" to **fully
online** on both arches.

| PR    | What |
|-------|------|
| F137  | AF_PACKET RX delivery into bound sockets |
| F138  | SIOCSIFADDR propagates new IPv4 into virtio-net ARP responder |
| F139  | AF_PACKET sockaddr_ll fill on recvfrom |
| F140  | af_packet_smoke exercises RX path |
| F141  | busybox udhcpc as v1 DHCP client |
| F142  | AF_INET / AF_INET6 SOCK_RAW admitted as UDP shells |
| F143  | wait4 missed-wakeup race fix |
| F144  | **CFS voluntary-schedule vruntime fix** — was THE wedge for every fork+exec+wait4 daemonize flow |
| F145  | virtio-net rx drain from timer tick (replaces kthread) |
| F146  | AF_PACKET SOCK_DGRAM eth-header strip/prepend; sys_poll inode dispatch; deliver_packet_rx wakes waiters |
| F147  | udhcpc lease handler script (ifconfig + route + resolv.conf) |
| F148  | SIOCADDRT / SIOCDELRT populate kernel route table |
| F149  | ARP resolver for outbound IPv4 + src-MAC snooping |
| F150  | socket_sendto picks iface primary IP for src; /bin/online_smoke proves UDP DNS round-trip |
| F151  | /bin/tcp_smoke proves TCP 3WHS via eth0 |
| F152  | **ARM lockstep**: rearm CNTV in elf_smoke_arm so tick_poll fires; retire kthread |
| F153  | bind(AF_UNIX) materialises tmpfs socket-type inode |
| F154  | ARM tickless idle (daifclr+wfi+daifset in tick_yield) |
| F155  | smoke-dhcp make target + boot-smoke-dhcp.sh |
| D34/D35 | mid-session hand-offs |

## End-to-end online (OXIDE_UDHCPC_ENABLE=1 on both arches)

```
udhcpc: started, v1.37.0
udhcpc: broadcasting discover
udhcpc: broadcasting select for 10.0.2.15, server 10.0.2.2
udhcpc: lease of 10.0.2.15 obtained from 10.0.2.2, lease time 86400
udhcpc: configured eth0 as 10.0.2.15 via 10.0.2.2
online_smoke: PASS rx=103 bytes from 10.0.2.3:53
tcp_smoke: 10.0.2.2:22 connect OK
tcp_smoke: 10.0.2.3:53 connect OK
tcp_smoke: PASS hits=2
```

ARM completes the lease too (verified via `make smoke-dhcp-arm`);
the default.script + smoke chain takes longer than the 180s standard
smoke window can hold so DHCP stays opt-in.

## Open next (priority order)

1. **wget / netcat outbound** — full read of an SSH banner or
   HTTP body. TCP 3WHS is proven; `recv` after connect is the
   remaining question.
2. **DNS resolver** (libc res_init) — read /etc/resolv.conf, send
   queries, fill /etc/hosts cache. Unlocks getent + curl style.
3. **AF_UNIX through tmpfs path lookup** — F153 materialises the
   inode; need `connect(AF_UNIX, path)` to consult the inode's
   UnixListener Arc directly (today it still goes through
   UNIX_REGISTRY string-key lookup).
4. **smoke-arm-dhcp perf** — investigate why the full chain
   exceeds 180s; probably default.script's fork/exec overhead.
5. **K10 eBPF verifier**, **K13 DRM atomic modeset**,
   **per-fd targeted epoll wakes** — large.

## Discipline notes

- Pre-push hook gates kernel-surface pushes — install once per
  clone: `git config core.hooksPath .githooks`
- Never rebase a published branch
- Never delete branches
- spec-lint clean before every commit + PR
- Never commit directly to main
- **ARM lockstep**: every kernel-side network change verified on
  both `make smoke-{x86,arm}` AND `make smoke-dhcp-{x86,arm}` (the
  latter takes longer on arm under TCG)

## First task next session

```
git pull && cargo run -p xtask -- spec-lint && cargo test --all 2>&1 | grep "test result" | head -5
make smoke-x86 SMOKE_TIMEOUT=300
make smoke-arm SMOKE_TIMEOUT=300
make smoke-dhcp-x86  # quick: ~16s
```

Then pick item 1 (wget / nc full TCP body read).
