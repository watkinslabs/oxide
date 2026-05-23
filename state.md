# state — hand-off

Branch: main (clean). spec-lint clean, 1151 hosted tests pass,
both arches build, x86 smoke 15s + arm smoke 20s green.

## Session tally (PRs #1188–#1189)

| PR    | What |
|-------|------|
| B47   | 3 kernel bugs unblocking dhcpcd: (1) glue_munmap was not refcount-aware → fixed the 0x40935a #GP (parent's munmap of COW-shared frames was yanking pages out from under the forked child); (2) sys_epoll_wait ignored the caller's timeout → fixed; (3) sys_mkdir returned EROFS on /var, /tmp, /run → /var, /tmp, /run added to is_ext4_path whitelist |
| B48   | SIOC* iface ioctls: SIOCGIFFLAGS / SIOCSIFFLAGS / SIOCGIFINDEX / SIOCGIF{ADDR,NETMASK,BRDADDR,MTU,HWADDR,NAME,CONF,TXQLEN}, SIOCADDRT/DELRT. AF_UNIX connect to a non-existent path now returns ECONNREFUSED instead of ENOBUFS. Adds Errno::Econnrefused (=111) + NetError::{Econnrefused,Enoent} |

## dhcpcd progress

| Stage | Status |
|-------|--------|
| double-fork daemon flow | works — no more 0x40935a #GP, no more silent SIGCHLD-handler crashes |
| /var/db/dhcpcd, /var/run/dhcpcd | mkdir succeeds |
| control_open (AF_UNIX) | succeeds → ECONNREFUSED → falls through to bind+listen path |
| SIOCGIFFLAGS/SIOCGIFINDEX/etc | succeed |
| read /etc/dhcpcd.conf | parses cleanly |
| epoll_wait with timeout | honoured |
| **DHCPDISCOVER → OFFER → REQUEST → ACK** | **not working — needs virtio-net rx/tx packet flow + ARP + AF_PACKET** |

Real DHCP is now squarely a network-stack completeness problem
(phase 15 in 00§3), not a unix-syscall surface problem. The
remaining work is several PRs of its own.

## Open next (priority order)

1. **virtio-net TX completeness on real DHCPDISCOVER**. F19-F25
   reach FEATURES_OK + DRIVER_OK but the full tx_pkt → virtqueue
   → device-write path for a real ARP/DHCP frame is untested.
   First step: a userspace probe that opens AF_PACKET + sends
   one broadcast frame, verify it reaches the host bridge.
2. **AF_PACKET (SOCK_RAW, ETH_P_ALL)** — dhcpcd opens this to
   send the DHCPDISCOVER before it has an IP. Our socket layer
   recognises AF_INET / AF_INET6 / AF_UNIX / AF_NETLINK; AF_PACKET
   (=17) falls through to EAFNOSUPPORT.
3. **ARP responder** — once a frame goes out, the host's bridge
   may probe back with ARP; we need to answer SIOCGIFADDR-supplied
   IP for the kernel-side iface.
4. **dhcpcd userspace heap-corruption** — closed; was the
   COW-munmap bug (B47). Auto-launch still gated behind
   /etc/oxide-dhcpcd-enable.
5. **arm tickless idle** — F130's arm side busy-spins.
6. **K10 eBPF rest** — verifier + JIT.
7. **K13 DRM/KMS atomic modeset** — property tables.
8. **per-fd targeted epoll wakes** — global broadcast today.

## Discipline notes

- Pre-push hook gates kernel-surface pushes — install once per
  clone: `git config core.hooksPath .githooks`
- Never rebase a published branch
- Never delete branches
- spec-lint clean before every commit + PR
- Never commit directly to main (slipped once on B48; recovered
  via reset + branch + PR)

## First task next session

```
git pull && cargo run -p xtask -- spec-lint && cargo test --all 2>&1 | tail -5
make smoke-x86 SMOKE_TIMEOUT=300
make smoke-arm SMOKE_TIMEOUT=300
```

Then pick item 1 (AF_PACKET + virtio-net TX). That unblocks
the actual DHCPDISCOVER on the wire and gets us measurable
"is the packet leaving the box" feedback. Item 2 (AF_PACKET
socket family) is the smallest follow-up.
