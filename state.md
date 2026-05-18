# state — hand-off

Branch: main (clean). spec-lint clean, 1086 tests pass, both arches build.
Both arches boot to login headless via the boot-smoke gate.

## What's working end-to-end now

- **virtio-net** drives an iface — NetDev registered, xmit ok, RX via
  MSI-driven softirq + RX poller kthread fallback (F86, F87)
- **netlink (AF_NETLINK)** — rtnetlink (RTM_GETLINK/GETADDR/NEWADDR/
  DELADDR/GETROUTE/NEWROUTE/DELROUTE) + genetlink (CTRL.GETFAMILY)
  + NFNETLINK substrate (nftables tables / chains / rules)
- **boot-smoke gate** local-only (pre-push hook, no GHA cost)

## Session totals

24 PRs landed: F82, F83, B35, B37, C74, F84, B38, B39, F85, F86,
F87, F88, F89, F90, F91, F92, F93, F94, F95, F96, F97, F98, D25, D26.
(One reverted disaster: B36.)

## Crate layout established (per docs/52§5)

| Crate | Purpose |
|---|---|
| `crates/kernel/net/` | protocol stack (TCP/UDP/ICMP/ARP/iface registry) |
| `crates/kernel/netlink/` | AF_NETLINK + rtnetlink + genetlink |
| `crates/kernel/netfilter/` | NFNETLINK + nftables |
| `crates/drivers/drv-virtio-net/` | virtio-net device driver |
| `crates/drivers/drv-virtio-{blk,gpu,input}/` | other virtio devices |

## Open next (priority order)

1. **userspace DHCP client** — busybox `udhcpc` integration. Now that
   #1132/#1133 ship, the kernel-side substrate is ready; userspace
   needs cross-build + image staging.
2. **nftables packet-path enforcement** — F96-F98 store the rule set
   but no packet hook executes against it. NF_INET_LOCAL_IN /
   LOCAL_OUT / etc. hook callbacks ride a follow-up.
3. **F58 per-vector MSI dispatch** — F87 raises NetRx on the shared
   vector. Per-vector dispatch lets the RX kthread retire and
   each device handle its own IRQ cleanly.
4. **K10 eBPF verifier + JIT** — large multi-PR. Verifier first,
   socket-filter prog type, then JIT.
5. **K13 DRM/KMS atomic modeset** — `crates/drivers/drm/` exists but
   atomic-commit surface is incomplete. Large multi-PR.
6. **getty wedge B40** — B39 worked around it by skipping getty. The
   real tty-ioctl/termios bug that hangs busybox getty headless is
   still there. Investigation-style PR.
7. **DNS / TLS userspace** — depends on DHCP. musl resolver + cross-
   built openssl/rustls.
8. **nftables sets / objects / batches** — NFNL_SUBSYS_NFTABLES sub-
   commands NEWSET/GETSET/DELSET, NEWOBJ/GETOBJ/DELOBJ. F96-F98 left
   these as accept-and-no-op (err=0).

## Discipline notes

- Pre-push hook is mandatory; smoke gate is local (KVM-cheap, no GHA
  cost burn). Install once per clone: `git config core.hooksPath .githooks`.
- Never rebase a published branch — `gh pr merge --merge` handles the
  integration server-side. See [[feedback_no_branch_rebase]].
- File-length cap 1000 LOC; split into submodules at next touch.
- spec-lint clean before every commit AND every PR.

## First task next session

```
git pull && cargo run -p xtask -- spec-lint && cargo test --all 2>&1 | tail -5
make smoke-x86 SMOKE_TIMEOUT=300
make smoke-arm SMOKE_TIMEOUT=300
```

Pick from "Open next". Smallest-bite next is #8 (nftables sets);
biggest-impact-per-PR is #2 (packet-path enforcement so the rule
set actually fires); #4 and #5 each want multiple sessions.
