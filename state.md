# state — hand-off

Branch: main (clean). spec-lint clean, 1086 tests pass, both arches build.
Boot-smoke gate passes both arches on every kernel-surface push.

## What's working end-to-end now

- **virtio-net** drives an iface — NetDev registered, xmit ok, RX via
  MSI-driven softirq + RX poller kthread fallback (F86, F87)
- **netlink (AF_NETLINK)** — rtnetlink (RTM_GETLINK/GETADDR/NEWADDR/
  DELADDR/GETROUTE/NEWROUTE/DELROUTE), genetlink (CTRL.GETFAMILY),
  NFNETLINK (nftables tables/chains/rules)
- **BPF maps** — BPF_MAP_LOOKUP / UPDATE / DELETE round-trip; verifier
  + JIT for PROG_LOAD still pending (F99)
- **boot-smoke gate** — pre-push hook, no GHA cost, gates kernel/,
  crates/{kernel,drivers,arch}/, userspace/, targets/, vendor/

## Session totals — 28 PRs

| Range | Theme |
|---|---|
| F82, F84, F85 | ext4 mknod/symlink/depth=2/O_TMPFILE |
| F83 | sys_futex_waitv |
| B35, B36(revert), B37 | arm-abi *at + chroot + utimensat sweep |
| C74, C75 | pre-push boot-smoke hook + crates/drivers/* trigger |
| B38 | x86 fork inherits LIVE FS_BASE (race) |
| B39 | inittab uses /bin/login direct (getty wedge bypass) |
| F86, F87 | virtio-net RX kthread + MSI-driven softirq |
| F88-F95 | netlink crate + rtnetlink + addr/route tables + lo seed |
| F94 | genetlink scaffold + CTRL family |
| F96-F98 | netfilter crate + nftables tables/chains/rules |
| F99 | BPF map LOOKUP/UPDATE/DELETE |
| B41 | drv-virtio-input keymap test flake fix |
| D25-D28 | state.md checkpoints |

## Crate layout established (per docs/52§5)

| Crate | Purpose |
|---|---|
| `crates/kernel/net/` | protocol stack (TCP/UDP/ICMP/ARP/iface registry) |
| `crates/kernel/netlink/` | AF_NETLINK + rtnetlink + genetlink |
| `crates/kernel/netfilter/` | NFNETLINK + nftables |
| `crates/drivers/drv-virtio-net/` | virtio-net device driver |
| `crates/drivers/drv-virtio-{blk,gpu,input}/` | other virtio devices |
| `crates/kernel/security/` | BPF / Landlock / capabilities |

## Open next (priority order)

1. **userspace DHCP** — busybox `udhcpc` integration. Substrate ready.
2. **nftables packet-path enforcement** — F96-F98 store rules; need
   `nf_hook_eval(hook_id, pkt) -> verdict` API in netfilter + NF_INET_
   LOCAL_IN/OUT callsites in net stack.
3. **F58 per-vector MSI dispatch** — F87 raises NetRx on the shared
   vector. Per-vector lets the F86 polling kthread retire.
4. **K10 eBPF verifier + JIT** — F99 ships map ops; PROG_LOAD still
   stores empty insns. Verifier first, then JIT. Multi-PR.
5. **K13 DRM/KMS atomic modeset** — `crates/drivers/drm/` exists but
   atomic-commit surface is incomplete. Multi-PR.
6. **getty wedge B40** — B39 worked around it. Real tty-ioctl/termios
   bug still there. Investigation-style PR.
7. **DNS / TLS userspace** — depends on DHCP. musl resolver + cross-
   built openssl/rustls.
8. **nftables sets / objects / batches** — NFNL subcommands left as
   accept-and-no-op in F96-F98.

## Discipline notes

- Pre-push hook gates kernel-surface pushes (now includes
  `crates/drivers/*` per C75). Install once per clone:
  `git config core.hooksPath .githooks`
- Never rebase a published branch — `gh pr merge --merge` handles
  the integration server-side ([[feedback_no_branch_rebase]])
- Verify post-merge CI on main, not just the pre-push hook —
  test-hosted can flake on parallel-shared-state tests (B41)
- File-length cap 1000 LOC; split into submodules at next touch
- spec-lint clean before every commit AND every PR

## First task next session

```
git pull && cargo run -p xtask -- spec-lint && cargo test --all 2>&1 | tail -5
make smoke-x86 SMOKE_TIMEOUT=300
make smoke-arm SMOKE_TIMEOUT=300
gh pr list --state merged --limit 5 --json number,statusCheckRollup \
  --jq '.[] | {n: .number, failed: ([.statusCheckRollup[]? | select(.conclusion=="FAILURE") | .name] | join(","))}'
```

Then pick from "Open next". The remaining items are each multi-day:
- eBPF verifier (#4) is the biggest single subsystem
- DRM/KMS (#5) is the second
- DHCP userspace (#1) is cross-build + image staging
- nftables packet-path (#2) is the smallest viable kernel-side bite
