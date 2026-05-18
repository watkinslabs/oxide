# state — hand-off

Branch: main (clean). spec-lint clean, 1078 tests pass, both arches build.
**Both arches boot to login headless** via the new boot-smoke gate.
**virtio-net drives an iface end-to-end** with MSI-driven RX softirq + RX
poller kthread fallback.
**netlink (AF_NETLINK) substrate** lands rtnetlink RTM_GETLINK / GETADDR /
NEWADDR / DELADDR / GETROUTE / NEWROUTE / DELROUTE — `ip link show`,
`ip addr show / add / del`, `ip route show / add / del` all wire-format
correct.

## This session highlights

| PR | Branch | Summary |
|----|--------|---------|
| #1114 | F82 | mknodat + symlinkat write-side (+arm ABI fix mknodat) |
| #1115 | F83 | sys_futex_waitv real impl |
| #1117 | B35 | arm-abi *at family + chroot + utimensat shift fixes |
| #1118 | B36 | (broken — wrong-direction systematic shift) |
| #1119 | B37 | revert B36 + targeted arm-abi re-fixes + tests |
| #1122 | C74 | pre-push boot-smoke hook + script (no GHA cost) |
| #1120 | F84 | ext4 extent depth 1→2 promotion + append_depth2 |
| #1123 | B38 | x86 fork inherits LIVE FS_BASE (race fix) |
| #1124 | B39 | inittab uses /bin/login direct, skipping wedge'd getty |
| #1125 | F85 | O_TMPFILE + AT_EMPTY_PATH linkat |
| #1126 | F86 | virtio-net RX-poller kthread |
| #1127 | F87 | MSI-driven virtio-net RX via softirq Slot::NetRx |
| #1128 | F88 | crates/kernel/netlink/ scaffold + AF_NETLINK socket |
| #1129 | F89 | netlink RTM_GETLINK for ip link show |
| #1130 | F90 | netlink RTM_GETADDR for ip addr show |
| #1131 | F91 | netlink RTM_GETROUTE for ip route show |
| #1132 | F92 | netlink iface-addr table + RTM_NEWADDR/DELADDR |
| #1133 | F93 | netlink route table + RTM_NEWROUTE/DELROUTE |

## Boot-smoke gate (C74)

`tools/boot-smoke.sh` + `make smoke-{x86,arm,}` + `.githooks/pre-push`
hook gate every kernel-surface push. Fires on changes under `kernel/`,
`crates/kernel/`, `crates/arch/`, `userspace/`, `targets/`, `vendor/`,
`rust-toolchain.toml`, `Cargo.toml`, `Cargo.lock`. SKIP_SMOKE=1 to bypass.

Install once per clone:
```
git config core.hooksPath .githooks
```

## Open next (priority order)

1. **userspace DHCP client** — busybox `udhcpc` integration or vendor
   real `dhcpcd`. Sends RTM_NEWADDR via netlink now that #1132 lands.
2. **NETLINK_GENERIC (genetlink)** — modern tools (e.g. `iw`,
   `nftables`) use this. Family registry + ctrl family.
3. **nftables substrate** — NETLINK_NETFILTER handlers + in-memory
   table/chain/rule storage. Multi-PR.
4. **K10 eBPF verifier + JIT** — large multi-PR. Verifier first,
   socket-filter prog type, then JIT.
5. **K13 DRM/KMS atomic modeset** — `crates/drivers/drm/` + per-evdev
   registry. Large.
6. **DNS / TLS userspace** — depends on DHCP landing. musl resolver
   + cross-built openssl/rustls.
7. **getty wedge follow-up** — B39 bypassed getty entirely; the real
   tty-ioctl/termios bug that causes it to hang headless is unfixed.
   Filing B40 to chase it.
8. **virtio-net per-vector MSI dispatch** — F87 raises NetRx on the
   shared vector. F58 follow-up in arch-irq adds per-vector dispatch;
   then the F86 polling kthread can retire.
9. **TLS endgame** — closed enough by B38 (x86 fork FS_BASE race);
   musl/glibc handle TLS via arch_prctl per Linux convention. No
   further kernel work needed unless a real-libc program complains.

## Discipline notes

- Pre-push hook is mandatory; smoke gate is local (KVM-cheap, no GHA
  cost burn).
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

Pick from "Open next". Easiest single-PR win is #2 (NETLINK_GENERIC
scaffold) — same crate, same shape as rtnetlink, follows the established
pattern. eBPF / DRM / DHCP all want fresh-context planning sessions
because they're 5+ PRs each.
