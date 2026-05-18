# state — hand-off

Branch: main (clean). spec-lint clean, ~1100 hosted tests pass,
both arches build. Recent CI: 21/21 green (this session).

## Session tally (PRs #1150–#1170)

| PR | What |
|---|---|
| F104 | netfilter→net::stack hook bridge on NF_INET_LOCAL_IN |
| F105 | nft expr interpreter: immediate / cmp / payload (NETWORK) |
| F106 | nft meta expr: LEN / NFPROTO / L4PROTO |
| F107 | BPF structural verifier |
| F108 | BPF interpreter core (ALU64 / JMP / EXIT / LD_IMM_DW) |
| F109 | BPF LDX_MEM_{B,H,W,DW} packet loads |
| F110 | BPF_CALL helper dispatch table |
| F111 | nft payload TRANSPORT base via IPv4 IHL |
| F112 | nft set elements: NEWSETELEM / DELSETELEM / GETSETELEM |
| F113 | nft lookup expression (set membership, F_INV honored) |
| F114 | netlink + netfilter mask NLA_F_NESTED in nla_type compares |
| F115 | DRM_IOCTL_MODE_ATOMIC TEST_ONLY → 0 |
| F116 | DRM SET_CLIENT_CAP + master arb + auth → 0 |
| F117 | DRM plane/CRTC/encoder/connector lookup stubs |
| F118 | BPF_MAP_GET_NEXT_KEY iteration |
| F119 | nft counter expression — per-rule (packets, bytes) |
| F120 | nft bitwise expression — (src AND mask) XOR xor |
| F121 | nft byteorder expression — per-element byte-reverse |
| F122 | UDP broadcast send falls back to first non-lo iface |
| C76  | split nft_expr tests into nft_expr_tests.rs (905→405 LOC) |
| D30  | state.md checkpoint after F113 |

## What works end-to-end now

- **netfilter packet path** — eval(hook_id, pkt) walks base chains
  in priority order, runs each rule's expression list, applies
  policy on fall-through. NF_INET_LOCAL_IN wired into deliver_rx
- **nft expression set** — immediate, cmp (EQ/NEQ), payload
  (NETWORK + TRANSPORT via IHL), meta (LEN/NFPROTO/L4PROTO),
  lookup (set + F_INV), counter (stateful per-handle), bitwise,
  byteorder
- **nft set elements** — NEW/DEL/GET round-trip; set_elem_lookup
  powers the lookup expression
- **eBPF substrate** — structural verifier + interpreter + helper
  CALL dispatch; map LOOKUP/UPDATE/DELETE/GET_NEXT_KEY all round-
  trip; PROG_LOAD rejects malformed
- **virtio-net** drives an iface — MSI-driven softirq + RX poller
- **netlink** — rtnetlink + genetlink (CTRL) + NFNETLINK; F_NESTED
  bit handled correctly across all parsers
- **DRM** — atomic-probe, client caps, master arb, auth, plane
  enumeration all return non-ENOTTY so compositors advance
- **UDP broadcast** — `send_udp_to(255.255.255.255, ...)` works
  even without a route entry (picks first non-lo iface)

## Open next (priority order)

1. **userspace DHCP** — busybox udhcpc cross-build + image stage;
   substrate now complete (broadcast UDP + ARP-broadcast L2)
2. **K10 eBPF rest** — path-sensitive verifier (reg types, scalar
   bounds) → JIT; structural-only today
3. **K13 DRM/KMS atomic modeset** — property tables + real
   atomic-commit; today only TEST_ONLY-with-no-ops returns 0
4. **getty wedge B40** — real tty-ioctl/termios bug behind the
   /bin/login direct workaround in inittab
5. **DNS / TLS userspace** — depends on DHCP
6. **nft polish** — dynset (rule-side set updates), batch txn
   rollback, NFT_LOOKUP with full key_len semantics
7. **net** — route table scope tracking (RT_SCOPE_LINK) so the
   broadcast fallback in send_udp_to can retire

## Discipline notes

- Pre-push hook gates kernel-surface pushes — install once per
  clone: `git config core.hooksPath .githooks`
- Never rebase a published branch — `gh pr merge --merge` handles
  integration server-side
- Never delete branches (`git branch -d/-D`) — preserve all
- Verify post-merge CI on main, not just the pre-push hook
- spec-lint clean before every commit + PR
- nft_expr.rs and nft_expr_tests.rs both well under the 1000-LOC
  cap now (405 / 501); next nft expression doesn't need another
  split

## First task next session

```
git pull && cargo run -p xtask -- spec-lint && cargo test --all 2>&1 | tail -5
make smoke-x86 SMOKE_TIMEOUT=300
make smoke-arm SMOKE_TIMEOUT=300
gh pr list --state merged --limit 5 --json number,statusCheckRollup \
  --jq '.[] | {n: .number, failed: ([.statusCheckRollup[]? | select(.conclusion=="FAILURE") | .name] | join(","))}'
```

Then pick from "Open next". DHCP (#1) is the next user-visible
win — kernel-side broadcast is in place, so the work is in
userspace cross-build + image staging.
