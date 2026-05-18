# state — hand-off

Branch: main (clean). spec-lint clean, ~1100 tests pass, both arches build.
Boot-smoke gate passes both arches on every kernel-surface push.
Recent PR-time CI: 10/10 green (F104–F113).

## What's working end-to-end now

- **netfilter packet path** — eval(hook_id, pkt) walks base chains
  by priority, runs each rule's expression list, applies policy on
  fall-through. Wired into net::stack::deliver_rx on NF_INET_LOCAL_IN.
  Expression set: payload (NETWORK + TRANSPORT bases via IHL), cmp
  (EQ/NEQ), immediate (VERDICT/value), meta (LEN/NFPROTO/L4PROTO),
  lookup (set membership + invert)
- **nft set elements** — NEWSETELEM/DELSETELEM/GETSETELEM round-
  trip; set_elem_lookup powers the lookup expression
- **eBPF substrate** — structural verifier (size, align, regs,
  jump bounds, EXIT terminator, wide-load straddling) + interpreter
  (ALU64/JMP/EXIT/LD_IMM_DW/LDX_MEM_{B,H,W,DW}/CALL helpers); 1M
  step budget; R1 = context register
- **virtio-net** drives an iface — MSI-driven softirq + RX poller
  kthread fallback
- **netlink** — rtnetlink + genetlink (CTRL) + NFNETLINK (nft+nfgen)
- **BPF maps** — LOOKUP/UPDATE/DELETE round-trip; PROG_LOAD now
  rejects malformed via verifier

## Open next (priority order)

1. **userspace DHCP** — busybox `udhcpc` cross-build + image stage
2. **K10 eBPF rest** — path-sensitive verifier (reg type/scalar
   bounds) → JIT; PROG_LOAD currently runs structural-only
3. **K13 DRM/KMS atomic modeset** — atomic-commit surface
4. **getty wedge B40** — real tty-ioctl/termios bug behind the
   /bin/login direct workaround
5. **DNS / TLS userspace** — depends on DHCP
6. **nft sweep** — bitwise / byteorder / counter exprs; batch txns
   real rollback; global find_*_attr should mask NLA_F_NESTED

## Discipline notes

- Pre-push hook gates kernel-surface pushes — install once per
  clone: `git config core.hooksPath .githooks`
- Never rebase a published branch — `gh pr merge --merge` handles
  integration server-side
- Never delete branches (`git branch -d/-D`) — preserve all
- Verify post-merge CI on main; this run: 5/5 green so far
- spec-lint clean before every commit + PR

## First task next session

```
git pull && cargo run -p xtask -- spec-lint && cargo test --all 2>&1 | tail -5
make smoke-x86 SMOKE_TIMEOUT=300
make smoke-arm SMOKE_TIMEOUT=300
gh pr list --state merged --limit 5 --json number,statusCheckRollup \
  --jq '.[] | {n: .number, failed: ([.statusCheckRollup[]? | select(.conclusion=="FAILURE") | .name] | join(","))}'
```

Then pick from "Open next". eBPF JIT (#2) and DRM/KMS (#3) are the
two biggest remaining single subsystems. DHCP (#1) is the next
user-visible win (real network address acquisition).
