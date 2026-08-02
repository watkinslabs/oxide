# state.md — session hand-off

Main `db658b904`. Tree is clean: 1 worktree, 1 local branch, 1 remote branch,
0 open PRs, 0 stray QEMU. Every gate green, both arches boot first attempt.

## Gate status on this commit

| gate | result |
|---|---|
| `make hosted-gate` | PASS — 103 crates type-check in isolation |
| `make test-build-gate` | PASS — 103 crates build their **test** targets |
| `make feature-gate` | clean both arches (only rustc's upstream-`core` future-incompat note) |
| `make matrix-gate` | ok — 385 rows, 385 distinct syscalls |
| `make lint-ratchet` | PASS — at baseline |
| `cargo build --workspace` | **0 warnings** |
| `make smoke-x86` / `smoke-arm` | PASS 66s / 100s, attempt 1 |

## Counts

- Ledger: **253 open (10 high), 277 archived**.
- Syscall matrix: **291 IMPL / 56 PARTIAL / 16 NEEDS-REWORK / 22 LINUX-ENOSYS** of 385.
- Default boot output: **3379 -> 513 lines**; `qemu-*` build with no debug features.

## Rules earned this session — read before working

- **The framing question (HARD RULE):** "is this how Linux does it?" — before the
  design, not after the diff. Reference tree is `../linux-master`. It has caught a
  coordinator error, an EEXIST "fix" that would have broken seven syscalls, and a
  `/sys/subsystem` shape that would have suppressed udev's three-root scan.
- **Boot only what can break the boot.** Docs, `scratch/**`, `cfg(test)`-only,
  harness edits and lint baselines get no boot; say why in the PR body.
- **Investigative agents run on Sonnet**; Opus for implementation, root-causing
  without a hypothesis, and ABI semantics.
- **One lane, one item, then it closes.** Follow-on work gets a fresh lane.
- Never `git stash` (shared stack across worktrees). Never `git reset` onto a
  remote ref. Never `git add -A`/`-u`. Claim numbers with
  `tools/next-branch.sh --claim <T> <title>`; claims live in `refs/claims/*`,
  never the branch namespace.
- Reap your own stale QEMU by PID with the sandbox disabled; do not ask the user.

## Open work, highest value first

1. **`name_to_handle_at` on cgroupfs returns EOVERFLOW** — 74 lines per boot of
   `Failed to get cgroup ID of cgroup ...`, the largest remaining log source and a
   real systemd-visible defect.
2. **`systemd-resolved` and `systemd-sysctl` fail to start** — pre-existing on the
   baseline, never investigated.
3. **Net interfaces have no `device`/`driver` symlink.** They project under
   `/sys/devices/virtual/net/` even for the real virtio-net NIC, so udev's
   `path_id`/`net_id` builtins cannot compute `ID_NET_NAME_PATH` — which is why the
   interface is `eth0` and not a predictable name. Needs the netdev registry wired
   to the bus device registry.
4. **Generic `SOL_SOCKET` is typed to `InetSocket`**, so netlink/vsock hand-roll
   their own option tables. Linux keeps one `struct sock` base. This is why the
   netlink `SO_PASSCRED` fix first shipped as four parallel copies.
5. **The `boot-smoke` marker rides on systemd output**, not the unconditional
   console path. It works today; it is fragile to exactly the quieting just done.
6. Matrix: 56 PARTIAL + 16 NEEDS-REWORK rows.
7. `pidfd/src/tests.rs` is red under `--features hosted` and uncovered — the new
   test-build gate uses default features only.

## Traps that cost real time today

- **A stale ledger row reads as fact.** Two audit passes found 41 stale/duplicate
  rows; several lanes chased blockers fixed hours earlier. Re-check a row's claim
  before acting on it.
- **`make boot` boots `target/artifacts/`, and `xtask kernel` does NOT export
  there** — `xtask artifacts` is a separate step. Check the mtime before trusting
  any boot result.
- **Concurrent boots contend for the rootfs image lock** and produce
  zero-kernel-output logs that read exactly like a boot failure. Confirm the log
  has kernel lines before believing a red result.
- **Bulk ledger edits by substring close rows nobody audited.** Match on exact row
  text, and read the diff before pushing.

## First command

    make hosted-gate && make test-build-gate && tools/issues.sh --count
