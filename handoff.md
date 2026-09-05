# Windows compatibility handoff

Status: MERGED. Snapshot: 2026-09-05. Current `origin/main`: `f601d5124`.

## Completed lane

Branch: `F1597-canonical-registry-hive-transactions` (merged as PR #7472).
Worktree: removed after merge. Primary is detached at `origin/main`.

This lane completes the canonical registry owner path for `NtSaveKey`,
`NtLoadKey`, and relative hive loading. The kernel syscall layer remains a
shim: it reads or writes through VFS and sends typed frames to the one
registry owner in userspace. No second registry or side-channel state was
added.

## Verified

- `cargo test --manifest-path userspace/probes/Cargo.toml -p windows-registry`: 38 passed.
- `./tools/test-windows-notepad-harness.sh`: PASS (W1-W5 contract harness).
- `./tools/test-windows-nt-transition-harness.sh`: PASS.
- `rustup run nightly-2026-05-01 cargo run --quiet -p xtask -- kernel --arch x86_64 --check`: PASS.
- `rustup run nightly-2026-05-01 cargo run --quiet -p xtask -- kernel --arch aarch64 --check`: PASS.
- `git diff --check`: PASS.

These are contract/build results. No graphical or headless boot was run in
this lane. The single visible boot remains final verification only.

## Follow-up before the next implementation lane

1. Inspect the complete diff and confirm the hive write path handles an
   existing longer destination correctly; add truncation through the VFS
   inode owner if required by the file-open contract.
2. Add or retain focused tests for root load, relative load, malformed hive,
   atomic failure, and durable save. Do not broaden the wire protocol with
   aliases for the removed export/import names.
3. Re-run the tests and both target checks.
4. Start the next lane from freshly fetched `origin/main`; do not reuse the
   completed branch or its removed worktree.

## Dependency-ordered work plan

### Lane A — registry persistence (current)

Owner: `F1597-canonical-registry-hive-transactions`.
Exit: merged PR, clean primary, registry tests and both target checks green.

### Lane B — NT file scatter/gather

Re-read current `nt_file` dispatch and VFS read/write iterator owners before
coding. Implement `NtReadFileScatter` and `NtWriteFileGather` in the existing
VFS path if absent. Prove buffer ordering, short I/O, alignment, and error
ordering with hosted tests. Do not duplicate volume/statfs: that path is
already implemented in `nt_file_volume.rs` and `vfs/superblock/stat.rs`.

### Lane C — Notepad runtime admission

Audit the current PE start, process environment, unixlib return bridge,
user32 window creation, message loop, GDI text, and process lifetime branches
against the real call graph. Combine only after each branch is independently
verified from fresh `origin/main`. The target is one visible Notepad launch,
window show, text draw, input/message dispatch, and clean exit.

### Lane D — NT exception and return delivery

Audit current x86-64 exception/unwind, APC delivery, and syscall return paths.
APC queueing and alertable waits already exist; do not create another queue.
Implement only missing target-aware delivery or remote-thread behavior, with
positive-control tests that compile the kernel-gated path.

### Lane E — graphics/audio/input/network runtime dependencies

Use the existing Wine/Proton reference only to identify the userspace
dependency boundary. Keep NT kernel ownership limited to process, memory,
objects, VFS, synchronization, and ABI delivery. Add one concrete runtime
dependency per lane: Vulkan admission, GDI/USER display, audio device
lifecycle, input translation, then Winsock/DNS. Linux DNS remains the common
network resolver owner.

### Lane F — final integration

After all non-boot lanes are green, run the required both-arch gates and one
visible x86_64 graphical boot. Capture the serial log and verify the Notepad
milestones. Do not use another boot as an exploratory test.

## Known stale findings

- Volume information/statfs is already implemented; do not reimplement it.
- APC queueing and return-path hooks already exist; remaining work is proof or
  a precisely identified missing delivery case.
- Symbolic-link namespace ownership is already canonical.
- Existing Notepad and NT transition harnesses prove contracts, not guest
  execution.

## Resume commands

```sh
cd /home/nd/oxide/kernel
git status --short --branch
git diff --check
cargo test --manifest-path userspace/probes/Cargo.toml -p windows-registry
rustup run nightly-2026-05-01 cargo run --quiet -p xtask -- kernel --arch x86_64 --check
rustup run nightly-2026-05-01 cargo run --quiet -p xtask -- kernel --arch aarch64 --check
```

Start every subsequent feature from freshly fetched `origin/main` using
`tools/next-branch.sh --claim`. Fan-out is allowed, but each linked worktree
must be merged, refreshed, or explicitly closed before the 2-hour guard
expires; never stash or leave hidden WIP.
