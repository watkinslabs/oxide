# Oxide Notepad handoff

Date: 2026-09-06
Branch: `D1550-notepad-masterplan`
Base HEAD: `586e5390e`

## State

The worktree contains the accumulated Notepad/Windows compatibility implementation from the parallel lanes. No commit, push, merge, image staging, or guest boot has been performed for this checkpoint. Six lanes are quiescent; their edits remain in this worktree.

Verified hosted work includes child process identity publication, canonical Unix pathname DAC ordering, Windows registry framing and bounded persistent clients, GDI/window/paint paths, compositor probes, and user-path validation. Latest focused results include:

- registry: 45 unit tests + 3 real-daemon lifetime tests pass;
- runtime user paths: 9 tests pass;
- Unix resolver: 12 tests pass, and the removed-DAC control fails as expected;
- native process identity: 6 tests pass with production-hook removal control;
- latest reported x86/aarch64 kernel debug-preempt checks pass.

## Not complete

- Notepad has not been guest-booted or visibly accepted in GNOME.
- The normal-user registry launch path still needs connected-FD admission, canonical transport identity on keys/watches, and wrapper lifecycle repair.
- Desktop authority/root publication and shared HWND ownership are not wired into the process-create path.
- PE handoff still loses the pinned Linux executable source identity; the versioned source-FD contract is only designed.
- ARM `registryd` cannot link from the current glibc-only sysroot. Required verified payloads are `libgcc-15.2.1-7.fc42.aarch64` and `gcc-15.2.1-7.fc42.aarch64`; compose a private reproducible sysroot before changing the shared one.
- The lint ratchet is red with 45 categories over the existing baseline, including pre-existing ledger rows. Do not silently bypass it; record the exact gate decision in the PR.

## Next integration order

1. Reconcile and review the staged diff; preserve all lane-owned files.
2. Integrate the connected registry capability and normal-user wrapper lifecycle.
3. Integrate desktop root/membership authority and shared window ownership.
4. Integrate versioned PE source identity and procfs verification.
5. Repair the reproducible ARM userspace sysroot composition.
6. Run both-arch hosted/build gates, then one final `make qemu-x86` visible Notepad acceptance. No boot is a development loop.

## Resume commands

```sh
git status --short --branch
git log --oneline -5
tools/issues.sh --query status=OPEN
git diff --check
```
