# Handover — 2026-08-15

## Current checkout

- `main` and `origin/main` are at `8364ce55c`.
- The primary checkout is clean. Recovery branches, temporary worktrees, and recovery tags are gone.
- The shared stash stack was cleared by explicit instruction. No garbage collection was run, so removed objects may remain recoverable until pruning.

## Merged in the last cleanup

- PR #5445 (`7810c4d5d`): block-device partition scans are queued during early registration and synchronously drained at the root-mount boundary. No partition-table I/O runs before the scheduler/completion path exists.
- PR #5446 (`a0c3e28e7`, `5d0ebc170`): `debug-preempt` now records an IRQ-entry witness and provides a stable GDB breakpoint at IRQ-exit underflow. It has no normal-runtime scheduler behaviour change.

## x86 boot state

`boot.txt` is the retained failing serial log. It shows:

- kernel command line at 8.494 s;
- systemd starts at 15.897 s;
- several userspace processes immediately fault, including `systemd-getty-generator` at 16.025 s;
- debug-shell service starts, but spawning `/bin/sh` fails at 16.922 s.

This is not evidence that PCI enumeration alone is slow. The system reaches userspace, then hits an intermittent x86 ABI, memory-mapping, or lifetime failure. Do not label the problem resolved because one serial smoke reaches a shell.

The graphical surface is also blank during early boot by construction: firmware simplefb is initialized after PCI and SMP, while the retained log is serial (`ttyS0`). That ordering must not be "fixed" by moving simplefb ahead of PCI. The correct future design is an early firmware-framebuffer boot-console/splash owner that preserves the validated handoff surface, then hands it to simpledrm/fbcon without competing with native PCI display ownership.

## Next steps

1. Diagnose the x86 userspace faults before adding more drivers or boot-time work. Turn the retained fault IP, VMA, ELF segment, and exec mapping state into a deterministic hosted decoder/provenance test; use the fault diagnostic feature only after that evidence is in place.
2. If an x86 run reports `scheduling while atomic` or IRQ-exit underflow, boot once with `debug-preempt` and use the witness to distinguish an unmatched IRQ exit from a counter overwrite. Do not make a scheduler behaviour change without that result.
3. Implement the early graphical boot-console/splash as a dedicated handoff path. It must use the existing validated boot framebuffer, render before heavyweight probing, and relinquish the aperture cleanly to the later DRM/simplefb owner.
4. Revisit AHCI/NVMe delay polling only in focused work. A hardware settle delay may sleep in process context; atomic and early paths must retain bounded polling. Do not revive the discarded mixed implementation.

## Rejected recovery fragments

- PCI probe loops that spin for fixed millions of iterations: non-Linux-shaped and a direct boot-latency risk.
- Moving simplefb before PCI: violates the firmware-framebuffer/native-driver handoff order.
- Boot-time NVMe LBA0 self-test: superseded by PR #5445's root-mount scan boundary.
- Unreviewed IGB driver snapshot: substantial but untested and unsafe to bind without a dedicated lifecycle audit.

## Working discipline

- Begin each change on a fresh branch from `origin/main`; keep the PR focused, validate it, merge it immediately, and remove its branch/worktree.
- Use the shared generic wait mechanism for condition/publish/recheck/schedule. Verify every new wait or lock shape against the reference before implementation.
- Build a focused harness first. Use one bounded, retained-log QEMU boot only as final verification when the change is boot-visible.
