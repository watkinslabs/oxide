ACTIVE 2026-09-05. Dep:windows,53,52.

## 1

Goal: execute one evidence-backed vertical slice at a time until a native
x86-64 PE Notepad process can create a visible window, draw text, receive a
message, and exit under the NT personality while Linux remains the common
kernel/service owner.

## 2

| Lane | Boundary | Exit evidence | Dependency |
|---|---|---|---|
| A | Registry hive save/load through canonical registry owner | 38 registry tests, both target checks, merged PR | current |
| B | NT scatter/gather file I/O through VFS iterator owner | hosted ABI/error-order tests, both target checks | A independent |
| C | PE start → environment → unixlib → USER/GDI → process lifetime | ordered Notepad harness plus guest milestone harness | current merged branches |
| D | x86-64 exception/unwind/APC/syscall return delivery | positive-control target tests and ABI return tests | C |
| E | Vulkan/GDI, audio, input, Winsock/DNS runtime dependencies | one dependency-specific harness per boundary | C |
| F | Final integration | both arches green and one visible x86-64 graphical boot | A–E |

## 3

Rules for every lane:

- re-read the current owner and the primary reference before coding;
- start from freshly fetched `origin/main` in a named worktree; reconcile it
  before the 2-hour worktree guard expires;
- make the Linux-shaped owner the only source of truth;
- test ungated decisions and run both target-aware kernel checks;
- do not use a boot to discover a defect;
- commit, push, PR, merge, delete the feature branch, and refresh primary;
- record negative findings when a ledger row is stale.

## 4

Current known-complete boundaries: volume/statfs, APC queueing and alertable
wait plumbing, symbolic-link namespace ownership, PE/NT transition contract
harnesses. Do not open duplicate lanes for them. Existing harnesses prove
contracts, not actual guest execution.

## 5

The final boot is visible, x86-64 only for the Windows workload, and happens
after all non-boot work is green. AArch64 remains a required shared-kernel
build/check target; it is not a claim of AArch64 Windows binary support.
