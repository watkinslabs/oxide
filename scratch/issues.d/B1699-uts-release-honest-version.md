# B1699-uts-release-honest-version

Lane: `UTS_RELEASE` said `5.15.0-oxide` (hardcoded since it was written), which
under-reports the surface this kernel routes and makes every userspace feature
probe that gates on the release number take an older path. Raised to
`6.19.0-oxide` and made ONE owner (`syscall::uts`) that `uname(2)`, `/proc`,
`/sys` and the module vermagic all derive from.

## Derivation of 6.19 (evidence, not preference)

| Bound | Evidence |
|---|---|
| floor | every native syscall slot through `listns` (470) has a live route (`scratch/syscall-compliance-matrix.md`, 385/385 rows routed, 0 `DISPATCH-GAP`). `listns` is absent from the 6.17 series table and present in the 6.19 series table, so it is a ≤6.19 surface. |
| ceiling | `rseq_slice_yield` (471) is absent from the 6.19 series table and present after it; its slot is routed but the rseq time-slice-extension GRANT machinery is not implemented. 7.0 is therefore the first release this kernel may not claim. |

Encoded as `syscall::uts::tests::claimed_release_sits_between_the_surface_we_have_and_the_first_we_lack`
so a later release bump has to re-argue both bounds.

## Findings

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| FIXED B1699 | high | Kernel release was stated in FIVE places with THREE different values: `uname(2)` `5.15.0-oxide`, `/proc/sys/kernel/osrelease` `5.15.0-oxide`, `/proc/version` `5.15.0-oxide`, `/sys/kernel/osrelease` `0.1.0-pre`, module vermagic + out-of-tree build header `0.1.0-oxide`. A libc startup path reads `/proc/sys/kernel/osrelease` while every other probe reads `uname(2)`; `/sys` and the module ABI disagreed with both. | all five now derive from `syscall::uts`; `uts::tests::every_derived_body_carries_the_one_release` and `modinfo::tests::out_of_tree_build_header_stamps_the_kernel_vermagic` fail if any drifts | — |
| FIXED B1699 | med | `uname(2)`'s `version` field was assembled per call as `"#1 SMP PREEMPT oxide v0.1.0 nr_cpus=N"` while `/proc/sys/kernel/version` reported the same utsname field WITHOUT the suffix — two answers for one field. Linux stamps `version` at build time. | `uts::UTS_VERSION` is now the only producer; `063_uname/tests.rs` asserts the field equals it | — |
| OPEN | low | `/sys/kernel/osrelease` and `/sys/kernel/ostype` do not exist in Linux — the kernel version is exposed only under `/proc/sys/kernel/`. They are an oxide-invented surface. Left in place (now carrying the correct value) rather than removed in a version-bump PR: a prober that found them would start failing instead of falling back, and that is a separate behavioural change. | Linux registers `ostype`/`osrelease`/`version` in the utsname sysctl table only; nothing under `/sys/kernel` | — |
| OPEN | med | Landlock advertises ABI 8, which is a POST-6.19 interface (the 6.19 series uapi carries the ABI-7 logging flags and no `LANDLOCK_RESTRICT_SELF_TSYNC`; 7.2-rc is at ABI 10). So the landlock surface EXCEEDS the release claimed here. Landlock is probed by ABI query, not by release, so this costs nothing today — but a future release bump must not be justified by it alone. | `crates/kernel/landlock/src/uapi.rs:104` `ABI_VERSION = 8`, `RESTRICT_SELF_TSYNC` implemented | — |
| OPEN | med | rseq time-slice extension: slot 471 read-and-clears the yielded flag correctly, but the GRANT side (`PR_RSEQ_SLICE_*`) is not implemented. This is what pins the release below 7.0. | matrix row 471 `PARTIAL` (F762) | — |
| OPEN (info) | — | The matrix `IMPL` status CANNOT date a release: 72 of 385 rows are `PARTIAL`/`NEEDS-REWORK` and they are spread across every era (`16:ioctl`, `42:connect`, `46:sendmsg` are 1.x/2.x syscalls). Read literally, "newest release where every syscall introduced at or before it is `IMPL`" yields a bound below 2.6 — because the status tracks AUDIT CLOSURE, not presence. Presence is the property a release number claims; audit closure is tracked separately and must not be conflated with it by the next lane that revisits this number. | `scratch/syscall-compliance-matrix.md` status column: 291 IMPL / 56 PARTIAL / 16 NEEDS-REWORK / 22 LINUX-ENOSYS | — |
