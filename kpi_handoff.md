# KPI Handoff

Date: 2026-07-07

## Repository State

- Primary repo: `/home/nd/oxide/kernel`
- Active worktree: `/home/nd/oxide-wt/kpi-usercopy-api`
- Active branch: `F673-kpi-usercopy-api`
- Base main commit: `af5a6767e2f704b3c8492811ddd7fad1a0afc298`
- Branch HEAD before this handoff commit: `2774f3f55b39d941fb8d6248f1e2fd374140fd2c`
- Branch is ahead of `origin/main` by the F673 claim and implementation commits.
- Work has not yet been pushed, PR'd, or merged.
- Main checkout has an unrelated dirty file: `crates/kernel/mm-pmm/src/buddy/api.rs`. Do not revert it.

## Completed Before F673

- F669 USB merged in PR #2781.
- F670 platform/ACPI/DT merged in PR #2782.
- F671 power/PM merged in PR #2783 at `ef90277a`.
- F672 crypto/random/CRC merged in PR #2785 at `af5a6767e2f704b3c8492811ddd7fad1a0afc298`.

## Current KPI Lane

- KPI: `F673-kpi-usercopy-api`
- Ledger row in `kpi_fix.md` has been changed from `GAP`/`CLAIMED` to `DONE`.
- `metadata/index.md` was already bumped during the claim commit from F next `673` to `674`.

## F673 Commits

- `be0d4d95 chore: claim F673 usercopy KPI lane`
- `2774f3f5 feat(modules): add Linux usercopy KPI helpers`
- This handoff/ledger commit should follow these commits.

## F673 Implementation Summary

- Added `crates/kernel/modules/src/linux_usercopy.rs`.
- Exported Linux KPI symbols:
  - `access_ok`
  - `copy_from_user`
  - `copy_to_user`
  - `clear_user`
  - `__get_user_1`, `__get_user_2`, `__get_user_4`, `__get_user_8`
  - `__put_user_1`, `__put_user_2`, `__put_user_4`, `__put_user_8`
- Wired the module through:
  - `crates/kernel/modules/src/lib.rs`
  - `crates/kernel/modules/src/registry.rs`
  - `crates/kernel/modules/Cargo.toml`
  - `Cargo.lock`
- Added KPI header:
  - `kpi/include/linux/uaccess.h`
- Extended syntax smoke coverage:
  - `tools/kpi-header-smoke.c`

## Design Notes

- No magic numbers were added for page math or user VA bounds; the implementation uses existing `hal` constants.
- Copy helpers return bytes not copied, matching the Linux API shape.
- Typed `get_user`/`put_user` helpers return `0` or `-EFAULT`.
- User ranges are checked against `USER_VA_END`, overflow is rejected, and non-empty null user pointers are rejected.
- The VMA permission check uses the current task's mm and requires READ for `copy_from_user`/`get_user`, WRITE for `copy_to_user`/`clear_user`/`put_user`.
- The current implementation does explicit validation and non-overlapping copies; it does not install a page-fault recovery path.

## Validation Already Passed

From `/home/nd/oxide-wt/kpi-usercopy-api`:

- `cargo test -p modules linux_usercopy`
- `cargo test -p modules`
- `cc -std=gnu11 -Ikpi/include -ffreestanding -fsyntax-only tools/kpi-header-smoke.c`
- `clang -std=gnu11 -target x86_64-unknown-linux-gnu -Ikpi/include -ffreestanding -fsyntax-only tools/kpi-header-smoke.c`
- `clang -std=gnu11 -target aarch64-unknown-linux-gnu -Ikpi/include -ffreestanding -fsyntax-only tools/kpi-header-smoke.c`
- `cargo run -p xtask -- kernel --arch x86_64`
- `cargo run -p xtask -- kernel --arch aarch64`
- `git diff --check`

## vDSO Note

glibc does not replace vDSO. glibc is the userspace C library; vDSO is the kernel-provided userspace ABI blob mapped into a process for fast paths such as time queries. The aarch64 kernel build initially failed because `vdso-aarch64.so` was missing in the fresh worktree. Rerunning `cargo run -p xtask -- kernel --arch aarch64` generated both vDSO blobs and the build passed.

## Next Steps

1. Confirm the worktree is clean:
   - `git -C /home/nd/oxide-wt/kpi-usercopy-api status --short --branch`
2. Fetch fresh main:
   - `git -C /home/nd/oxide-wt/kpi-usercopy-api fetch origin main --prune`
3. Push the branch:
   - `SKIP_SMOKE=1 git -C /home/nd/oxide-wt/kpi-usercopy-api push -u origin F673-kpi-usercopy-api`
4. Open a PR titled:
   - `feat(modules): add Linux usercopy KPI helpers`
5. Merge the PR once clean.
6. Fast-forward `/home/nd/oxide/kernel` to `origin/main`.
7. Remove the worktree and local branch:
   - `git -C /home/nd/oxide/kernel worktree remove /home/nd/oxide-wt/kpi-usercopy-api`
   - `git -C /home/nd/oxide/kernel branch -d F673-kpi-usercopy-api`
8. Only then claim the next F lane, likely `F674-kpi-debugfs-configfs`.

## Do Not Do

- Do not run `rustfmt` or `cargo fmt`.
- Do not revert unrelated user changes in `/home/nd/oxide/kernel`.
- Do not call `PARTIAL` rows complete. Only merged `DONE` rows are complete.
- Do not run CI/CD or boot smokes for this lane; use `SKIP_SMOKE=1` for push hooks per instruction.
