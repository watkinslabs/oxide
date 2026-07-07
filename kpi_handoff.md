# KPI Handoff

Date: 2026-07-07

## Repository State

- Primary repo: `/home/nd/oxide/kernel`
- Active worktree: `/home/nd/oxide/worktrees/kpi-debugfs-configfs`
- Active branch: `F674-kpi-debugfs-configfs`
- Base freshness: `git fetch origin main --prune` followed by `git merge --ff-only origin/main`; branch was already up to date with `origin/main` before the final F674 work.
- Work has not been pushed, PR'd, or merged.
- Keep all follow-up work in `/home/nd/oxide/worktrees/...`, not the main checkout.

## Current KPI Lane

- KPI: `F674-kpi-debugfs-configfs`
- Ledger row in `kpi_fix.md` is now `DONE`.
- The previous `PARTIAL` reason was real: configfs lacked active-operation lifetime parity and the real-module audit still showed missing configfs symbols.
- That F674-specific partial reason is now closed.

## F674 Implementation Summary

- Split configfs attribute VFS handling into `crates/kernel/modules/src/linux_configfs/attr.rs`.
- Added per-open configfs attr/binattr state so open files stop calling module callbacks after unregister/rmdir marks the item dead.
- Added last-close configfs binattr write flushing.
- Added configfs dependency tracking so `configfs_depend_item` pins a live item and blocks rmdir with `EBUSY` until `configfs_undepend_item`.
- Added owned formatted config item names via `config_item_set_name`.
- Added `config_item_get_unless_zero` and `configfs_remove_default_groups`.
- Exported the new configfs symbols and declared them in `kpi/include/linux/configfs.h`.
- Added `ETXTBSY` and `EFBIG` errno plumbing for configfs file behavior.
- Fixed `tools/kpi-audit` so it scans nested module source files and recognizes tuple export tables.
- Extended `tools/kpi-header-smoke.c` to exercise the new configfs prototypes.

## Real-Module Audit Result

Audit inputs:

- `/lib/modules/6.16.10-200.fc42.x86_64/kernel/drivers/target/target_core_mod.ko.xz`
- `/lib/modules/6.16.10-200.fc42.x86_64/kernel/drivers/usb/gadget/libcomposite.ko.xz`
- `/lib/modules/6.16.10-200.fc42.x86_64/kernel/drivers/iio/industrialio-configfs.ko.xz`

F674 result:

- `configfs_depend_item`: exported
- `configfs_remove_default_groups`: exported
- `configfs_undepend_item`: exported
- `config_item_get_unless_zero`: exported
- `config_item_set_name`: exported
- Existing configfs registration/init/get/put symbols remained exported.
- No remaining debugfs/configfs missing symbols were reported for those modules.

The audit still exits nonzero overall because those same real modules require symbols in other KPI lanes, including alloc, device-core, DMA/scatterlist, module refcounting, UBSAN/compiler runtime, sync, and SCSI/target-specific surfaces.

## Validation Passed

From `/home/nd/oxide/worktrees/kpi-debugfs-configfs`:

- `cargo test -q -p modules linux_configfs`
- `cargo test -q -p modules`
- `cargo test -q -p vfs`
- `cc -std=gnu11 -Ikpi/include -ffreestanding -fsyntax-only tools/kpi-header-smoke.c`
- `clang -std=gnu11 -target x86_64-unknown-linux-gnu -Ikpi/include -ffreestanding -fsyntax-only tools/kpi-header-smoke.c`
- `clang -std=gnu11 -target aarch64-unknown-linux-gnu -Ikpi/include -ffreestanding -fsyntax-only tools/kpi-header-smoke.c`
- `cargo run -q -p xtask -- kernel --arch x86_64`
- `cargo run -q -p xtask -- kernel --arch aarch64`
- `git diff --check`
- Configfs source line-count check; all `crates/kernel/modules/src/linux_configfs/*.rs` files are under 500 lines.

## Next Steps

1. Review the final diff.
2. Commit with author `Chris Watkins <chris@watkinslabs.com>` if the scope is accepted.
3. Push/open PR for `F674-kpi-debugfs-configfs`.
4. After merge, fast-forward the main checkout and remove this worktree.
5. Pick the next partial lane from `kpi_fix.md`; the broad real-module audit still points at alloc/device/DMA/module/sync gaps, not debugfs/configfs.

## Do Not Do

- Do not run `cargo fmt` or rustfmt.
- Do not revert unrelated user or other-agent changes.
- Do not work in `/home/nd/oxide/kernel` except for main fast-forward/worktree management.
