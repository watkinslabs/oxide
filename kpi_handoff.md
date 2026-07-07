# KPI Handoff

Date: 2026-07-07

## Repository State

- Primary repo: `/home/nd/oxide/kernel`
- Active worktree: `/home/nd/oxide/worktrees/kpi-debugfs-configfs`
- Active branch: `F674-kpi-debugfs-configfs`
- Base freshness: `main` is at `origin/main` `9277e1ac` on 2026-07-07; `origin/main` was merged into `F674-kpi-debugfs-configfs` before continuing sync follow-up work.
- Work has not been pushed, PR'd, or merged.
- Keep all follow-up work in `/home/nd/oxide/worktrees/...`, not the main checkout.

## Current KPI Lane

- KPI: `F674-kpi-debugfs-configfs`
- Ledger row in `kpi_fix.md` is now `DONE`.
- The previous `PARTIAL` reason was real: configfs lacked active-operation lifetime parity and the real-module audit still showed missing configfs symbols.
- That F674-specific partial reason is now closed.

## Allocator Follow-Up

- Added Fedora 6.16-era allocation exports required by real module audits: `__kmalloc_noprof`, `__kmalloc_cache_noprof`, `__kvmalloc_node_noprof`, `alloc_pages_noprof`, `__alloc_pages_noprof`, `kvfree`, `kvfree_call_rcu`, `kmemdup_noprof`, `kmalloc_caches`, and `random_kmalloc_seed`.
- `kvfree_call_rcu` now defers the free through the existing shared RCU callback queue instead of freeing inline.
- Split allocator tests into `crates/kernel/modules/src/linux_alloc_tests.rs` to keep `linux_alloc.rs` under the 500-line cap.
- Extended `kpi/include/linux/slab.h`, `kpi/include/linux/mm.h`, and `tools/kpi-header-smoke.c` for the new allocator surface.
- Valid Fedora module audit now resolves those allocator symbols. Overall audit still exits nonzero because remaining misses are in other KPI lanes: workqueue/time, USB gadget, DMA/scatterlist, module refcounting, device/sysfs helpers, compiler/runtime helpers, and target/SCSI-specific helpers.

## Sync Follow-Up

- Added Fedora 6.16-era sync/RCU exports required by real module audits: `_raw_spin_lock_bh`, `_raw_spin_lock_irq`, `_raw_spin_lock_irqsave`, `_raw_spin_unlock_bh`, `_raw_spin_unlock_irq`, `_raw_spin_unlock_irqrestore`, `__mutex_init`, `mutex_lock_interruptible`, `sema_init`, `down`, `down_interruptible`, `down_trylock`, `up`, `wait_for_completion_interruptible`, `wait_for_completion_timeout`, `__init_waitqueue_head`, `__init_swait_queue_head`, `__wake_up`, `init_wait_entry`, `prepare_to_wait_event`, `finish_wait`, `__rcu_read_lock`, `__rcu_read_unlock`, `synchronize_rcu`, `rcu_barrier`, and `refcount_warn_saturate`.
- Added `kpi/include/linux/rcupdate.h`, `kpi/include/linux/semaphore.h`, and extended spinlock/mutex/wait/completion headers plus `tools/kpi-header-smoke.c`.
- Valid Fedora module audit no longer reports missing sync/RCU symbols for `target_core_mod`, `libcomposite`, or `industrialio-configfs`.
- `F656-kpi-linux-sync-api` remains `PARTIAL`: the current facade is still counter/spin-backed compatibility, not full Linux scheduler-backed sleeping wait-event semantics.

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
- No remaining sync/RCU missing symbols were reported for those modules after the sync follow-up; the audit reported 525 exports, 280 undefined refs, 225 unique symbols, 162 missing symbols, 0 weak-missing, and 63 exported matches.

The audit still exits nonzero overall because those same real modules require symbols in other KPI lanes, including device-core/sysfs, DMA/scatterlist, module refcounting, UBSAN/compiler runtime, workqueue/time, USB gadget, and SCSI/target-specific surfaces.
After the allocator and sync follow-ups, the remaining audit misses no longer include the modern allocator or sync/RCU symbols listed above.

## Validation Passed

From `/home/nd/oxide/worktrees/kpi-debugfs-configfs`:

- `cargo test -q -p modules linux_configfs`
- `cargo test -q -p modules linux_alloc`
- `cargo test -q -p modules linux_sync`
- `cargo test -q -p modules -- --test-threads=1`
- `cargo test -q -p vfs`
- `cc -std=gnu11 -Ikpi/include -ffreestanding -fsyntax-only tools/kpi-header-smoke.c`
- `clang -std=gnu11 -target x86_64-unknown-linux-gnu -Ikpi/include -ffreestanding -fsyntax-only tools/kpi-header-smoke.c`
- `clang -std=gnu11 -target aarch64-unknown-linux-gnu -Ikpi/include -ffreestanding -fsyntax-only tools/kpi-header-smoke.c`
- `tools/kpi-audit --fail-on-missing <decompressed Fedora target_core_mod/libcomposite/industrialio-configfs .ko files>` (expected nonzero overall; no remaining sync/RCU or debugfs/configfs missing rows)
- `cargo run -q -p xtask -- kernel --arch x86_64`
- `cargo run -q -p xtask -- kernel --arch aarch64`
- `git diff --check`
- Configfs source line-count check; all `crates/kernel/modules/src/linux_configfs/*.rs` files are under 500 lines.
- Sync source line-count check; `crates/kernel/modules/src/linux_sync.rs` is 494 lines.

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
