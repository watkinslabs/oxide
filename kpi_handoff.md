# KPI Handoff

Date: 2026-07-07

## Repository State

- Primary repo: `/home/nd/oxide/kernel`
- Active worktree: `/home/nd/oxide/worktrees/kpi-debugfs-configfs`
- Active branch: `F674-kpi-debugfs-configfs`
- Base freshness: `main` is at `origin/main` `9277e1ac` on 2026-07-07; `origin/main` was fetched again before the DMA/scatterlist and string/runtime follow-ups and remained current.
- Work has not been pushed, PR'd, or merged.
- Keep all follow-up work in `/home/nd/oxide/worktrees/...`, not the main checkout.

## Current KPI Lane

- KPI: `F674-kpi-debugfs-configfs`
- Ledger row in `kpi_fix.md` is now `DONE`.
- The previous `PARTIAL` reason was real: configfs lacked active-operation lifetime parity and the real-module audit still showed missing configfs symbols.
- That F674-specific partial reason is now closed.

## Allocator Follow-Up

- Added Fedora 6.16-era allocation exports required by real module audits: `__kmalloc_noprof`, `__kmalloc_cache_noprof`, `__kvmalloc_node_noprof`, `alloc_pages_noprof`, `__alloc_pages_noprof`, `kvfree`, `kvfree_call_rcu`, `kmemdup_noprof`, `kmalloc_caches`, and `random_kmalloc_seed`.
- Added the remaining real-module slab-cache allocation exports: `__kmem_cache_create_args`, `kmem_cache_alloc_noprof`, `kmem_cache_free`, `kmem_cache_destroy`, and `vzalloc_noprof`.
- `__kmem_cache_create_args` now records object size, requested alignment, and constructor metadata; `kmem_cache_alloc_noprof` allocates owned objects through the shared allocator and invokes the registered constructor; `kmem_cache_free`/`kmem_cache_destroy` release object/cache ownership.
- `kvfree_call_rcu` now defers the free through the existing shared RCU callback queue instead of freeing inline.
- Split allocator tests into `crates/kernel/modules/src/linux_alloc_tests.rs` to keep `linux_alloc.rs` under the 500-line cap.
- Split slab-cache compatibility into `crates/kernel/modules/src/linux_alloc_cache.rs` to keep `linux_alloc.rs` under the 500-line cap.
- Extended `kpi/include/linux/slab.h`, `kpi/include/linux/mm.h`, and `tools/kpi-header-smoke.c` for the new allocator surface.
- Valid Fedora module audit now resolves those allocator symbols. Overall audit still exits nonzero because remaining misses include real `vmap`/`vunmap` page-table alias support plus other KPI lanes: workqueue/time, USB gadget, module refcounting, device/sysfs helpers, compiler/runtime helpers, and target/SCSI-specific helpers.

## CRC Follow-Up

- Added Linux T10-DIF CRC exports required by Fedora 6.16 `target_core_mod`: `crc_t10dif_arch` and the matching `crc_t10dif_generic`.
- Added `kpi/include/linux/crc-t10dif.h` with Linux-shaped `crc_t10dif_arch`, `crc_t10dif_generic`, `crc_t10dif_update`, and `crc_t10dif` declarations.
- The implementation uses the T10-DIF polynomial `0x8BB7` and is covered by the standard `"123456789"` known vector `0xD0DB`.
- Valid Fedora module audit now resolves the `crc_t10dif_arch` reference; no `MISSING | crypto-random-crc` rows remain for `target_core_mod`, `libcomposite`, or `industrialio-configfs`.

## Sync Follow-Up

- Added Fedora 6.16-era sync/RCU exports required by real module audits: `_raw_spin_lock_bh`, `_raw_spin_lock_irq`, `_raw_spin_lock_irqsave`, `_raw_spin_unlock_bh`, `_raw_spin_unlock_irq`, `_raw_spin_unlock_irqrestore`, `__mutex_init`, `mutex_lock_interruptible`, `sema_init`, `down`, `down_interruptible`, `down_trylock`, `up`, `wait_for_completion_interruptible`, `wait_for_completion_timeout`, `__init_waitqueue_head`, `__init_swait_queue_head`, `__wake_up`, `init_wait_entry`, `prepare_to_wait_event`, `finish_wait`, `__rcu_read_lock`, `__rcu_read_unlock`, `synchronize_rcu`, `rcu_barrier`, and `refcount_warn_saturate`.
- Added `kpi/include/linux/rcupdate.h`, `kpi/include/linux/semaphore.h`, and extended spinlock/mutex/wait/completion headers plus `tools/kpi-header-smoke.c`.
- Valid Fedora module audit no longer reports missing sync/RCU symbols for `target_core_mod`, `libcomposite`, or `industrialio-configfs`.
- `F656-kpi-linux-sync-api` remains `PARTIAL`: the current facade is still counter/spin-backed compatibility, not full Linux scheduler-backed sleeping wait-event semantics.

## DMA/Scatterlist Follow-Up

- Added real-module scatterlist exports required by Fedora 6.16 `target_core_mod`: `sg_alloc_table`, `sg_free_table`, `sg_copy_to_buffer`, `sg_miter_start`, `sg_miter_next`, `sg_miter_stop`, `sgl_alloc_order`, and `sgl_free_n_order`.
- `sg_init_table`, `sg_set_buf`, `sg_set_page`, and `sg_next` now preserve and honor the Linux `SG_END` marker so finite SG arrays do not walk past their last entry.
- `sg_copy_to_buffer` and `sg_miter_*` walk real CPU-addressable buffer/page-backed entries. `sgl_alloc_order` allocates page-backed SG entries and `sgl_free_n_order` releases the owned pages and table.
- Split DMA tests into `crates/kernel/modules/src/linux_dma_tests.rs` and moved SGL helpers into `crates/kernel/modules/src/linux_dma_sgl.rs` so `linux_dma.rs` stays under the 500-line cap.
- Extended `kpi/include/linux/scatterlist.h`, `tools/kpi-header-smoke.c`, and the audit classifier for SGL symbols.
- Valid Fedora module audit no longer reports any missing DMA/scatterlist symbols for `target_core_mod`, `libcomposite`, or `industrialio-configfs`.

## String/Runtime Follow-Up

- Added focused `crates/kernel/modules/src/linux_string/` helpers and `kpi/include/linux/string.h`.
- Exported real byte/string helpers required by Fedora 6.16 real-module audits: `memcpy`, `memset`, `memcmp`, `memcpy_and_pad`, `strlen`, `strnlen`, `strcmp`, `strncmp`, `strncasecmp`, `strcpy`, `strncpy`, `strchr`, `strstr`, `strsep`, `strim`, and `sized_strscpy`.
- Exported conversion helpers: `hex_to_bin`, `hex2bin`, `bin2hex`, `simple_strtoul`, `kstrtobool`, `kstrtoint`, `kstrtou8`, `kstrtou16`, `kstrtouint`, and `kstrtoull`.
- Exported bounded printf helpers: `snprintf`, `scnprintf`, `sprintf`, `_printk`, `printk`, and `__warn_printk`.
- Exported runtime support symbols: `__stack_chk_fail`, `__fortify_panic`, `__fentry__`, `_ctype`, and `__ref_stack_chk_guard`.
- Updated `tools/kpi-audit` to classify these as `string-runtime`, and extended `tools/kpi-header-smoke.c` to compile common call sites.
- Valid Fedora module audit no longer reports any missing `string-runtime` rows for `target_core_mod`, `libcomposite`, or `industrialio-configfs`.

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
- No remaining sync/RCU missing symbols were reported for those modules after the sync follow-up; that audit reported 525 exports, 280 undefined refs, 225 unique symbols, 162 missing symbols, 0 weak-missing, and 63 exported matches.
- After the DMA/scatterlist follow-up, the audit reported 533 exports, 280 undefined refs, 225 unique symbols, 154 missing symbols, 0 weak-missing, and 71 exported matches.
- Exported DMA/scatterlist matches now include `sg_alloc_table`, `sg_copy_to_buffer`, `sg_free_table`, `sg_init_table`, `sg_miter_next`, `sg_miter_start`, `sg_miter_stop`, `sgl_alloc_order`, and `sgl_free_n_order`.
- After the string/runtime follow-up, the audit reported 570 exports, 280 undefined refs, 225 unique symbols, 118 missing symbols, 0 weak-missing, and 107 exported matches.
- Exported `string-runtime` matches now cover 34 real-module references; no `MISSING | string-runtime` rows remain.
- After the slab-cache allocator follow-up, the audit reported 575 exports, 280 undefined refs, 225 unique symbols, 113 missing symbols, 0 weak-missing, and 112 exported matches.
- Exported allocator matches now include `__kmem_cache_create_args`, `kmem_cache_alloc_noprof`, `kmem_cache_destroy`, `kmem_cache_free`, and `vzalloc_noprof`; remaining allocator misses are `vmap` and `vunmap`, which were not stubbed because the current module layer lacks a real vmalloc VA/page-table alias primitive.
- After the CRC follow-up, the audit reported 577 exports, 280 undefined refs, 225 unique symbols, 112 missing symbols, 0 weak-missing, and 113 exported matches.
- Exported `crypto-random-crc` matches now include `crc_t10dif_arch`; no `MISSING | crypto-random-crc` rows remain.

The audit still exits nonzero overall because those same real modules require symbols in other KPI lanes, including device-core/sysfs, module refcounting, UBSAN/compiler runtime, x86 retpoline thunks, workqueue/time, USB gadget, and SCSI/target-specific surfaces.
After the allocator, sync, DMA/scatterlist, string/runtime, and CRC follow-ups, the remaining audit misses no longer include the modern allocator slab-cache symbols, sync/RCU, DMA/scatterlist, string/runtime, or crypto-random-crc symbols listed above. Real `vmap`/`vunmap` remain allocator work.

## Validation Passed

From `/home/nd/oxide/worktrees/kpi-debugfs-configfs`:

- `cargo test -q -p modules linux_configfs`
- `cargo test -q -p modules linux_alloc`
- `cargo test -q -p modules linux_sync`
- `cargo test -q -p modules linux_dma`
- `cargo test -q -p modules linux_string`
- `cargo test -q -p modules linux_crypto::crc`
- `cargo test -q -p modules -- --test-threads=1`
- `cargo test -q -p vfs`
- `cc -std=gnu11 -Ikpi/include -ffreestanding -fsyntax-only tools/kpi-header-smoke.c`
- `clang -std=gnu11 -target x86_64-unknown-linux-gnu -Ikpi/include -ffreestanding -fsyntax-only tools/kpi-header-smoke.c`
- `clang -std=gnu11 -target aarch64-unknown-linux-gnu -Ikpi/include -ffreestanding -fsyntax-only tools/kpi-header-smoke.c`
- `tools/kpi-audit --fail-on-missing <decompressed Fedora target_core_mod/libcomposite/industrialio-configfs .ko files>` (expected nonzero overall; no remaining allocator slab-cache, sync/RCU, DMA/scatterlist, string/runtime, or debugfs/configfs missing rows)
- `tools/kpi-audit --fail-on-missing <decompressed Fedora target_core_mod/libcomposite/industrialio-configfs .ko files>` after slab-cache allocator follow-up (expected nonzero overall; allocator missing rows reduced to real `vmap`/`vunmap` only)
- `tools/kpi-audit --fail-on-missing <decompressed Fedora target_core_mod/libcomposite/industrialio-configfs .ko files>` after CRC follow-up (expected nonzero overall; 577 exports, 112 missing, 113 exported matches, and no remaining `crypto-random-crc` missing rows)
- `cargo run -q -p xtask -- kernel --arch x86_64`
- `cargo run -q -p xtask -- kernel --arch aarch64`
- `git diff --check`
- Configfs source line-count check; all `crates/kernel/modules/src/linux_configfs/*.rs` files are under 500 lines.
- Sync source line-count check; `crates/kernel/modules/src/linux_sync.rs` is 494 lines.
- DMA source line-count check: `linux_dma.rs` is 452 lines, `linux_dma_sgl.rs` is 52 lines, `linux_dma_tests.rs` is 96 lines.
- Allocator source line-count check after slab-cache split: `linux_alloc.rs` is 469 lines, `linux_alloc_cache.rs` is 74 lines, and `linux_alloc_tests.rs` is 135 lines.
- String/runtime line-count check: `linux_string.rs` is 23 lines; child files are 210 lines or less.
- CRC source line-count check: `linux_crypto/crc.rs` is 128 lines.

## Next Steps

1. Review the final diff.
2. Commit with author `Chris Watkins <chris@watkinslabs.com>` if the scope is accepted.
3. Push/open PR for `F674-kpi-debugfs-configfs`.
4. After merge, fast-forward the main checkout and remove this worktree.
5. Pick the next partial lane from `kpi_fix.md`; the broad real-module audit still points at device-core/sysfs, module refcounting, UBSAN/compiler runtime, x86 retpoline thunks, workqueue/time, USB gadget, SCSI/target helpers, and other runtime symbols, not debugfs/configfs, DMA/scatterlist, or string/runtime helpers.

## Do Not Do

- Do not run `cargo fmt` or rustfmt.
- Do not revert unrelated user or other-agent changes.
- Do not work in `/home/nd/oxide/kernel` except for main fast-forward/worktree management.
