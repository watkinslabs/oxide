# B1680 — `cargo test --workspace` is not green and its failing set is unstable

Baseline: 10 sequential `cargo test --workspace --no-fail-fast` runs on `main`
(`09d4695a3`), each with a private `TMPDIR` on a non-tmpfs filesystem.

**0 of 10 runs were clean.** Red packages, by how many of the 10 runs they failed in:

| Package | Red runs | Status |
|---|---|---|
| `drv-virtio-input` | 10/10 | FIXED B1683 |
| `fbcon` | 9/10 | FIXED B1682 |
| `modules` | 5/10 | OPEN |
| `procfs` | 3/10 | OPEN |
| `klog` | 3/10 | OPEN |
| `sound` | 2/10 | OPEN |
| `netlink` | 2/10 | OPEN |
| `drv` | 2/10 | OPEN |
| `sysfs` | 1/10 | OPEN |
| `nscg` | 1/10 | OPEN |
| `fbdev` | 1/10 | OPEN |
| `drv-zram` | 1/10 | OPEN |
| `drv-virtio-gpu` | 1/10 | OPEN |
| `softirq` | (earlier run) | FIXED B1681 |
| `net` | (earlier run) | OPEN, root-caused in B1683's drop |

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| OPEN | high | `cargo test --workspace` has never been green, and every "N passed, 0 failed" claim in this repo is a per-package measurement, which the table above shows does not imply workspace green. The failing set differs on every run, so one workspace run never characterizes it either. Nothing in CI or the routine gate runs the suite to completion — the same defect class as a feature nothing compiles. | 10 runs, 0 clean, distribution above. | — |
| OPEN | high | Long tail of the same root cause, one owner per package: `modules` (`linux_string`/`linux_runtime`/`linux_pm` `export_symbols_registers_*_surface` — a global symbol registry), `procfs` (`devices_body_*` — global input records), `klog` (`concurrent_emitters_do_not_splice_lines`), `netlink` (`genetlink::tests::quota::*`), `drv` (`bus::tests::device_index::*`, `model::tests::hooks::*`), `sysfs` (`block::tests::block_uevent_*`), `nscg` (`proc_ns::setns_perm_tests::*`), `sound`, `fbdev` (`fb_ops_are_per_instance`, `register_count_roundtrip`), `drv-zram`, `drv-virtio-gpu`. Each is a process-global registry with several tests mutating it and either no lock or a per-module lock that excludes nothing. | Failing test names captured per run. | — |
| OPEN | high | The ext4 e2fsck tests write ~1.8 GB images to **fixed** `$TMPDIR` names (`balloc_concurrent_repro.img`, `balloc_uninit_repro.img`, `arm_hwdb_framecache_repro.img`, `arm_hwdb_rewrite_repro.img`, built via `format!("{}/…", std::env::temp_dir())`). Two concurrent workspace runs — or two lanes on this box — collide on the same file, and every run leaves ~7 GB behind. This filled the shared 32 GB `/tmp` tmpfs to 100% during the first baseline attempt, which failed the ext4 tests, aborted 8 of 10 runs, and broke the agent harness's own output files. Same defect class as the rest of this lane, in the filesystem namespace. | `crates/kernel/ext4/tests/balloc_uninit_e2fsck.rs:136,208`; `/tmp` at 100% with four `*_repro.img` totalling ~7.2 GB. | — |
| OPEN | med | Once the suite is green, a completed `cargo test --workspace` belongs in the routine gate alongside `make feature-gate`. Wiring it before then would only add a permanently-red gate. | — | — |
