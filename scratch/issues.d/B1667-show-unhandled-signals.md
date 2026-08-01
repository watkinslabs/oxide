# B1667 — unhandled-fault report

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| FIXED B1667 | high | No unhandled-signal report in the kernel log: a user-mode fault that killed a task printed nothing on a normal build. The register dump in the user-fault path is gated behind `debug-irq`, which also turns on the timer-tick flood, so naming a faulting instruction cost a rebuild plus a boot. The reference prints one line per unhandled fault by default (`show_unhandled_signals`, `debug/exception-trace`). | B1667 adds it: `<comm>[<pid>]: segfault at <addr> ip <ip> sp <sp> error <err> tid <tid> in <exe> vma <start>+<len> ino <ino> off <off>`, rate-limited 10 per 5 s, screened by the reference's `unhandled_signal()` ladder. 10 hosted tests in `sched::signal_report`. | B1667 |
| OPEN | med | The report's `print_vma_addr` tail names the backing INODE, not a path — `mm-vmm`'s `FileBacking` exposes `ino()` and no name. Resolving it needs `find /usr -inum N` in the guest. A path would make the line self-contained. | B1667. | — |

## Evidence carried over from the B1663 triage (SIGSEGV lane)

The GTK4 Vulkan SIGSEGV that motivated this report narrows further than the
merged ledger row records. All from ONE live-gnome boot:

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| OPEN | high | The GTK4 Vulkan SIGSEGV is caused by ONE mesa ICD, `powervr_mesa` — not by the ICD count and not by the DRM device. ANY pair containing it faults (`lvp+powervr` 139, `panfrost+powervr` 139); pairs without it are clean (`lvp+virtio` 124); the driver ALONE is clean (124). Adding it to a clean set of seven flips that set to 139, adding `panfrost` instead does not. An alternate set of NINE without it survives, so it is not a count threshold. `chmod 000 /dev/dri/renderD128` does NOT prevent the fault, so the render node and every DRM ioctl are ruled out. `NODEVICE_SELECT=1` does not help, so `VK_LAYER_MESA_device_select` is ruled out. | B1663 in-guest bisect: 11 single-ICD runs, five set sizes, an alternate-nine control, two eight-ICD runs, a trio, two pairs, one render-node-denied run. | — |
| OPEN | high | What is unique about `powervr_mesa`: it is the only ICD whose `DT_NEEDED` list carries `libpowervr_rogue.so`, and that library (present, 9.4 MB) is the only one in the set with a LARGE `PT_TLS` segment — `p_memsz 0x1100` (4352 B) of zero-init TLS. `libvulkan_radeon.so` also has `PT_TLS` but only 0x30 (48 B) and does not fault; `lvp`, `virtio`, `intel`, `panfrost` and `powervr_mesa` itself have none. 4352 B is far past glibc's static-TLS surplus, so this is the one `dlopen` in the whole enumeration that forces the heavy TLS path (static-surplus placement or DTV growth) in an already-multithreaded process. Program-header shape, alignment and `GNU_PROPERTY` are otherwise identical across all of these libraries. | B1663, `readelf -lW` / `readelf -dW` on the libraries extracted from the image. Hypothesis, not yet confirmed against a faulting `ip`. | — |

## Pre-existing break found while gating this branch

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| OPEN | blocker | `net` does not compile without its `hosted` feature: nine errors, all `could not find X in the crate root` for modules gated `any(target_os = "oxide-kernel", test, feature = "hosted")` (`sock_opts`, and the `use` chain around it). Any crate that depends on `net` and is tested on its own — `cargo test -p procfs` — therefore fails to build. Arrived on `main`, not from this branch: `cargo check -p procfs` was clean in this worktree BEFORE merging `origin/main` and fails immediately after, and B1667 touches no `net` file. | B1667, `cargo test -p procfs` at `origin/main` = `80e6adf05`: `error: could not compile net (lib) due to 9 previous errors`. Both kernel targets still build, because there the `target_os` arm of the gate is live — only the hosted build is broken. | — |
