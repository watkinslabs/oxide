# What in this repo is not the kernel

Decision document. This repo is supposed to be the kernel; image and rootfs
composition moved to the sibling `../images` repo, which composes a Fedora
userspace from RPMs. This inventory says what is left behind that does not
belong, so the owner can decide what moves, what dies, and what stays.

**Nothing here is a deletion.** Every row needs an owner's call first. Rows carry
a Status and Branch column per the plan convention.

Buckets:

| Bucket | Meaning |
|---|---|
| **1 — kernel** | Compiles the kernel, or produces/boots the ISO the dev loop uses. Stays. |
| **2 — image** | Builds or stages a userspace. Belongs in `../images` (or its own repo) even if something here currently calls it. |
| **3 — dead** | No consumer of any kind. |

Method: `git ls-files` + `wc -l` on tracked files; consumers traced by grepping
`Makefile`, `tools/*.sh`, `.github/workflows/`, `.githooks/`, and every
`Cargo.toml`. Claims marked UNSURE were not resolved and must not be acted on
without checking.

## 1 Headline

| # | Finding | Evidence |
|---|---|---|
| H1 | **No kernel crate depends on any `crates/user/*` crate.** ~54.8k Rust LOC is not in the kernel binary's dependency tree at all. The only reverse edges are intra-family (`pam`→`nss`, `pkg`→`rpm`, `glibc`→`nss`) plus one host-tool edge, `tools/xtask/Cargo.toml` → `crates/user/ldso` (feature `hosted`). | Grep of every `Cargo.toml` for `crates/user/*` path deps returns exactly `crates/user/pam`, `crates/user/pkg`, `tools/xtask`. |
| H2 | **The `glibc`/`sysroot`/`ldso`/`folded` xtask family has zero automated callers** — not in `Makefile`, `tools/*.sh`, CI, or the git hooks. 908 LOC of xtask driving ~52k LOC of `crates/user/{glibc,ldso,folded-stub,crt1}`. Only `glibc-test` has one caller. | `tools/oxide-conformance-ssh.sh:226` is the single hit for the whole family. |
| H3 | **`xtask rootfs` already delegates to `../images`.** `rootfs_glibc.rs` is a 63-line `cp --reflink=auto ../images/output/<profile>-<arch>-root.img`. The composition move already happened; what remains around it is leftovers. | `tools/xtask/src/rootfs_glibc.rs`. |
| H4 | **The boot-smoke probe story is half-migrated.** ~20 `tools/boot-smoke-*.sh` grep for `/bin/<name>_probe: PASS`, but only 6 probes have an injector in `rootfs_disks/`, and `../images` carries no probe sources. Either a staging path exists that this audit missed, or those smokes have been decorative. **This is the one blocking unknown.** | Injectors present: `af_packet_diff`, `wait_diff`, `request_key`, `swapfile`, `drm_probe`, `gnome_input_classify`. |
| H5 | `kpi/` (3,793) + `tools/kpi-header-smoke.c` (1,573) + `tools/kpi-audit` (290) = **~5.6k LOC with no consumer.** The one apparent hit is a false positive: a `b"kpi/input0\0"` device-phys byte string in `linux_input/core/test_constants.rs`, unrelated to the directory. | Verified by hand. |

## 2 Biggest non-kernel chunks

| Status | Rank | Chunk | LOC | Bucket | Branch |
|---|---:|---|---:|---|---|
| OPEN | 1 | `crates/user/glibc/` — from-scratch Rust glibc | 49,413 | 2 | — |
| OPEN | 2 | `userspace/` (393 files, 133 dirs) — splits three ways, see §4 | 29,538 | 1/2/3 | — |
| OPEN | 3 | `crates/user/ldso/` — glibc-ABI dynamic linker | 2,994 | 2 | — |
| OPEN | 4 | `kpi/` — Linux-shaped headers for out-of-tree module compat | 3,793 | 3 | — |
| OPEN | 5 | `crates/user/{svc,rpm,pkg,dl,obs,nss,pam,crt1,folded-stub}` | 2,363 | 2 | — |
| OPEN | 6 | `tools/kpi-header-smoke.c` | 1,573 | 3 | — |
| OPEN | 7 | `tools/xtask/src/{glibc,sysroot,ldso,folded,glibc_test}.rs` | 908 | 2 | — |
| OPEN | 8 | `tools/oxide-conformance-ssh.sh` + `test-conformance-preqemu-result.sh` | 664 | 2 | — |
| OPEN | 9 | `crates/shared/{cpio,inflate}` — orphaned if `pkg` goes | 526 | 2 | — |
| OPEN | 10 | `tools/xtask/src/rootfs_disks/{gnome_input_classify,mutter_debug}.rs` | 490 | 2 | — |
| OPEN | 11 | `tools/kpi-audit` | 290 | 3 | — |

**Rollup:** `crates/user/` = 54,770 LOC, of which **0 reaches the kernel binary**.
With the bucket-2 slice of `userspace/` (~10.5k) and the xtask glibc family (908),
roughly **66k LOC exists solely to build a userspace `../images` now composes from
Fedora RPMs**. Separately ~**5.9k LOC** has no consumer of any kind.

## 3 xtask command surface

`main.rs` dispatch; xtask totals 5,235 LOC.

| Status | Command | LOC | Bucket | Consumer | Branch |
|---|---|---:|---|---|---|
| KEEP | `kernel` | ~120 | 1 | `Makefile`, CI build-kernel | — |
| KEEP | `grub` / `image` | 1,061 | 1 | `Makefile`, `boot-smoke.sh`, qemu-mcp | — |
| KEEP | `rootfs` (copy from `../images`) | 93 | 1 | `cmds.rs` ensure_blobs, `Makefile` | — |
| KEEP | `artifacts` | 176 | 1 | `Makefile`. **The correct kernel↔images seam — keep and strengthen.** | — |
| KEEP | `test`, `gc`, `path`, `spec-lint`, `doc-check` | ~350 | 1 | `Makefile`, CI | — |
| MIXED | `rootfs` disk/probe injection | 1,659 | 1 mostly; 490 is 2 | Env-gated `OXIDE_*_SMOKE` | — |
| OPEN | `glibc` | 170 | 2 | **none** | — |
| OPEN | `sysroot` | 194 | 2 | **none** | — |
| OPEN | `ldso` | 196 | 2 | **none**; not even in `usage()` | — |
| OPEN | `folded` | 101 | 2 | **none**; not in `usage()` | — |
| OPEN | `glibc-test` | 247 | 2 | `oxide-conformance-ssh.sh:226` only | — |
| OPEN | `stats` | ~630 | 3-adjacent | `Makefile` `make stats` | C251 (reworked) |
| OPEN | `user`, `soak`, `bench` | 3 lines | 3 | Stubs printing "not yet implemented" | — |
| OPEN | `qemu` | 0 | 3 | **Advertised in `usage()` but has no dispatch arm** — the help text lies | — |

## 4 `userspace/` splits three ways

| Status | Population | LOC | Bucket | Note |
|---|---|---:|---|---|
| KEEP | (a) Kernel smoke probes with a live injector | ~7.7k | 1 | `af_packet_diff` 2,034; `wait_diff` 4,640; `drm_probe` 197; `swapfile_probe` 211; `request_key_probe` 60 |
| **UNSURE** | (b) Probes a `boot-smoke-*.sh` greps for, with **no staging mechanism found** | ~3.5k | 1 intended | `vsock_probe`, `sysblock_probe`, `sysbus_bind_probe`, `storage_multictrl_probe`, `uart_rebind_probe`, `ps2_rebind_probe`, `msix_net_rx_probe`, `virtio_*_multidev_probe`, `uevent_probe`, `shutdown_probe`, … **Resolve before acting.** |
| OPEN | (c) Userspace-platform test material | ~10.5k | 2 | `glibc_conformance/` alone is 9,355 LOC / 219 `t_*.c`, consumed only by `xtask glibc-test`. Tests our libc, not the kernel. |
| OPEN | (d) No consumer anywhere (23 dirs) | — | 3 | `drm_probe3`, `fbdev_probe2`, `g19_glibc_*`, `keymaps`, `login_sim`, `pamtest`, `mtmalloc_smoke`, … |
| OPEN | (e) ~30 library-presence probes | — | 2 | `openssl_probe`, `zstd_probe`, `libcap_probe`, `libseccomp_probe`, `dbus_probe`, … "does the image contain library X" is an image assertion. |

## 5 Repo-root junk

| Status | Path | Size | What it is | Branch |
|---|---|---|---|---|
| OPEN | `vm_ops` | 0 B | Empty tracked file — an accidental `touch` | — |
| OPEN | `h` | 568 B | Raw ANSI-colored `git branch` output — a `git branch > h` typo, committed | — |
| OPEN | `again.ms` | 5.7 KB | Boot investigation notes dated 2026-07-10; belongs in `scratch/` if kept | — |
| OPEN | `jizzo.md` | 7.6 KB | Session hand-off note, duplicate role of `state.md` | — |
| OPEN | `work/` | — | Accidentally committed boot tree — **includes a committed kernel ELF binary** (`boot-live-gnome-x86_64/boot/oxide-x86_64`) | — |
| OPEN | `tools/xtask/src/assets/oxide-smokes.sh` | ~5 KB | In-guest smoke runner; not `include_str!`d, not referenced anywhere | — |
| KEEP | `AGENTS.md` | 233 B | Points other agents at CLAUDE.md | — |
| KEEP | `state.md`, `project-stats.md` | — | Process doc; generated stats artifact (`make stats`) | — |

Unverified, no caller found — check by hand before removing, they are plausible
manual tools: `tools/accept.py` (202), `tools/syscall-audit.py` (144),
`tools/test-arm-mprotect-debug-features.sh` (66).

## 6 Suggested order

| Status | Step | What | Branch |
|---|---|---|---|
| OPEN | 0 | **Resolve H4 first.** Run `make smoke-sysblock-x86` / `make smoke-vsock-x86`. Pass ⇒ a staging path exists, find it and classify §4(b) as bucket 1. Fail/hang ⇒ those smokes are decorative and that is a real bug. Everything else is independent of the answer except the §4 split. | — |
| OPEN | 1 | Free deletions, no design needed: `kpi/` + `kpi-header-smoke.c` + `kpi-audit`, `oxide-smokes.sh`, the root junk in §5, the `qemu` usage-string lie, the three `user`/`soak`/`bench` stubs. ~5.9k LOC. | — |
| OPEN | 2 | **The real decision: is writing our own glibc still a goal?** If no, `crates/user/{glibc,ldso,folded-stub,crt1}` + `glibc_conformance/` + the xtask glibc family + `docs/59` all go — the largest reduction available, zero effect on the kernel build. If yes, it is still a userspace libc and belongs in its own repo, not here and not in `../images`. Do not split the difference; 52k LOC with no automated caller is the worst version. | — |
| OPEN | 3 | Move to `../images`: `crates/user/{rpm,pkg,svc}` + orphaned `crates/shared/{cpio,inflate}`; `rootfs_disks/{gnome_input_classify,mutter_debug}`; the library-presence probes; spec text in `docs/29`, `29a`, `39`, `51`. | — |
| OPEN | 4 | Settle `crates/user/obs` (378). It depends on `hal`/`klog`/`sync` — a kernel shape — and `docs/37` is the observability spec. Likely misfiled kernel code that was never wired up, not userspace. One read decides promote-or-delete. | — |

Explicitly not touching: `xtask artifacts` and `rootfs_glibc.rs`. Those are the
kernel↔images seam and it already works; the leftovers around it are the problem.
