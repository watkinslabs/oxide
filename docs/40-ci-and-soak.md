# 40 CI + Soak

FROZEN 2026-05-02. Dep:`02`,`05`,`07`,`39`,`42`,`08`.

PR-time CI = phase gate. Soak = continuous background diagnostic, NOT gate. Single soak box; v1 release waits 168h on `main`. Else: bugs found by soak file as tickets, don't block phase advance.

## 1 Frozen invariants

1. PR cannot merge without green PR-time CI on both arches.
2. CI calls `xtask` only; no direct cargo invocations in CI scripts.
3. Soak artifacts (signed Ed25519: commit, arch, duration, seed, exit) under `soak-artifacts/`. Continuous on `main`; not phase-gating.
4. v1 release tag requires a 168h soak artifact for the tagged commit on each arch (`00§15`).
5. Perf regression >5% on `04§1` hot-path budgets fails CI unless commit has `Performance-Regression-Justification:` trailer.
6. Build env = pinned Docker image (digest, not tag). Image hash in CI logs.

## 2 PR-time CI (≤5 min wall, both arches)

Runs on every PR. THE phase gate.

| Job | Cmd | Budget |
|---|---|---|
| build-kernel-{x86_64,aarch64}-release | `xtask kernel --arch X --profile release` | 90s |
| build-kernel-{x86_64,aarch64}-dev | `--profile dev` | 60s |
| build-user-{x86_64,aarch64} | `xtask user --arch X` | 60s |
| build-image-{x86_64,aarch64} | `xtask image --arch X` | 30s |
| qemu-smoke-{x86_64,aarch64} | `xtask qemu --arch X --headless --timeout 60s --expect "init started"` | 60s |
| test-hosted | `xtask test --hosted` (incl 10M-op proptests) | 4min |
| test-loom | `xtask test --loom` | 3min |
| test-miri | `xtask test --miri` | 5min |
| test-canary-1h | `xtask test --canary --duration 1h` | 1h |
| spec-lint | `xtask spec-lint` | 10s |
| doc-check | `xtask doc-check` | 10s |
| clippy | `cargo clippy --all-targets -- -D warnings` | 60s |
| deny | `cargo deny check` | 30s |
| bench-vs-history | bench; compare `bench-history/main`; fail >5% regress | 3min |
| coverage-gate | per-crate ≥95% on critical (`pmm`,`slab`,`vmm`,`sched`,`vfs`); ≥80% HAL | 1min |

Parallel where independent. Total wall ≤ 5min for fast jobs + canary 1h running concurrently. PR can merge as soon as fast jobs + canary all green.

## 3 Background soak (continuous, not gating)

Runs on **single soak box** against `main`. Each cycle:
1. Pull latest `main` Docker image.
2. Run a workload picked from rotation (pmm-mix, slab-mix, sched-canary, fs-stress, net-loopback, build-self).
3. Duration: 4h default; 24h on weekends.
4. Emit signed artifact regardless of result.
5. Failure → file GitHub issue with workload, commit, seed, panic msg, last-1MB serial log.

Bugs found = tickets. Tickets are worked when found. **Phase advance does NOT wait.** Spec-discipline (`02§3`) handles drift: bug → revise spec or fix code under PR-time gates.

Workload rotation per `tests/soak/<name>/` (`42§9`).

## 4 v1 release tag CI

`release.yml` triggered on tag push. Verifies:
1. Latest soak artifact for this commit, both arches, duration ≥ 168h, exit==0.
2. All v1 acceptance scenarios (`43§5`) green on tag.
3. SHA-256 reconciles fs_mark corpus.

If artifact absent: tag rejected; soak must complete first. Only place we wait.

## 5 Soak runner (`tools/soak-runner/`)

- Spawns QEMU w/ workload binary in initramfs.
- Streams serial to file.
- After duration: SIGTERM QEMU; wait clean exit or SIGKILL after 30s.
- Parse exit code + last-N-lines.
- Emit `soak-artifacts/<commit>-<workload>-<arch>-<duration>h.json`: `{commit, workload, arch, seed, start_time, duration_s, exit_code, panics, oopses, injected_faults_caught, image_sha256}`. Signed Ed25519.

## 6 Bench history

`bench-history/main/<commit>.json`: per-bench median+p99 cycles. Pruned to last 90d + version tags.

`tools/perfrunner/` cycle-accurate timing (`rdtsc`/`cntvct`), 1000 iters/op, 5 trials.

PR bench job: rerun, compare last `main` commit; fail >5% p99 regress on any `04§1` hot path.

## 7 Concurrency

CI jobs parallel where independent. Soak box runs 1 QEMU at a time (no concurrency on hardware).

## 8 Docker image (build env)

Two images. Both built once per Dockerfile change (workflow `dockerfile.yml`); pushed to `ghcr.io/<org>/oxide2-{build,soak}:<dockerfile-sha>`. CI pulls; never rebuilds per PR.

### 8.1 `Dockerfile.build`

Base: `debian:trixie@sha256:<digest>` (digest-pinned).
Layers:
- nightly rustc per `rust-toolchain.toml` + `rust-src` + `rustfmt` + `clippy` + `miri` + `llvm-tools-preview`.
- `qemu-system-{x86_64,aarch64}`.
- EDK2/OVMF firmware (x86_64) + `qemu-efi-aarch64`.
- `mtools`, `sgdisk`, `zstd`, `cpio` (image building).
- `cargo-deny`, `cargo-tarpaulin`, `cargo-fuzz`.
- `git`, `curl`, `make`.

Multi-stage to keep final image lean.

### 8.2 `Dockerfile.soak`

`Dockerfile.build` + `linux-perf` + `flamegraph` + `tools/soak-runner/` binary as ENTRYPOINT.

## 9 GitHub workflows (`.github/workflows/`)

| File | Trigger | Action |
|---|---|---|
| `pr.yml` | PR opened/updated | §2 matrix; gates merge |
| `bg-soak.yml` | cron `*/4h` | self-hosted runner pulls main, runs §3 cycle, files issue on fail |
| `release.yml` | tag push | §4 verification |
| `dockerfile.yml` | push touching `tools/docker/` | rebuilds + pushes images to ghcr |
| `weekly.yml` | cron Sunday | toolchain-bump dry-run; `cargo deny advisories`; coverage report archive |

## 10 Runners

- PR-time: GHA hosted (`ubuntu-latest` x86, `ubuntu-24.04-arm` aarch64). Native arm; no qemu-emulation of arm runner.
- Background soak: 1 self-hosted box labeled `soak`. Linux + KVM + `actions/runner` agent. Hardware floor: 8 cores, 32 GB RAM, 200 GB SSD. Both arches via QEMU+KVM (x86) and QEMU-tcg (arm-on-x86 for soak; bench numbers on this box not used for arm bench-history).
- Bench-history arm cycles: nightly job runs on a separate ARM runner (rented hourly when needed) to capture true cycle counts.

## 11 Test contract (frozen)

- PR adding `static mut FOO`: build fails (`07§5`).
- PR regressing `pmm.alloc(0)` p99 ≥10%: CI fails.
- PR adding new spec without `MANIFEST.md` entry: `doc-check` fails.
- Soak finding files GitHub issue automatically; ticket labeled `soak-found`.
- v1 tag with no 168h soak artifact: `release.yml` rejects.
- Docker image build artifact has SHA-256 in CI log every run.

## 12 Failure modes

- Soak box offline: cron job logs missed; non-blocking (it's diagnostic). Slack/email alert if down >24h.
- Bench-history corrupted: rebuild from last good commit's recorded values.
- GHA hosted runner OOM during build: bump runner size to `ubuntu-latest-8core` (paid). Rare; kernel build fits in 7 GB.

## 13 Debug

CI artifacts (90d retention): full serial log on QEMU jobs, kernel ELF + split debuginfo on build jobs, full bench output on bench job. Failed soak: tarball serial + `dmesg` + final task list.

## 14 Cross-spec

`02§1` (PR-time CI is freeze prerequisite, not soak), `05§D2`/`§G2` (single-machine v1 exit), `39§5` (image format), `42` (test patterns), `43§5` (acceptance scenarios).

## 15 Changelog

(none)

