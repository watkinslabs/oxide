# 44 Phase Quick Reference

DRAFT 2026-05-05. Dep:`00`,`40`,`43`.

## 1 Phase gate

| Gate | Required |
|---|---|
| Phase advance | PR-time CI green, bench within budget, coverage gate met (`00§3`,`40§2`) |
| v1 release tag | PR-time CI green on tag + `43§2` acceptance binaries pass + audit no-regression (`00§15`,`40§3`) |

## 2 Implementation phases (v1 path)

| Phase | Includes | Primary specs |
|---|---|---|
| 0 | Build infra: `xtask`, targets, hello-world boot, CI, Docker image | `07`,`39`,`40` |
| 1 | PMM: buddy, bitmap-truth, oracle diff | `10` |
| 2 | VMM + MMU bring-up, per-CPU areas, TLB shootdown | `11`,`20`,`21` |
| 3 | Slab allocator + `GlobalAlloc` wiring | `12` |
| 4 | Scheduler, context switch, preemption, SMP | `13`,`14` |
| 5 | Syscalls, ELF loader, init, busybox shell path | `15`,`31`,`29` |
(io_uring is v2 phase 23, not a v1 phase.)
| 6 | VFS + tmpfs + procfs + sysfs + devtmpfs + ext4 RO | `16`,`19` |
| 7a | Block layer + page cache | `17` |
| 7b | ext4 RW + JBD2 | `17` |
| 8 | Net: loopback, virtio-net, TCP must-run subset | `25` |
| 9 | Hardening, observability, modules (ongoing) | `27`,`37`,`18` |

## 3 Milestone scope by binaries

| Milestone | Includes |
|---|---|
| v1 | busybox shell/core tools, static Go binary, static Rust+tokio binary, redis, nginx (no io_uring), openssh-server, chrony/ntpd (`43§2`) |
| v2 | nginx with io_uring, runc privileged OCI bundle, bpftrace simple probe, perf record/report, cri-o or containerd minimal (`43§3`) |
| v2.x | systemd as PID1, Wayland GUI path, full Docker/Moby path, KVM backend (`43§4`) |
