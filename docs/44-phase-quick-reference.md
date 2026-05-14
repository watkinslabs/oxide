# 44 Phase Quick Reference

DRAFT 2026-05-14. Dep:`00`,`40`,`43`.

## 1 Phase gate

| Gate | Required |
|---|---|
| Phase advance | PR-time CI green, bench within budget, coverage gate met (`00§3`,`40§2`) |
| Release tag | PR-time CI green on tag + `43§2` acceptance binaries pass + audit no-regression (`00§15`,`40§3`) |

## 2 Phase ladder (cite `00§3` for authoritative table)

| Phase | Includes | Primary specs |
|---|---|---|
| 0 | Build infra: `xtask`, targets, hello-world boot, CI, Docker image | `07`,`39`,`40` |
| 1 | PMM: buddy, bitmap-truth, oracle diff | `10` |
| 2 | VMM + MMU bring-up, per-CPU areas, TLB shootdown | `11`,`20`,`21` |
| 3 | Slab allocator + `GlobalAlloc` wiring | `12` |
| 4 | Scheduler, context switch, preemption, SMP | `13`,`14` |
| 5 | Syscalls, ELF loader, init, busybox shell path | `15`,`31`,`29` |
| 6 | VFS + tmpfs + procfs + sysfs + devtmpfs + ext4 RO | `16`,`19` |
| 7a | Block layer + page cache | `17` |
| 7b | ext4 RW + JBD2 | `17` |
| 8 | Net: loopback, virtio-net, TCP/UDP, AF_UNIX | `25` |
| 9 | Hardening, observability, klog cfg-gating (ongoing) | `27`,`37`,`18` |
| 10 | Modules loader (ELF ET_REL + relocator + `finit_module`) | `18`,`31` |
| 11 | PCI / PCIe enumeration | `34` |
| 12 | virtio shared infrastructure | `34`,`35` |
| 13 | Real virtio-net live driver | `25`,`35` |
| 14 | mremap real + per-PTE mprotect + file-backed mmap | `11`,`20§7` |
| 15 | AF_INET6 + DHCP + DNS resolver + SCM_CREDS | `25` |
| 16 | Namespaces: unshare/setns/pivot_root + per-NS state | `13`,`16`,`26` |
| 17 | Modern mount API + real mount/umount/chroot | `16` |
| 18 | xattr ext4-backed + ACLs + capability bits on files | `16`,`27` |
| 19 | fanotify_init + fanotify_mark + inotify completeness | `16` |
| 20 | userfaultfd + memfd_secret enforced isolation | `11` |
| 21 | ptrace family completion | `27`,`13` |
| 22 | io_uring (setup/enter/register, fixed buffers, IORING_OP_*) | `30` |
| 23 | bpf + seccomp + landlock (verifier + JIT + hook points) | `27` |
| 24 | SysV IPC + POSIX MQ + keyring | `24` |
| 25 | perf_event_open + tracefs/ftrace + ebpf tracepoints | `27`,`37` |
| 26 | Core dump generation (sigaction SIGSEGV → ELF coredump) | `27`,`16` |
| 27 | Dynamic linker (real ld-musl: PT_INTERP, DT_NEEDED, GOT/PLT, dlopen) | `31`,`29a` |
| 28 | Standard userspace libc + NSS + PAM | `29a`,`43` |
| 29 | System manager (real PID 1, service supervision, journalctl) | `29a` |
| 30 | Package manager (rpmbuild + dnf/microdnf + /var/lib/rpm) | `43`,`29a` |
| 31 | TTY + login flow (agetty, terminfo/ncurses, motd/issue) | `28`,`29a` |
| 32 | DRM/KMS framebuffer + virtio-gpu + input subsystem (evdev) | `35` |
| 33 | vDSO + glibc compat surface (FSGSBASE, IFUNC) | `15` |
| 34 | USB stack | new spec |
| 35 | ACPI runtime + AML interpreter | new spec |
| 36 | KVM / hypervisor backend | new spec |
| 37 | NFS / CIFS / FUSE | new spec |
| 38 | SELinux / AppArmor / IMA — full LSM impls | `27` |
| 39 | DT overlays + full netfilter | new spec |
| 40 | Wayland + GNOME (graphical stack) | `35`, new spec |
| 41 | NUMA + hibernate/S3 + Memory Protection Keys | `10`,`11` |

## 3 Acceptance binary buckets (cite `43§2-§4`)

| Bucket | Binaries |
|---|---|
| Substrate (phases 0–9) | busybox shell/core tools, static Go binary, static Rust+tokio binary, redis, nginx (no io_uring), openssh-server, chrony/ntpd (`43§2`) |
| Async + container (phases 22–26) | nginx with io_uring, runc privileged OCI bundle, bpftrace probe, perf record/report, cri-o or containerd minimal (`43§3`) |
| Distro endgame (phases 27–32) | systemd as PID 1, Wayland GUI path, full Docker/Moby path, KVM backend (`43§4`) |

## 4 Changelog

- 2026-05-14: v1/v2/v2.x framing stripped per `02§9` rule 8. Single phase ladder mirroring `00§3`.
