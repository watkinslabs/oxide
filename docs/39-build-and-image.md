# 39 Build + Image

FROZEN 2026-05-02. Dep:`02`,`07`,`29`,`36`. Provides:build/image workflows and QEMU entrypoints.

## 1 Purpose

Define workspace layout, `xtask` commands, image-build pipeline (kernel ELF + GRUB ISO + ext4 root disk), QEMU runner.

## 2 Invariants (frozen)

1. Single Cargo workspace at repo root.
2. Each kernel crate `#![no_std]`.
3. `xtask` owns build operations; Makefile owns the composed QEMU and smoke entrypoints.
4. `cargo build` directly with the right target also works (xtask is convenience, not required).
5. Image is reproducible: same source → same hash. SOURCE_DATE_EPOCH respected.

## 3 Workspace layout

```
oxide2/
├── Cargo.toml                    # workspace root
├── rust-toolchain.toml
├── targets/
│   ├── x86_64-unknown-oxide-kernel.json
│   └── aarch64-unknown-oxide-kernel.json
│   # no userspace target: userspace is Fedora RPMs per 29a§2
├── link/
│   ├── x86_64-kernel.ld
│   └── aarch64-kernel.ld
├── docs/                         # specs (this dir)
├── kernel/                       # thin integration crate
├── crates/                       # grouped per 52§4
│   ├── arch/                     # hal-x86_64, hal-aarch64, boot-*, kernel-bin-*
│   ├── kernel/                   # subsystem crates (mm-pmm, mm-vmm, sched, vfs, net, …)
│   ├── drivers/                  # virtio, nvme, ahci, uart, input, gpu
│   └── shared/                   # no_std libraries
├── userspace/                    # kernel conformance probes only (29a§5) — not userland
├── tools/
│   ├── xtask/
│   ├── spec-lint/
│   ├── qemu-mcp/
│   └── boot-smoke.sh + smoke harnesses
├── tests/
│   ├── unit/                     # arch-free hosted #[cfg(test)]
│   ├── integration/              # boots a kernel, runs a userspace test program
│   └── bench/                    # criterion-based microbenchmarks
└── bench-history/, perf-history/
```

Userland lives in the sibling `../images` repo (composition from RPMs) and `../packages` (locally built RPMs). Neither is part of this workspace.

## 4 xtask commands

```
xtask kernel    --arch <a> --profile <p>
xtask artifacts --arch <a>            -> target/artifacts/<a>/kernel.elf
xtask rootfs    --arch <a>            -> root-<a>.img (copy of ../images output)
xtask image     --arch <a>            -> oxide-<arch>-grub.iso
xtask grub      --arch <a> [--smp N] [--features <f>]
xtask test      [--hosted | --kernel | --loom | --miri | --proptest | --all]
xtask bench     --arch <a>
xtask spec-lint                       # CI lints from `08`,`07`
xtask doc-check                       # MANIFEST consistency, spec header/status/xref lints
xtask sign-cert <key.pem>             # generate `OXIDE_TRUSTED_KEYS` for module signing
```

`make qemu-x86` and `make qemu-arm` are the supported QEMU entrypoints. Each
invokes `xtask grub` for its architecture; `make smoke-x86` and `make smoke-arm`
add the serial verdict harness.

## 5 Image format

`xtask image` produces a GRUB rescue ISO plus a separate root disk — no ESP, no GPT boot image, no initramfs:
1. `oxide-<arch>-grub.iso` (`grub2-mkrescue`): `boot/grub/grub.cfg` + the kernel payload. x86_64 loads `boot/oxide-x86_64` (ELF) with `multiboot2` from either SeaBIOS El Torito or x86_64 OVMF; aarch64 loads `boot/oxide-aarch64.Image` (EFI-stub arm64 Image) with `linux` under OVMF.
2. `root-<arch>.img`: ext4 root, attached as virtio-blk and named by the kernel cmdline.

Root filesystem content is Fedora's, composed by `../images` (`29a§2`): `/sbin/init`→systemd, `/lib64/ld-linux-*`, `/lib64/libc.so.6`, `/bin/{bash,…}`, `/etc/*`, empty `/proc`,`/sys`,`/dev`,`/tmp` mount points. This repo adds nothing to it but the conformance probes (`29a§5`).

Built by `xtask`:
- `xtask kernel` + `xtask artifacts` → kernel ELF.
- `xtask rootfs` → copy `../images/output/<profile>-<arch>-root.img`.
- `xtask grub` stages `boot/` + `grub.cfg` and runs `grub2-mkrescue` (aarch64 with `-d vendor/grub/arm64-efi`, fetched by `tools/fetch-vendor.sh`).

## 6 Reproducibility

- All builds set `SOURCE_DATE_EPOCH`.
- Linker uses `--build-id=none` or `--build-id=sha1` deterministic.
- Cpio archives sorted, no atime, fixed UID/GID.
- Image hash committed to `image-history/<commit>.sha256`.

## 7 QEMU invocation

`make qemu-x86` builds and boots the x86_64 GRUB rescue ISO through the
multiboot2 path under SeaBIOS; `OXIDE_QEMU_UEFI=1 make qemu-x86` selects OVMF
and the same GRUB handoff. `make qemu-arm` builds and boots the aarch64 GRUB rescue ISO
through the EFI-stub `linux` path. The runner attaches the ext4 root disk and
passes the architecture's QEMU options; `SMP=<n>` and `FEATURES=<csv>` select
the exposed Makefile controls.

## 8 Concurrency

`xtask` runs builds in parallel via Cargo's job scheduler. Image build serial post-build.

## 9 Test contract (frozen)

- `xtask kernel --arch x86_64` and `--arch aarch64` succeed clean checkout.
- `xtask rootfs` fails with a clear message when `../images/output/<profile>-<arch>-root.img` is absent.
- `xtask image` produces an `oxide-<arch>-grub.iso` whose hash matches across machines (with same toolchain + same rootfs image).
- `make smoke-x86` / `make smoke-arm` boot to `oxide login:`; `OXIDE_QEMU_UEFI=1 make qemu-x86` reaches the x86_64 boot marker through OVMF.
- CI runs `xtask spec-lint` and `xtask doc-check`; both pass.

## 10 Failure modes

- Toolchain mismatch: xtask checks `rustc --version` vs `rust-toolchain.toml`; mismatch errors clearly.
- Missing aarch64 UEFI firmware: xtask provides the `EDK2_AARCH64` path hint.

## 11 Debug

`OXIDE_QEMU_GDB=wait make qemu-x86` or `make qemu-arm`, then `gdb-multiarch`
with the kernel ELF + symbol-decoded klog. `OXIDE_QEMU_GDB_PORT` selects the
otherwise per-launch port.

## 12 Cross-spec

`07` (toolchain + targets), `29` (userspace), `36` (bootloader handoff), `40` (CI uses xtask).
