# 39 Build + Image

FROZEN 2026-05-02. Dep:`02`,`07`,`29`,`36`. Provides:every workflow (`xtask kernel`,`xtask rootfs`,`xtask image`,`xtask qemu`).

## Revision 2026-08-01 (R01)

- Changed: §3 layout, §4 command list, §5 image content, §9 test contract — no userspace is built here. `userspace/libc/musl/`, `userspace/dynlink/`, `userspace/apps/` and `xtask user` are deleted; the root filesystem is a Fedora glibc image composed by `../images` and copied in by `xtask rootfs`. §3 also matches the real grouped crate layout (`52§4`).
- Why: `crates/user/*`, the `xtask glibc`/`sysroot`/`ldso` commands, the `userspace/` build tree, and `vendor/cross` are deleted; spec `59` is deleted with them. The layout block described a tree that has not existed for months.
- Affected code: none — the deletions already landed.
- Test contract change: §9 drops "`xtask user` builds"; adds the boot gate against the Fedora rootfs.

## 1 Purpose

Define workspace layout, `xtask` commands, image-build pipeline (kernel ELF + initramfs + ESP partition), QEMU runner.

## 2 Invariants (frozen)

1. Single Cargo workspace at repo root.
2. Each kernel crate `#![no_std]`.
3. `xtask` is the only build entry point users invoke; CI calls `xtask` only.
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
xtask image     --arch <a>            -> boot.img
xtask qemu      --arch <a> [--gdb] [--smp N] [--mem MB]
xtask test      [--hosted | --kernel | --loom | --miri | --proptest | --all]
xtask bench     --arch <a>
xtask spec-lint                       # CI lints from `08`,`07`
xtask doc-check                       # MANIFEST consistency, frozen-revision-block lints
xtask sign-cert <key.pem>             # generate `OXIDE_TRUSTED_KEYS` for module signing
```

## 5 Image format

`xtask image` produces a GRUB rescue ISO plus a separate root disk — no ESP, no GPT boot image, no initramfs:
1. `oxide-<arch>-grub.iso` (`grub2-mkrescue`): `boot/grub/grub.cfg` + the kernel payload. x86_64 loads `boot/oxide-x86_64` (ELF) with `multiboot2`; aarch64 loads `boot/oxide-aarch64.Image` (EFI-stub arm64 Image) with `linux`. Firmware is SeaBIOS El Torito on x86_64, OVMF on aarch64.
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

`xtask qemu --arch x86_64`:
```
qemu-system-x86_64 \
  -machine q35,accel=kvm -cpu host \
  -m 4G -smp 4 \
  -drive if=pflash,format=raw,unit=0,file=$OVMF_CODE,readonly=on \
  -drive if=pflash,format=raw,unit=1,file=$OVMF_VARS \
  -drive format=raw,file=boot.img \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
  -device virtio-rng-pci \
  -nographic \
  -serial mon:stdio \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04
```

`xtask qemu --arch aarch64`:
```
qemu-system-aarch64 \
  -machine virt -cpu max -m 4G -smp 4 \
  -bios $EDK2_AARCH64 \
  -drive format=raw,file=boot.img,if=virtio \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
  -device virtio-rng-pci \
  -nographic
```

`--gdb` adds `-s -S`.

## 8 Concurrency

`xtask` runs builds in parallel via Cargo's job scheduler. Image build serial post-build.

## 9 Test contract (frozen)

- `xtask kernel --arch x86_64` and `--arch aarch64` succeed clean checkout.
- `xtask rootfs` fails with a clear message when `../images/output/<profile>-<arch>-root.img` is absent.
- `xtask image` produces a `boot.img` whose hash matches across machines (with same toolchain + same rootfs image).
- `make smoke-x86` / `make smoke-arm` boot to `oxide login:`.
- CI runs `xtask spec-lint` and `xtask doc-check`; both pass.

## 10 Failure modes

- Toolchain mismatch: xtask checks `rustc --version` vs `rust-toolchain.toml`; mismatch errors clearly.
- Missing UEFI firmware: xtask provides path hints (`OVMF_CODE`, `EDK2_AARCH64`).

## 11 Debug

`xtask qemu --gdb` + `gdb-multiarch` with kernel ELF + symbol-decoded klog.

## 12 Cross-spec

`07` (toolchain + targets), `29` (userspace), `36` (bootloader handoff), `40` (CI uses xtask).

