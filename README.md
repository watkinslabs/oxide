# Oxide

[![pr](https://github.com/watkinslabs/oxide/actions/workflows/pr.yml/badge.svg?branch=main)](https://github.com/watkinslabs/oxide/actions/workflows/pr.yml)

Oxide is an experimental operating system written primarily in Rust. It combines an original kernel with established open-source software rather than rebuilding an entire operating-system ecosystem from scratch.

The kernel targets Linux ABI and behavioral compatibility so existing Linux software can run without Oxide-specific ports. Current images boot unmodified Fedora userspace, including glibc, systemd, bash, coreutils, and other RPM-packaged software. Linux compatibility is broad and actively tested, but the project remains under development and is not yet a complete replacement for Linux.

Oxide also has its own glibc-ABI C library and dynamic loader under active development in the sibling `glibc` repository. The roughly 50,000-line Rust libc implementation is intended to provide `libc.so.6`, `ld-linux-*`, static libc, startup objects, and folded-library compatibility artifacts for unmodified GNU/Linux binaries. Fedora glibc remains the default runtime while this implementation matures.

Oxide is also developing native Windows application compatibility. The current work includes PE loading, NT process and memory infrastructure, native `ntdll` services, object and synchronization primitives, and the runtime path needed by real Windows binaries. This surface is experimental and incomplete.

## Project goals

- Run unmodified Linux applications through the Linux syscall ABI and glibc.
- Develop a Rust implementation of the glibc ABI and dynamic loader.
- Support x86_64 and aarch64 as equal targets.
- Add native Windows binary compatibility without compromising the Linux personality.
- Keep kernel behavior aligned with externally defined compatibility contracts.
- Reuse mature open-source userland, packages, boot components, and development tools where appropriate.
- Make correctness measurable through hosted tests, property tests, CI, and QEMU integration tests.

## Architecture

Oxide is not a Linux fork. Its kernel is implemented in Rust with small architecture-specific assembly boundaries and a modular crate layout for memory management, scheduling, filesystems, networking, security, drivers, and compatibility runtimes.

| Layer | Implementation |
|---|---|
| Kernel | Original Rust kernel targeting Linux-compatible behavior |
| Architectures | x86_64 and aarch64 |
| Linux userspace | Unmodified Fedora RPMs using glibc and systemd |
| Oxide libc | In-progress Rust glibc-ABI C library and dynamic loader |
| Windows compatibility | Native PE/NT compatibility runtime under active development |
| Filesystems | VFS with ext4, tmpfs, and Linux-style pseudo-filesystems |
| Devices | PCI, virtio, storage, networking, display, input, audio, serial, and related drivers |
| Validation | Hosted tests, property tests, architecture builds, CI, and QEMU smoke tests |

Third-party projects retain their own licenses and remain separate from Oxide's original kernel code. The root filesystem is composed from upstream Fedora packages; dependency and vendor sources are tracked in their respective project locations.

## Status

Oxide boots on x86_64 and aarch64, runs Linux-compatible userspace, and contains working implementations across core kernel subsystems. Development is ongoing in Linux parity, hardware support, desktop workloads, reliability, and Windows compatibility.

This is research and development software. Expect incomplete APIs, unsupported hardware, compatibility gaps, and breaking changes. It is not intended for production systems.

For current scope and implementation contracts, see:

- [`docs/MANIFEST.md`](docs/MANIFEST.md)
- [`docs/00-master-plan.md`](docs/00-master-plan.md)
- [`docs/29a-userspace-platform.md`](docs/29a-userspace-platform.md)
- [`docs/31a-windows-pe-loader.md`](docs/31a-windows-pe-loader.md)
- [`docs/40-ci.md`](docs/40-ci.md)
- [`docs/42-test-strategy.md`](docs/42-test-strategy.md)

## Build

The repository uses a pinned Rust toolchain and custom kernel targets.

```bash
make build
make qemu-x86
make qemu-arm
```

Image composition and Fedora userspace are managed separately from the kernel repository. See [`docs/39-build-and-image.md`](docs/39-build-and-image.md) for the current build and image workflow.

## License

Oxide's original code is available under the [MIT License](LICENSE). Third-party components are distributed under their respective upstream licenses.
