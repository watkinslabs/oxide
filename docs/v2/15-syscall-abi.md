# 15 Syscall ABI — v2 deferred entries

Carried from `docs/15-syscall-abi.md` at freeze 2026-05-02.

## aarch64 numbering

v1 = keep x86_64 syscall numbers on both arches. Trade: Linux-compat aarch64 binaries need recompile against our libc. Acceptable; libc-controlled.

## `iopl` / `ioperm` for QEMU debug builds

No. Kernel uses `isa-debug-exit`; userspace doesn't need port I/O.

## `personality` sub-flags

`ADDR_NO_RANDOMIZE` honored (debuggers). Legacy `MMAP_PAGE_ZERO`, `READ_IMPLIES_EXEC` return `EINVAL`.

## `seccomp` filter mode without BPF

v1.0 returns `ENOSYS` (breaks systemd hardening; systemd is v2 anyway). v1.x adds BPF subset.

## Syscall table sizing

Linux today tops out at 462; v1 sizes table to 1024 for future Linux additions.
