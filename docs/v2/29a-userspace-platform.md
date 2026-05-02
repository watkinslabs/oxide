# 29a Userspace Platform — v2 deferred entries

Carried at freeze 2026-05-02.

## `uname().sysname`

v1 lean = `"Linux"` (max app compatibility — bash version checks etc.). Consistent with `07§3.3` LLVM-target naming. v2 = `"oxide"` once distinct ABI lands.

## musl version pin

v1 = 1.2.5; bump policy follows upstream tags. Documented in `tools/musl-bump.sh` (lands when first musl bump is needed).

## v1.x C++ runtime

v1.x lean = libc++ (LLVM); consistent with rest of toolchain choice.

## Static vs dynamic default for in-tree apps

v1 = static. One demo binary dynamic to validate `ld-oxide`.

## App distribution v1.x

APK vs tarball. Pick deferred.

## Sysroot publication

`xtask user --sysroot` produces `target/sysroot-<arch>/usr/{include,lib}` for external app builds. Documented in `39`.
