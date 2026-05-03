# vendor/

External binaries we depend on at boot/run time but don't build ourselves.
**Not committed to git** — fetched by `tools/fetch-vendor.sh` (or
`cargo run -p xtask -- vendor`) into checksum-verified per-binary
directories. Keeps repo size down + sidesteps license-redistribution
tracking.

| Path | What | License | Source |
|---|---|---|---|
| `limine/` | Limine ≥ 9.0 binary release tarball — `BOOTX64.EFI` / `BOOTAA64.EFI` / `limine-bios-*` / `limine.c` host tool source | BSD-2-Clause | https://github.com/Limine-Bootloader/Limine/releases |
| `firmware/ovmf-x64.fd` | EDK2 OVMF UEFI firmware, x86_64 | BSD-2-Clause | https://retrage.github.io/edk2-nightly/ |
| `firmware/ovmf-aarch64.fd` | EDK2 OVMF UEFI firmware, aarch64 (QEMU `virt`) | BSD-2-Clause | https://retrage.github.io/edk2-nightly/ |

## How to populate

```
$ ./tools/fetch-vendor.sh
```

Idempotent — skips files that already exist. Pinned versions live at
the top of the script. Re-run after editing those.

## CI

`.github/workflows/pr.yml` runs `tools/fetch-vendor.sh` once and caches
`vendor/` between jobs (per `40§2`). PR-time builds reuse the cache
so we don't hit GitHub's rate limit on every push.
