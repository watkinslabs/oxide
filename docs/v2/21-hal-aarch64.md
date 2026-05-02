# 21 HAL aarch64 — v2 deferred entries

Carried from `docs/21-hal-aarch64.md` at freeze 2026-05-02.

## LPA2 (52-bit PA, 16 KiB granule)

`FEAT_LPA2`. v1 = 48-bit PA + 4 KiB granule. Deferred.

## ACPI vs DT

Both supported. ACPI when EDK2-shipped; DT for U-Boot/embedded. Documented as v1 invariant.

## PAC / BTI enable

`aarch64-unknown-oxide-kernel.json` keeps PAC + BTI off for v1. v1.x toggle.

## MTE (Memory Tagging Extension)

Deferred.
