# 33 Firmware Tables — v2 deferred entries

Carried from `docs/33-firmware-tables.md` at freeze 2026-05-02.

## ACPI on aarch64

Both DT and ACPI supported; chosen per firmware advertisement. Documented as v1 invariant.

## AML interpreter

Not committed for v2. Linux-style AML interpretation is enormous; userspace tools handle laptop power policies (see `32` and userspace `acpid`-equivalent).
