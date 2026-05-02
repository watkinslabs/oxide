# 14 Context-Switch — v2 deferred entries

Carried from `docs/14-context-switch.md` at freeze 2026-05-02 per `02§9.8`.

## Stack-switch atomicity (arm)

Between `mov sp, x9` and the next `ldp` an IRQ would land on the new SP. Safe by HAL design (arm IRQ entry uses `SP_EL1`, set by kernel and never holding a user SP). Verification belongs in `22`; tracked here only so the analysis doesn't get lost.

## GS-base x86 immutability

Per-CPU, not per-task; never saved/restored in switch. Documented so a reviewer doesn't try to "fix" it.

## CET shadow stack / arm GCS

When toolchain OQ resolves to enabling CET / GCS, asm save/restore must keep saved RIP on regular stack and shadow-stack SSP in agreement. Deferred to v1.x.

## arm PAC across migration (ARMv8.3+)

If kernel uses `pac`, saved `lr` is signed with the source thread's key. Cross-CPU migration may need key rotation logic. Deferred to v1.x.
