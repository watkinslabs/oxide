# 27 Security — v2 deferred entries

Carried at freeze 2026-05-02.

## LSM stacking surface

v1 lean = hook surface stubbed in v1 (~50 callsites; cheap), only Landlock plugged. v2 adds further LSMs (SELinux/AppArmor-equivalent).

## IMA (integrity measurement) / EVM

Deferred to v2.

## KASLR entropy source

`RDRAND` + boot timer mix. Spec'd in v1; listed here only for completeness vs original OQ.

## `kallsyms` for unprivileged

`kptr_restrict=1` default (hide for non-CAP_SYSLOG).
