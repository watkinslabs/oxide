# 43 Acceptance — v2 deferred entries

Carried at freeze 2026-05-02.

## Hardware acceptance

v1 ships QEMU-only. Bare-metal validation deferred to v1.x.

## Performance acceptance bar

v1 lean = 50% of bare-Linux on same hardware (not enforced; investigate if regression vs Linux exceeds 10×).

## Static-only vs static+dynamic mix

v1 = static-linked allowed; one dynamically-linked binary in the suite to validate `ld-oxide`.
