# 01 Glossary + Types — v2 deferred entries

Carried from `docs/01-glossary-and-types.md` at freeze 2026-05-02 per `02§9.8`.

## 5-level paging knob

Widen `USER_VA_END` runtime vs per-process flag (`prctl(PR_SET_VA_BITS)`). v1 lean = per-process opt-in. Revisit when 5-level paging hardware presence + workload demand justify the syscall surface.

## Pid reuse / generation

Store generation inside `Pid` (16-bit packed) vs alongside in task struct. v1 lean = alongside; preserves 32-bit ABI. Revisit if pid reuse races become observable.

## Errno 16-bit margin

Invent new errno values beyond Linux's? v1 = no; never. Documented here as the rationale, not as an open question — frozen `15-syscall-abi.md` enforces the Linux number set.

## Caps v3 bits 41+

64-bit capability mask retained. Adding new capabilities is an ABI bump (per `02§2` frozen-section rule). Documented as policy; not actually open.
