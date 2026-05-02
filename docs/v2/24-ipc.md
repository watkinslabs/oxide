# 24 IPC — v2 deferred entries

Carried at freeze 2026-05-02.

## Robust-futex list verification

v1 lean = trust the user pointer + return `EFAULT` on fault (vs validating on every access, which costs).

## POSIX message queues (`mq_*`)

v2.

## `eventfd2 EFD_SEMAPHORE`

Copy Linux semantics exactly.

## PI futexes

v1.x.
