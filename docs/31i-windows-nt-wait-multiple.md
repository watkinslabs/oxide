# Windows NT multiple-object waits

FROZEN 2026-08-31. Dep:`01`,`02`,`06`,`13`,`31d`,`31f`,`31g`,`52`,`53`. Provides: native wait-any and wait-all ABI and scheduler fanout.

## 1 Contract

- `NtWaitForMultipleObjects` accepts one through 64 process-local handles.
- Its stable oxide service selector is ID `17`; IDs `0` through `16` remain unchanged.
- `WaitAny` returns `STATUS_WAIT_0 + index` for the first signaled object.
- `WaitAll` reports success only when every object is signaled.
- Every handle requires `SYNCHRONIZE` access and resolves to a waitable NT event.
- The process-local fanout wakes multiple-object predicates after event state changes.
- Null, relative, and absolute NT timeout encodings retain the single-object rules.
- Linux wait queues and syscall numbers remain unchanged.

## 2 ABI

| Field | Windows x64 source |
|---|---|
| count | `RCX` |
| handles | `RDX` |
| wait type | `R8D` (`WaitAll=0`, `WaitAny=1`) |
| alertable | `R9D` |
| timeout | stack argument at `RSP+28h` |

## 3 Tests

- service decoding preserves the complete six-register shape;
- the bootstrap NTDLL resolves `NtWaitForMultipleObjects` to an executable stub;
- invalid count, wait type, alertable flag, pointer, access mask, and handle type fail before waiting;
- a signaled wait-any returns the corresponding index;
- wait-all consumes auto-reset event signals only after every predicate is ready;
- event state publication wakes the process-local multiple-object fanout;
- Linux hosted and kernel architecture checks remain green.
