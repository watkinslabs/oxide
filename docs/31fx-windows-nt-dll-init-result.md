# Windows NT DLL initialization result

FROZEN 2026-09-03. Dep:`31fw`,`31h`,`52`,`53`. Provides: process-start and
dynamic-load handling for PE DLL entry-point results.

## 1

The process-start continuation invokes each dependency initializer with
`(module_base, DLL_PROCESS_ATTACH, NULL)`. TLS callbacks are `void` callbacks;
their return register is ignored. A PE DLL entry point returns `BOOL`.

For a DLL entry point returning `FALSE`, the continuation calls the native
`RtlExitUserProcess` entry with `STATUS_DLL_INIT_FAILED` and does not enter the
application. A successful entry point proceeds to the next initializer, then
the application entry. Dynamic-load continuation returns `STATUS_DLL_INIT_FAILED`
to its suspended `LdrLoadDll` caller on failure and `STATUS_SUCCESS` after all
initializers succeed.

## 2

The initializer kind is carried with the process loader's single initializer
record. The hosted byte-level harness checks the conditional failure branch
and status encoding; target checks compile the actual x86-64 continuation.
