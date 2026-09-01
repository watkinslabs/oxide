# Windows PE module initialization plan

FROZEN 2026-08-31. Dep:`31a`,`31e`,`31p`,`31q`,`52`,`53`. Provides: dependency-first DLL initialization metadata for the NT runtime.

## 1 Contract

- Catalog discovery order is root-first; initialization order is the reverse mapped dependency order, excluding the executable.
- Each initializer carries the actual mapped entry address, so ASLR and relocations are already reflected.
- The native NTDLL bootstrap has no DLL entrypoint and is never included in the initializer list.
- PE commit publishes the process only after the plan is built; a user-mode trampoline calls each initializer with the Windows loader contract before jumping to the application.
- Linux ELF loading has no dependency on this plan.

## 2 Wine relationship

Wine's `user32` startup patches selected NTDLL-forwarded exports such as `DefWindowProcW`. The runtime must initialize dependency DLLs before entering the application, rather than treating static forwarder tables as the final callable surface.

## 3 Tests

- the catalog loader returns dependency-first initializer addresses;
- the initialization trampoline emits Windows x64 process-attach calls and then transfers to the relocated application entry;
- catalog-backed process startup reserves the Windows x64 home space, calls the application entry, and routes a returned status to the native `RtlExitUserProcess` entry;
- the startup continuation ends in an architectural trap if the process-termination entry unexpectedly returns, so a PE task cannot fall through into adjacent mapped bytes;
- runtime-only NTDLL is excluded;
- malformed environment construction still rolls back mapped images and produces no process plan;
- Linux ELF execution remains on its existing path.
