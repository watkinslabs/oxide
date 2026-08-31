# Windows thread environment

FROZEN 2026-08-31. Dep:`01`,`02`,`06`,`13`,`31b`,`31l`,`31m`,`52`,`53`. Provides: per-thread TEB allocation for native NT thread creation.

## 1 Contract

- The PEB and process parameters remain process-owned by the initial NT environment.
- Every `NtCreateThreadEx` child receives a distinct private TEB page in the shared address space.
- TEB self pointer, PEB pointer, process ID, thread ID, and TLS pointer are initialized before publication.
- x86-64 user GS base and AArch64 TPIDR_EL0 in the child context point at that TEB.
- TEB mapping failure rolls back the user stack and leaves no runnable child.

## 2 Tests

- two thread environments in one address space have distinct bases;
- all published TEB pointers and IDs match the requested process/thread identity;
- x86-64 and AArch64 kernel checks compile the same publication path;
- the normal Windows compatibility suite includes the environment allocator tests.
