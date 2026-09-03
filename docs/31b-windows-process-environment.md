# Windows process environment

FROZEN 2026-08-31. Dep:`01`,`02`,`06`,`11`,`14`,`31a`,`52`. Provides: NT process-environment construction for PE32+.

## 1 Contract

- A PE launch result carries `Nt` personality metadata; ELF launch results remain Linux.
- The environment block is one private, read/write user mapping owned by the process.
- PEB and TEB use stable x86-64 offsets for fields consumed by the initial runtime.
- All pointers stored in the block are user virtual addresses inside the same mapping or the mapped image.
- UTF-16 strings include a trailing NUL and lengths exclude that NUL.
- Command-line and environment conversion rejects embedded NULs and arithmetic overflow.
- The initial Windows stack is 16-byte aligned and reserves the x64 ABI shadow space.
- GS points at the TEB for the first thread; Linux FS/GS state is unchanged for Linux tasks.

## 2 Environment layout

| Object | Required fields |
|---|---|
| PEB | image base, loader data, process parameters, TLS state |
| loader data | executable plus mapped runtime module entries, image bases, image sizes, full/base names |
| process parameters | image path, command line, environment pointer |
| environment | UTF-16 `NAME=VALUE` strings separated by NUL and terminated by NUL |
| TEB | self pointer, PEB pointer, process id, thread id, TLS pointer |

The loader entries are an initial state. DLL discovery remains owned by the NT
runtime provider; when a validated catalog is supplied, the PE initialization
trampoline runs dependency TLS callbacks and attach entry points before the
application entry point.

`NtCreateUserProcess` validates the caller's 88-byte x64 `PS_CREATE_INFO`
record and writes the complete `PsCreateSuccess` union: normalized process
parameters, native PEB address, and explicit zero values for unsupported
section/manifest handles. The process transaction publishes the child only
after this record and the child-owned environment are ready.

## 3 Entry state

`RIP` is the PE entry point, `RSP` is 16-byte aligned below the reserved shadow
space, `GS_BASE` is the TEB address, and the process personality is `Nt`.

## 4 Tests

- PEB/TEB self and cross pointers resolve inside the environment mapping.
- UTF-16 lengths, NUL termination, command line, and environment ordering are exact.
- embedded NUL and overflow inputs fail without mapping a partial environment.
- entry state carries `Nt`, aligned RSP, and TEB GS base.
- Linux ELF loader tests remain unchanged and pass.

`make test` runs the hosted PE, process-environment, and Linux regression gate
automatically. The gate does not modify a disk image or boot the Linux
personality.
