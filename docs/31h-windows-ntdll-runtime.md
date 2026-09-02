# Windows NTDLL runtime boundary

FROZEN 2026-08-31. Dep:`01`,`02`,`31a`,`31b`,`31d`,`31e`,`52`,`53`. Provides: PE import binding contract and the first NTDLL-compatible runtime seam.

## 1 Contract

- PE import descriptors are parsed before an NT process becomes visible.
- Each import thunk is either a validated symbol name plus hint or a validated ordinal.
- DLL lookup is owned by the NT runtime provider; the kernel does not search Linux library paths.
- Import address table writes target only writable image pages and occur before the PE entry point runs.
- Missing DLLs or symbols fail PE commit with a native failure; unresolved calls never become null callable pointers.
- The Linux ELF loader has no dependency on the NT runtime provider or import table.

## 2 Runtime provider

| Responsibility | Owner |
|---|---|
| PE descriptor/thunk validation | `shared/pe` |
| image relocation and writable IAT update | `exec::pe_loader` |
| DLL search policy and module lifetime | NT userspace runtime |
| bootstrap NTDLL syscall stubs for native NT services | `exec::pe_loader` |
| full NTDLL API surface and Win32-facing runtime | NT userspace runtime |
| native service implementation | NT syscall adapter |

## 3 Entry state

- PEB/TEB construction precedes imported DLL initialization.
- Runtime initialization receives the mapped image base, PEB, TEB, and NT service entry selector.
- The application entry point runs only after all required imports are resolved.

## 4 Tests

- malformed import descriptors, thunk overflows, unterminated lookup tables, and invalid name RVAs fail without indexing outside the image;
- name and ordinal thunks preserve their exact values;
- loaded module export tables resolve name and ordinal imports to base-plus-RVA addresses, with forwarders left for runtime policy;
- the native NTDLL page owns the bootstrap module in the production catalog; a
  Notepad graph that requires an unimplemented NTDLL export fails transactionally
  instead of silently mapping Wine's NTDLL as a substitute;
- the first x86-64 unary NTDLL stub preserves Windows nonvolatile `RDI`, moves `RCX` into the native first-argument register, and emits the tagged NT selector;
- the six-argument stub translates `RCX,RDX,R8,R9,[RSP+28h],[RSP+30h]` to the native six-register order while preserving Windows nonvolatile registers;
- a validated module set is mapped as one transaction and rolls back every prior image if a later module cannot bind;
- module bases are reserved before binding, so inter-DLL imports resolve against actual ASLR-selected bases rather than preferred-base guesses;
- runtime-owned module blobs provide the explicit DLL search result; the kernel receives copied bytes and never derives a search path from Linux filesystem names;
- a missing runtime binding prevents PE commit;
- Linux ELF process construction remains unchanged when no PE input is present.

## 5 Wine Unix-call boundary

The synthetic NTDLL also publishes Wine's private
`__wine_unix_call_dispatcher` and `__wine_unixlib_handle` data exports. The
dispatcher translates Wine's `(unixlib_handle_t, code, args)` Windows ABI into
the native NT entry; the handle is a nonzero opaque Oxide table identity, never
a user-provided kernel function pointer. The kernel validates that identity
before dispatching a typed Unix operation. Operations requiring Wine's server
protocol or a Unix module loader remain explicit implementation work behind
this boundary.

Tests verify the dispatcher encoding, service decoding, handle validation, and
that the three private runtime exports are distinct, mapped, and backed by the
synthetic NTDLL page.

## 6 Wine server packet bridge

Wine server calls use the mapped request/reply union directly. The native
bridge validates the fixed header, routes by request ID, and writes the reply
header and fixed reply fields back into the same user buffer.

| Request | ID | Native owner | Reply fields |
|---|---:|---|---|
| close handle | 21 | NT handle table | none |
| create event | 30 | NT event + handle table | handle at 8 |
| event operation | 31 | NT event | previous state at 8 |
| query event | 32 | NT event | manual reset at 8, state at 12 |

Fixed request fields follow the 12-byte server header: event access is at 12,
manual-reset at 16, initial-state at 20, and event-operation handle/op at
12/16. Variable request data is rejected until its owning native subsystem is
implemented. Handle close uses the same registry-key cleanup path as native NT
close, preventing a second lifetime owner.

## 7 Wine synchronization objects

Wine server synchronization requests use the same process-local NT handle
table as direct NT calls. Fixed packets are translated without a second object
registry.

| Request | ID | Native owner | Reply |
|---|---:|---|---|
| create/release/query mutex | 36/37/39 | `NtMutant` | handle, prior recursion, state |
| create/release/query semaphore | 40/41/42 | `NtSemaphore` | handle, prior count, current/max |

Unnamed objects are created with Wine’s requested access mask; mutex ownership
uses the current NT thread and semaphore release wakes the native multiple-wait
queue. Variable object-attribute data is a separate packet shape and is
rejected until its native object-namespace translation is wired.

`select` request 23 consumes the required APC-result vector followed by the
operation vector. Wait and wait-all operations are converted to the native
multiple-object wait path, including its handle access checks, signal
consumption, alertable result, and NT timeout conversion. The reply's
`signaled` field is true for any successful wait index, not only index zero.
