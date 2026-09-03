# Windows NT relay target resolution

FROZEN 2026-09-02. Dep:`01`,`02`,`31h`,`31q`,`52`,`53`. Provides: fail-closed resolution of Wine x86-64 relay entries.

## 1

- Wine patches callable PE export-table entries to relay entry points.
- The native relay service resolves the implementation from the address-space export snapshot first, then Wine's validated private relay metadata.
- A patched EAT entry is never an implementation fallback; returning it would recurse into the relay thunk.
- Missing immutable metadata returns the native procedure-not-found path and cannot produce a null callable target.

## 2

- The snapshot and private metadata are independently validated against the containing module before selection.
- The selection policy is a single shared pure contract so hosted tests exercise the same precedence used by the kernel adapter.

## 3

- Hosted tests cover snapshot precedence, private-metadata fallback, and rejection when both authoritative sources are absent.
- Both target checks compile the kernel adapter; no AArch64 relay workload is implied by the shared contract.
