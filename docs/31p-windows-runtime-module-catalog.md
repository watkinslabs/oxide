# Windows runtime module catalog

FROZEN 2026-08-31. Dep:`01`,`02`,`31a`,`31h`,`52`,`53`. Provides: explicit owned DLL catalog and catalog-backed PE process construction.

## 1 Contract

- The native NT loader owns DLL search policy: it builds the ordered Windows search path from process state and probes each candidate through the canonical VFS.
- A runtime may seed the same catalog with validated PE blobs during process handoff; filesystem probing adds missing modules to that catalog.
- Catalog insertion validates PE32+ format, rejects empty and duplicate names, and preserves insertion order.
- Dependency discovery is case-insensitive and first-seen; cycles are accepted and each module is loaded once.
- Native NTDLL bootstrap modules may be marked built-in and resolved by the fallback resolver without a duplicate blob.
- Catalog-backed process construction maps the discovered graph transactionally, builds loader metadata for every mapped module, and rolls back all mapped images on environment or entry failure.
- The native API-set schema resolves `api-ms-win-core-console-l1-1-0` to `kernelbase.dll`, including imports with or without the `.dll` suffix.
- Linux ELF loading and its search policy remain separate from the NT loader.

## 2 Tests

- invalid and duplicate catalog entries fail before ownership changes;
- recursive catalog discovery preserves owned dependency blobs;
- built-in NTDLL exclusion works with native stub fallback;
- a catalog-backed PE process maps its root image, ordinary Wine DLLs, and the native NTDLL ABI page together;
- native NTDLL exports take precedence for implemented services; the launcher never supplies a second `ntdll.dll` image that could shadow that page;
- the installed Wine Notepad import/DLL contract remains covered by the normal debug suite.
- the console API-set contract resolves to its schema host before catalog lookup.
- filesystem probing preserves candidate order, maps only an absolute `Z:` path into the VFS, rejects malformed PE bytes, and retains the resolved path for loader metadata;
- an alternate Unix `.so` lookup cannot satisfy an NT DLL request.
