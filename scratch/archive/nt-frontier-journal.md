# NT frontier journal (moved from known_issues.md, C320)

Windows frontier update (2026-09-01): the graph test now reports `ntdll.dll!RtlFindActivationContextSectionString`; the directory-object boundary is implemented and the named object namespace remains open.

Windows frontier update (2026-09-01): `RtlFindActivationContextSectionString` now has a validated native ABI boundary; the graph advances to `ntdll.dll!RtlImageDirectoryEntryToData`. Activation-context manifest parsing and process/thread context state remain open.

Windows frontier update (2026-09-01): PE directory and raw-RVA helper boundaries are native; the graph advances through the user-procedure and multibyte conversion pair to `ntdll.dll!ApiSetQueryApiSetPresenceEx`. API-set namespace resolution is now the next loader-critical subsystem.

Windows frontier update (2026-09-01): the API-set presence query now validates names and reports the absent-map result; the graph advances to `ntdll.dll!DbgBreakPoint`. A serialized per-process API-set map and target resolution remain open.

Windows frontier update (2026-09-01): Wine's x86-64 `DbgBreakPoint` (`int3; ret`) is now emitted as a direct native-code export, and `DbgUiConnectToDbg` has an explicit ABI selector; the graph advances to `ntdll.dll!DbgUiContinue`. Debug-object state and continuation semantics remain open.

Windows frontier update (2026-09-01): the remaining Wine debug-UI ABI entries through `DbgUiWaitStateChange` are now represented explicitly; the graph advances to `ntdll.dll!DbgUiConvertStateChangeStructure`. Native debug-object queues and state-change conversion remain open.

Windows frontier update (2026-09-01): API-set contract names are now canonicalized through the shared schema table during dependency discovery, while the same table populates the process PEB namespace; a schema-host regression passes. The installed Notepad graph remains blocked at `DbgUiConvertStateChangeStructure`.

Windows frontier update (2026-09-01): `DbgUiConvertStateChangeStructure` now has an explicit ABI selector and remains intentionally unsupported pending native debug-event structures; the next graph frontier will identify the following NTDLL dependency.

Windows frontier update (2026-09-01): `DbgUiDebugActiveProcess` now has an explicit ABI selector matching Wine's delegation to `NtDebugActiveProcess`; native debug-object attachment remains open.

Windows frontier update (2026-09-01): `LdrAccessResource` now translates mapped-image and raw-data-file resource entries with bounded user accesses; the graph advances to `ntdll.dll!LdrAddDllDirectory`.

Windows frontier update (2026-09-01): `LdrAddDllDirectory` and `LdrRemoveDllDirectory` now maintain process-local absolute UTF-16 directory entries with opaque cookies; the graph advances to `ntdll.dll!LdrAddRefDll`.

Windows frontier update (2026-09-01): the DLL-directory implementation now compiles in the target kernel path and preserves explicit cookie ownership; `LdrAddRefDll` remains the next module-lifetime boundary.

Windows frontier update (2026-09-01): `LdrAddRefDll` now validates canonical PEB loader membership and tracks incremented or pinned process-local module counts; the graph advances to `ntdll.dll!LdrDisableThreadCalloutsForDll`.

Windows frontier update (2026-09-01): `LdrDisableThreadCalloutsForDll` now validates canonical PEB loader membership and records process-local callback suppression; native TLS-index flags remain open, and the graph advances to `ntdll.dll!LdrEnumerateLoadedModules`.

Windows frontier update (2026-09-01): resource directory and data-entry lookup now walk bounded PE32+ resource trees for numeric type/name/language identifiers; named resource ordering and locale fallback remain open, and the graph advances to `ntdll.dll!LdrGetDllHandleEx`.

Windows frontier update (2026-09-01): `LdrGetDllHandleEx` now validates flags, resolves loaded modules through the canonical PEB loader list, supports implicit `.dll`, and applies unchanged/refcount/pin behavior; path-based DLL discovery remains open, and the graph advances to `ntdll.dll!LdrGetDllPath`.

Windows frontier update (2026-09-01): `LdrGetDllPath` now validates flags, builds a bounded UTF-16 search list from process, user, and system directories, allocates it through the NT process heap, and publishes an owned pointer; full DLL probing and exact Wine directory ordering remain open, and the graph advances to `ntdll.dll!LdrSetDefaultDllDirectories`.

Windows frontier update (2026-09-01): `LdrSetDefaultDllDirectories` now validates the documented default-directory mask and stores process-wide loader policy; wiring that policy into path construction remains open, and the graph advances to `ntdll.dll!LdrUnloadDll`.

Windows frontier update (2026-09-01): `LdrUnloadDll` now validates PEB loader membership and decrements or preserves process-local reference state for ordinary and pinned modules; detach callbacks, VMA teardown, and loader-list removal remain open, and the graph advances to `ntdll.dll!NtAccessCheck`.

Windows frontier update (2026-09-01): `LdrGetProcedureAddress` now validates loaded modules and ANSI strings, resolves bounded named and ordinal exports from mapped PE32+ images, resolves named exports from the synthetic native ntdll catalog, and follows bounded forwarders through the current loader list; the graph remains at `ntdll.dll!NtAccessCheck`.

Windows frontier update (2026-09-01): `NtAccessCheck` now uses the preserved Windows-x64 stack tail for its seventh and eighth parameters, validates the token, generic mapping, self-relative DACL, bounded ACE ordering, and publishes granted access/status; full privilege-set semantics and richer token SID membership remain open, and the graph advances to `ntdll.dll!NtAdjustGroupsToken`.

