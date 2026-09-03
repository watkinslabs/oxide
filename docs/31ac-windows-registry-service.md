# Windows registry service

FROZEN 2026-08-31. Dep:`01`,`03`,`29a`,`31ab`,`52`,`53`. Provides: one userspace registry owner for the initial Windows runtime.

## 1 Contract

- `userspace/probes/windows-registry` owns registry state; kernel NT objects carry handles and synchronization only. The NT ABI records for the handoff are specified in `31d`.
- Roots are HKLM, HKCU, and HKCR. HKCU state is selected by the launcher’s per-user database path.
- The owner exposes opaque 64-bit process-local key handles; predefined root handles cannot be closed and closed allocated handles become invalid.
- Key and value lookup is case-insensitive and retains first-created display spelling.
- Values retain Windows type tags and opaque byte payloads; UTF-16 conversion belongs to the Win32/advapi32 layer.
- Persistence uses a versioned bounded file format, synced temporary-file replacement, and a synced containing directory. A malformed file is rejected rather than treated as an empty registry.
- A runtime session opens one per-user database, marks mutations dirty, and flushes that same canonical owner explicitly; read-only sessions perform no write.
- The typed service interface routes root and relative open/create, set, query, enumerate-keys, enumerate-values, and close through that session; responses carry the same opaque 64-bit handle, bounded result vectors, or an explicit error.
- Native NT key objects retain the service handle in the scheduler object; the
  service `CLOSE` is sent only when the final duplicated NT handle is removed,
  matching Wine's reference-counted server object lifetime.
- The supported `NtNotifyChangeKey` value-mutation watch is owned by the key
  object, issuing TID, and IOSB; matching cancellation and final-object close
  complete the event and IOSB before removing the watch.
- Hive transactions use a bounded, versioned export/import envelope owned by
  the same service. Export records are subtree-scoped; import validates and
  stages the decoded snapshot before committing it to the target key.
- The userspace `Advapi` adapter exposes the initial `RegOpenKeyExW`, `RegCreateKeyExW`, `RegQueryValueExW`, `RegSetValueExW`, `RegEnumKeyExW`, `RegEnumValueW`, and `RegCloseKey` behavior over the client; it preserves query-size probes, short-buffer `ERROR_MORE_DATA`, default values, no-more-item results, and reserved-argument validation.
- `registryd` exposes that interface over a bounded length-prefixed Unix stream and flushes the same store after each client connection; framing errors never become registry success.
- The native Notepad smoke starts one `registryd` instance for the runtime
  session and exposes its endpoint as `OXIDE_REGISTRY_SOCKET`; the database path
  is `OXIDE_REGISTRY_DATABASE` and remains owned by the service.
- The registry has one source of truth; no kernel shadow database or alternate string-key side channel is permitted.

## 2 Tests

- root creation, nested keys, case-insensitive lookup, and display spelling;
- typed value byte preservation;
- stable key and value enumeration through the framed service;
- Win32 adapter nested-key and query-buffer behavior;
- persistence round-trip;
- malformed-file rejection;
- normal `windows-compat-test` execution.
