# Windows registry service

FROZEN 2026-09-06. Dep:`01`,`03`,`29a`,`31ab`,`52`,`53`. Provides: one userspace registry owner for the initial Windows runtime.

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
- `NtFlushKey` validates its full 64-bit syscall argument before converting it
  to the native table handle; null, closed, wrong-kind, and unrepresentable
  values return `STATUS_INVALID_HANDLE` and never reach the registry owner.
- The userspace `Advapi` adapter exposes the initial `RegOpenKeyExW`, `RegCreateKeyExW`, `RegQueryValueExW`, `RegGetValueW`, `RegSetValueExW`, `RegDeleteValueW`, `RegEnumKeyExW`, `RegEnumValueW`, and `RegCloseKey` behavior over the client; it preserves query-size probes, short-buffer `ERROR_MORE_DATA`, default values, no-more-item results, type restrictions, string termination, and reserved-argument validation. `RegQueryInfoKeyW` maps the same canonical key metadata to Windows character and byte units.
- `registryd` exposes that interface over a bounded length-prefixed Unix stream. Each successful mutation is atomically committed before its response is sent, and the same store is flushed again at client-session end; framing errors never become registry success.
- The native Notepad smoke starts one `registryd` instance for the runtime
  session and exposes its endpoint as `OXIDE_REGISTRY_SOCKET`; the database path
  is `OXIDE_REGISTRY_DATABASE` and remains owned by the service.
- The registry has one source of truth; no kernel shadow database or alternate string-key side channel is permitted.
- Explicit configured prefix/database/socket paths take precedence. Default mutable paths are per-user: data-home/oxide/windows-prefix, state-home/oxide/registry.db and runtime-dir/oxide/registry.sock. Data/state homes use absolute XDG_DATA_HOME/XDG_STATE_HOME or HOME/.local/share and HOME/.local/state; relative XDG values are ignored. Runtime directory requires absolute XDG_RUNTIME_DIR, user ownership and private permissions, with no global /run or /var/lib fallback. Path selection is configuration, not an authority grant.
- Runtime initialization validates ownership/type/permissions before use, creates private user directories, preserves existing databases and rejects malformed state. Immutable seed content is used only for an absent database; initialization must not overwrite a concurrent owner's database.
- One canonical daemon serves a selected database/socket pair across application lifetimes. Launchers never unlink its live socket or terminate it because one application exits. Only an exclusive database-lock owner may reclaim its stale socket. Socket existence alone is not readiness; clients verify the live service. Concurrent clients must not monopolize acceptance while idle.
- Native registry admission consumes the selected endpoint through canonical caller filesystem/network namespace and socket security checks (`24§9`). No root-credential lookup, guessed endpoint or initial-namespace fallback authorizes a user launch.
- Listener admits at most128 live client workers by default. Every worker shares the same RegistryStore through a sleeping userspace mutex; request read/decode and response encode/write occur outside that mutex, execute/durable flush inside. Idle or partial-frame clients cannot monopolize the database owner or listener. Excess clients close without a success response; worker spawn failure releases the stream and admission permit. Only EOF before a new header is a clean disconnect; truncated headers/payloads fail framing.

## 2 Tests

- root creation, nested keys, case-insensitive lookup, and display spelling;
- typed value byte preservation;
- stable key and value enumeration through the framed service;
- Win32 adapter nested-key and query-buffer behavior;
- Win32 `RegGetValueW` subkey lookup, type filtering, string termination, and zero-on-failure behavior;
- Win32 adapter key metadata counts, length units, and argument validation;
- persistence round-trip;
- malformed-file rejection;
- normal `windows-compat-test` execution.
