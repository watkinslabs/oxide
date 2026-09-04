# Windows NT LdrGetDllPath

FROZEN 2026-09-04. Dep:`01`,`02`,`31h`,`31ax`,`52`,`53`. Provides: native DLL search-path policy for the NT loader.

## 1 Contract

- `LdrGetDllPath` accepts only the documented `LOAD_WITH_ALTERED_SEARCH_PATH` and `LOAD_LIBRARY_SEARCH_*` flag combinations. An altered path cannot be combined with a search-directory flag.
- `LdrSetDefaultDllDirectories` accepts a nonzero subset of application, user, system32, and default-directory bits. The aggregate default bit expands to application, user, and system32 directories before path construction.
- An explicit search-directory flag set replaces the process default. A request with no search-directory mode consumes the process default.
- Application-directory search contributes the directory containing the process image. User-directory search contributes `LdrAddDllDirectory` entries followed by the process-local `LdrSetDllDirectory` override. System32 search contributes the native system directory.
- The path list is constructed in loader order, with duplicate directories removed. The kernel does not consult Linux loader environment state.

## 2 Ownership

| Responsibility | Owner |
|---|---|
| flag validation and aggregate expansion | `nt_loader_dir_policy` |
| process-local defaults and directory state | NT `ThreadGroup` |
| user-memory descriptor and output handling | NT loader adapter |
| PE module discovery and runtime blob selection | NT userspace runtime |

## 3 Tests

- allowed and rejected default flag masks;
- aggregate default expansion;
- explicit request precedence over process defaults;
- altered-path exclusion from search-directory flags;
- policy inputs preserve loader order and duplicate elimination in the native adapter.
