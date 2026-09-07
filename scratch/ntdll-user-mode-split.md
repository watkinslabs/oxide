# NTDLL user-mode split — inventory for the removal lane

Status column tracks each item; Branch names the lane that owns it.

## Measured facts

| Fact | Value | How measured |
|---|---|---|
| Exports the kernel publishes as traps | 533 | `NTDLL_EXPORTS`, `crates/kernel/exec/src/pe_loader.rs:28` |
| x86-64 system services (the only kernel entries the ABI has) | 264 | `pe::ntdll::syscalls::SERVICES`, from the runtime service table |
| Published names that are `Nt*`/`Zw*` | 160 | name split of `NTDLL_EXPORTS` |
| Published names that are library code | 373 | 533 − 160 |
| ntdll names the Notepad closure imports | 505 | `windows-surface-audit.md` |
| …of those, library routines served as traps | 352 | ratchet `usermode-trap ntdll <name>` |
| Names in the pinned 11.16 PE ntdll | 1477 | export-table parse |
| Synthetic names that image does **not** carry | 0 | set difference over all 533 |
| Modules that bind with no kernel export page | 28 | `every_import_binds_against_the_runtime_own_ntdll_image` |

## The two deletion sites

Both reverse together. Reversing only the first leaves the second deleting it again.

| Status | Site | What it does | Branch |
|---|---|---|---|
| OPEN | `tools/build-wine-runtime.sh:92` (lane C1573) | `rm -f "$OUT/x86_64-windows/ntdll.dll"` | |
| OPEN | `tools/xtask/src/rootfs_disks/windows_notepad.rs:71` | stage filter `&& !same_name(path, "ntdll.dll")` | |

## What already prefers the real image

`crates/kernel/exec/src/pe_loader.rs:1100` marks ntdll builtin only when
`source.load(name).is_none()`. With the image staged, the loader takes the real
PE and the synthetic page is never chosen. Three sites then need review because
they assume the synthetic page is the ntdll module:

| Status | Site | Assumption |
|---|---|---|
| OPEN | `pe_loader.rs:1119` | pushes a synthetic `ntdll.dll` module record when none loaded |
| OPEN | `pe_loader.rs:1146` | takes the process exit entry from `resolve_nt_runtime_export("RtlExitUserProcess")` |
| OPEN | `pe_loader.rs:1166` | pushes a synthetic runtime module for exception-table lookup |

The page also carries four things that are **not** exports and do not move with
the library half: the relay stub, `__wine_syscall_dispatcher`,
`__wine_unix_call_dispatcher` and `__wine_unixlib_handle` data slots, the
run-once / wndproc / APC continuations, and the unixlib callable table
(`map_nt_runtime`, `pe_loader.rs:475`).

## The 19 names this lane was asked to implement

None exists in this tree, by name or by behaviour: greps for `Srw`, `SRWLock`,
`ConditionVariable`, `FunctionTable`, `RtlEqualString`, `crc32`, `wcslwr`,
`chkstk` and `SpecificHandler` over `crates/` return nothing. None is published
as a trap, which is why they do not bind. All 19 are exported by the pinned PE
ntdll, pinned by `the_runtime_own_ntdll_image_carries_every_name_the_kernel_page_lacks`.

Sibling routines that **do** exist as kernel services, and so are part of the
373 that the split deletes rather than relocates:

| Missing name | Nearest existing service | Slot |
|---|---|---|
| `RtlEqualUnicodeString` | `RtlCompareUnicodeStrings` (`nt_unicode.rs`) | 343 |
| `RtlCompareString` | `RtlUpperChar` (`nt_rtl_ansi.rs`) | 171 |
| `RtlInitString` | `RtlInitAnsiString` | 62 |
| `RtlCopyUnicodeString` | `RtlUpcaseUnicodeString` | 170 |
| `RtlImageRvaToSection` | `RtlImageRvaToVa` | 222 |
| `RtlWakeConditionVariable` | `RtlSleepConditionVariableCS`/`SRW` | 461/462 |
| `RtlAddFunctionTable` etc. | `RtlLookupFunctionEntry`, `RtlUnwindEx` | 206/210 |
| `__C_specific_handler` | `RtlUnwindEx` | 210 |

## Kernel modules on the wrong side

`nt_rtl*`, `nt_ip_string`, `nt_loader_dir` — the library half. `nt_window`,
`nt_wine_window`, `nt_gdi`, `nt_compositor` are win32k and stay. The `Nt*`
handlers stay.

## The open edge

What the system-service stubs inside the real PE ntdll hit in our guest: our
kernel's NT syscalls directly, or a dispatcher we provide. Not answered here.
