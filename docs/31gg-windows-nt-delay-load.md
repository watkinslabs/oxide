# Windows NT delay-load resolution

FROZEN 2026-09-06. Dep:`31a`,`31aw`,`31fw`,`31h`,`52`,`53`,`54`. Provides:
`LdrResolveDelayLoadedAPI`, the binding step every `-delayload` PE thunk runs
on first call.

## 1

Delay-load thunk contract. A PE built with delayed imports emits, per imported
DLL, a stub that loads the module's `IMAGE_DELAYLOAD_DESCRIPTOR` address and
its own import-address-table slot address, calls the delay-load helper, and
jumps to the returned address. **The return value is an address, not a status**:
the caller jumps to whatever comes back. This service therefore never answers
with an `NTSTATUS`.

| Argument | Windows x64 register | Meaning |
|---|---|---|
| `base` | `RCX` | image base the descriptor's RVAs are relative to |
| `descriptor` | `RDX` | `IMAGE_DELAYLOAD_DESCRIPTOR*` |
| `dllhook` | `R8` | `PDELAYLOAD_FAILURE_DLL_CALLBACK`, may be NULL |
| `syshook` | `R9` | `PDELAYLOAD_FAILURE_SYSTEM_ROUTINE`, may be NULL |
| `thunk` | `[RSP+28h]` | `IMAGE_THUNK_DATA*` — the caller's own IAT slot |
| `flags` | `[RSP+30h]` | reserved; no bit changes resolution |

## 2

`IMAGE_DELAYLOAD_DESCRIPTOR` is eight little-endian `DWORD`s: attributes,
`DllNameRVA`, `ModuleHandleRVA`, `ImportAddressTableRVA`,
`ImportNameTableRVA`, `BoundImportAddressTableRVA`,
`UnloadInformationTableRVA`, `TimeDateStamp`. Every RVA is resolved against
`base`; a zero RVA names no table and fails resolution.

The thunk index is `(thunk - IAT) / 8`. A thunk below the table, misaligned to
an eight-byte entry, or beyond the table bound is a malformed descriptor. The
same index selects both the import-address-table slot written on success and
the import-name-table entry that names the import.

An import-name-table entry with `IMAGE_SNAP_BY_ORDINAL64` set names an
ordinal in its low word. Otherwise the entry is an RVA to an
`IMAGE_IMPORT_BY_NAME`, whose two-byte ordinal hint precedes the
NUL-terminated name.

## 3

Success path, in order:

1. Read the module handle at `base + ModuleHandleRVA`.
2. When it is NULL, load the DLL named at `base + DllNameRVA` through the
   process module loader (`31fw`) and publish the handle into that same slot.
   The loader owns search order, dependency closure, and PEB loader lists; no
   second module table exists.
3. Resolve the import against the module handle by ordinal or by name through
   the single export resolver `LdrGetProcedureAddress` uses (`31aw`).
4. Write the resolved address into `IAT[index]` and return it.

The bound import address table and unload information table are descriptor
metadata this service neither reads nor writes: an image whose bound table is
stale must still resolve against the loaded module.

## 4

Failure path. Resolution fails when the DLL cannot be loaded
(`STATUS_DLL_NOT_FOUND`) or the export is absent
(`STATUS_PROCEDURE_NOT_FOUND`). The failing status is never returned. Control
transfers to a hook, whose return value becomes this service's answer, exactly
as a direct call from the service would:

| Condition | Transfer |
|---|---|
| `dllhook` non-NULL | `dllhook(DELAYLOAD_GPA_FAILURE, &info)` |
| `dllhook` NULL, `syshook` non-NULL | `syshook(dll_name, api)` |
| both NULL | answer NULL |

`api` is the import's name address for a by-name import and the bare ordinal
value for a by-ordinal import. `DELAYLOAD_GPA_FAILURE` is `4`.

`DELAYLOAD_INFO`, x86-64 offsets: `00h` `Size` = `48h`; `08h`
`DelayloadDescriptor`; `10h` `ThunkAddress`; `18h` `TargetDllName`; `20h`
`TargetApiDescriptor.ImportDescribedByName`; `28h`
`TargetApiDescriptor.Description`; `30h` `TargetModuleBase`; `38h` `Unused`
= NULL; `40h` `LastError`. `Description` carries the low word of the raw
import-name-table entry for both import forms.

The structure is written into user-stack storage reserved below the
interrupted stack pointer, above the hook's four home slots, so the hook's own
frame — which grows downward from its entry `RSP` — cannot overwrite the
structure it was handed. The hook returns through the ntdll callback
continuation (`54`), which restores the interrupted frame and delivers the
hook's return value as the service result.

## 5

Test contract, hosted, ungated (`53`, `Phantom tests`): descriptor field
order; RVA resolution rejecting a zero base or absent table; thunk index
arithmetic including misaligned, below-table, and out-of-bound thunks;
eight-byte slot indexing; ordinal-vs-name selection on the snap bit and the
low ordinal word; the two-byte hint skip; every `DELAYLOAD_INFO` field offset
in both import forms; hook precedence and per-hook argument selection; the
no-hook answer being NULL, not a status-valued address; hook-frame
alignment and the info block staying clear of the home area.
