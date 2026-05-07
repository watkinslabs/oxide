# 31 ELF loader + dynamic linker

FROZEN 2026-05-02. Dep:`01`,`02`,`11`,`12`,`16`,`18`,`27`. Provides:`execve` syscall, module loader (shares parser).
## 1 Purpose

Load ELF64 binaries into an `AddressSpace`. Support static + dynamic (PIE). Establish auxv. Hand off to `_start` or `ld.so` interp.

## 2 Invariants (frozen)

1. Only ELF64 `e_machine` matching HAL arch.
2. PIE only (`ET_DYN` with `INTERP`); also support `ET_EXEC` but emit warning (legacy).
3. PT_LOAD segments mapped with `mmap` (file-backed, MAP_PRIVATE), permissions per `p_flags`. W^X enforced (no segment both W and X).
4. PT_INTERP load: read interp string, recursively load ld.so.
5. Stack: 8 MiB initial, MAP_GROWSDOWN, MAP_STACK; argv/envp/auxv populated at top; SP aligned per ABI (16 on x86, 16 on arm).
6. Brk: initial brk at end of bss, randomized within 32 MiB above (when KASLR on).

## 3 Public ifc

```rust
pub fn load_elf(file:&Arc<dyn Inode>, argv:&[&[u8]], envp:&[&[u8]]) -> KR<LoadedExe>;
pub struct LoadedExe { entry: UVA<u8>, sp: UVA<u8>, brk: UVA<u8>, interp: Option<UVA<u8>> }
```

## 4 Load flow (execve path)

1. Open + read first page; parse `ehdr`.
2. Verify magic, class=ELF64, data=little-endian, machine matches.
3. Walk PHDRs:
   - PT_LOAD → mmap into AS at `p_vaddr` (or `+ load_bias` for PIE).
   - PT_INTERP → read string.
   - PT_DYNAMIC → noted for ld.so.
   - PT_GNU_STACK → set stack exec bit (must be off in v1; W^X).
   - PT_TLS → record `image_size`,`mem_size`,`p_align` for TLS template.
4. If PT_INTERP set:
   - Load interp ELF (recurse).
   - Final entry = interp's `e_entry`.
5. Build stack:
   - argv strings.
   - envp strings.
   - auxv pairs (AT_PHDR, AT_PHENT, AT_PHNUM, AT_PAGESZ, AT_BASE, AT_FLAGS, AT_ENTRY, AT_UID, AT_EUID, AT_GID, AT_EGID, AT_SECURE, AT_RANDOM (16B), AT_HWCAP, AT_PLATFORM, AT_EXECFN, AT_SYSINFO_EHDR — vDSO).
   - argc + argv-pointers + NULL + envp-pointers + NULL + auxv + NULL.
6. Free old AS contents (per `11.fork`-inverse).
7. Set up new task state: entry, sp, fs/tpidr base zero (ld.so will set TLS).

## 5 Dynamic linker (ld.so)

Built as part of userspace at `userspace/dynlink/` against our libc. Installed `/lib/ld-oxide.so.1`.

Responsibilities:
- Map dependent shared libs.
- Resolve symbols (lazy via PLT or eager).
- Run `.init_array`.
- Call program entry.

Not in kernel scope; userspace implementation. Only relevance to kernel: `PT_INTERP` chain + auxv contract.

## 6 Hardening

- ASLR: randomize stack base, mmap base, brk base, ld.so load base. PIE-required for full randomization. v2; v1 ships without ASLR.
- VDSO mapped at randomized va per process.
- `noexec` stack enforced.

## 7 Concurrency

ELF load runs in process context of the execving task. AS replacement is the only thread-affecting step; CLONE_VM peers must be killed first (Linux semantics: execve in multi-threaded process kills siblings).

## 8 Perf budget

| Op | wall |
|---|---|
| Load 1MB static binary | ≤ 5 ms |
| Load 1MB dyn + 5 deps via ld.so | ≤ 20 ms |

Mostly disk-bound; budget is non-disk overhead.

## 9 Test contract (frozen)

- Static busybox loads + runs.
- Dyn busybox + ld-oxide loads + runs.
- Bad e_machine: ENOEXEC.
- Both W&X segment: ENOEXEC.
- PT_INTERP not found: ELIBBAD.
- argv/envp at limit (`E2BIG`): boundary tested.
- AT_RANDOM 16-byte field varies across exec.
- Coverage ≥90%.

## 10 Failure modes

- Bad ELF: ENOEXEC at execve before AS replaced (so old process survives).
- Mid-load mmap failure: rollback (free partial mappings, restore old AS — easy for execve since we built new AS in shadow first).

## 11 Debug

`debug-elf`: per-PHDR trace; auxv dump; reloc trace (in ld.so debug).

## 12 Cross-spec

`11` (mmap), `15` (execve), `18` (shares ELF parser), `23` (vDSO mapping into auxv).

