# Windows PE execution commit

FROZEN 2026-08-31. Dep:`01`,`02`,`11`,`13`,`14`,`31a`,`31b`,`31c`,`31d`,`52`,`53`. Provides: x86-64 PE selection and process commit at `execve`.

## 1 Contract

- ELF images remain on the existing Linux `execve` path.
- A validated PE32+ image selects the NT personality before Linux ELF stack construction.
- PE commit maps image, stack, PEB/TEB, and process parameters into a private address space.
- PE commit publishes NT task state only after image and environment construction succeeds.
- Failed PE construction leaves the caller's Linux image and task personality unchanged.
- aarch64 rejects Windows PE execution because the supported Windows target is x86-64.

## 2 Entry state

| Field | Source |
|---|---|
| `RIP` | PE optional-header entry RVA plus mapped image base |
| `RSP` | 16-byte aligned stack top below x64 shadow space |
| `GS_BASE` | first-thread TEB |
| task personality | NT marker, separate from Linux `personality(2)` |

## 3 Tests

- PE selection never enters the ELF loader;
- the no-import Hello PE entry sequence is mapped byte-for-byte and targets the native NT terminate selector;
- PEB image base and size match the mapped image, not caller metadata;
- malformed PE/environment input rolls back all mappings;
- Linux kernel target builds remain unchanged;
- x86-64 and aarch64 kernel target checks pass.
