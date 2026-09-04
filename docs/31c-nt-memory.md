# NT virtual-memory work layer

FROZEN 2026-08-31. Dep:`01`,`02`,`06`,`11`,`31a`,`31b`,`53`. Provides: typed NT memory operations over the common VMM.

## 1 Contract

- The NT work layer accepts typed arguments and never receives Linux syscall registers.
- Allocation uses the common `AddressSpace` VMA service; Linux mappings remain unchanged.
- `allocate` supports advisory base selection and private anonymous reserve/commit.
- `free` requires the exact allocation base and extent supplied by the caller.
- `protect` returns the prior protection and rejects ranges crossing VMA boundaries.
- `query` reports the containing VMA base, extent, current protection, and allocation base.
- `read_current_process` and `write_current_process` accept only the current
  address-space owner; the writable local buffer is validated before source
  access, source faults return `STATUS_PARTIAL_COPY`, and the byte count is the
  successfully completed prefix.
- Invalid ranges and unsupported protection bits return typed NT status values.

## 2 Operations

| Operation | Common service |
|---|---|
| `NtAllocateVirtualMemory` | `AddressSpace::mmap` |
| `NtFreeVirtualMemory` | `AddressSpace::munmap` |
| `NtProtectVirtualMemory` | `AddressSpace::mprotect` |
| `NtQueryVirtualMemory` | VMA snapshot |
| `NtReadVirtualMemory` / `NtWriteVirtualMemory` (current process) | `copy_current_process` |

## 3 Tests

- allocation honors an advisory address and page alignment;
- free rejects partial extents and succeeds for the exact mapping;
- protection returns the old protection and preserves may-protection;
- query reports stable VMA ownership and rejects unmapped addresses;
- Linux ELF/PE loader tests continue to pass.
