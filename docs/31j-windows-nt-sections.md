# Windows NT section objects

FROZEN 2026-08-31. Dep:`01`,`02`,`11`,`13`,`31c`,`31d`,`31f`,`52`,`53`. Provides: anonymous and file-backed section handles and VMA views for the NT personality.

## 1 Contract

- Section, view, and unmap selectors are appended at IDs `18`, `19`, and `20`.
- Section sizes are page-rounded, non-zero, and bounded before allocation.
- Section handles are process-local NT objects with explicit query/map rights.
- Views use the canonical `AddressSpace` VMA placement and teardown paths.
- Initial anonymous views use kernel-owned zero bytes and the VMM private fault path.
- File-backed views retain the originating VFS file and use the same demand-paged `InodeFileBacking` bridge as Linux `mmap`.
- Executable section views and image-specific section attributes remain owned by later PE/DLL image integration.
- Linux ELF mappings and syscall selectors remain unchanged.

## 2 Operations

| Operation | Owner |
|---|---|
| create anonymous or file-backed section | `sched::nt_object` + NT adapter |
| map view | `mm-vmm::AddressSpace` |
| unmap view | `mm-vmm::AddressSpace` |
| section lifetime | process-local handle `Arc` |

## 3 Tests

- section IDs decode without renumbering existing services;
- section backing is zero-filled and retains its exact extent;
- file-section creation retains a file object and maps through the canonical VFS backing;
- invalid size, protection, attributes, process, offset, view, and rights fail before VMA publication;
- view placement writes back the assigned base and size;
- failed copyout removes the newly mapped view;
- unmap accepts only the owning process and exact VMA start;
- Linux hosted and both architecture checks remain green.
