# Windows PE32+ loader

FROZEN 2026-08-30. Dep:`01`,`02`,`11`,`12`,`16`,`31`. Provides: PE32+ parse and image mapping foundation for the NT personality.

## 1 Contract

- Accept only little-endian PE32+ images for AMD64 (`Machine=0x8664`).
- Reject DOS/PE/header/section arithmetic overflow before indexing the image.
- Preserve the Linux ELF loader path and Linux process personality unchanged.
- Represent section bytes as private VMAs with section-derived read/write/execute protection.
- Map `SizeOfRawData` bytes from `PointerToRawData`; zero-fill the remainder of `VirtualSize`.
- Resolve RVAs through section table ranges; reject RVAs outside headers and sections.
- Apply only `DIR64` base relocations; reject malformed or unsupported relocation entries.
- Expose import descriptors and validated AMD64 name/ordinal thunks, plus
  export, TLS, and x64 exception directory ranges for the NT runtime layer.
- Discover transitive DLL dependencies through an explicit module source with
  cycle detection and missing-module rejection before address-space mapping.
- The image-only mapping API does not execute imported DLL initialization. The catalog-backed NT process builder performs dependency TLS callbacks and attach entry points through the separate PE initialization trampoline after PEB/TEB construction.

## 2 Parse contract

| Field | Required value |
|---|---|
| DOS signature | `MZ` |
| PE signature | `PE\0\0` at `e_lfanew` |
| optional-header magic | `0x20b` |
| machine | `0x8664` |
| sections | non-zero, bounded by the file and header sizes |
| image alignment | power of two, at least page size |
| section alignment | power of two, at least file alignment |
| image size | section-aligned and large enough for headers and sections |
| entry RVA | inside headers or a mapped section |

## 3 Mapping

`load` selects an unused page-aligned base, maps `SizeOfImage`, copies headers and sections into the common VM service, and applies relocations when the selected base differs from `ImageBase`. Section protection is `R`, `W`, and `X` from `IMAGE_SCN_MEM_*`; writable and executable protection together is rejected.

## 4 Tests

- Valid and invalid DOS/PE/optional headers.
- Truncated tables and overflowing offsets.
- Section RVA translation and zero-filled tails.
- Section protection and W+X rejection.
- Relocation application and malformed relocation rejection.
- Directory range validation for imports, exports, TLS, and exception metadata.
- Hosted tests run on both supported kernel architectures; no Linux boot path changes are required for this parser-only foundation.
