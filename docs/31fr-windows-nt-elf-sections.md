# Windows NT builtin ELF section publication

FROZEN 2026-09-03. Dep:`31fq`,`31h`,`31v`,`52`,`53`. Provides: the ELF image
metadata boundary used to publish builtin unwind data.

## 1

The loaded-image owner locates `.eh_frame` through the ELF section table,
validates that it is file-backed `SHT_PROGBITS` with `SHF_ALLOC`, and retains
the bounded bytes plus virtual address. Missing `.eh_frame` is a valid image
state; malformed table arithmetic or section bytes fails the image load.

Section metadata does not become a process pointer by itself. The runtime
owner adds the image load bias only after the corresponding PT_LOAD mapping is
established, then performs range validation against that mapping.

## 2

The shared reader supports the little-endian ELF64 images used by both kernel
targets. It does not parse extended section numbering or follow indirect
DWARF encodings. Those operations belong to later, explicitly tested runtime
owners.

Hosted tests cover successful `.eh_frame` discovery and out-of-file rejection;
both architecture checks compile the no-std path.
