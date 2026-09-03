# Windows NT builtin ELF unwind owner

FROZEN 2026-09-03. Dep:`31fp`,`31v`,`52`,`53`. Provides: the bounded shared
format reader required by the Wine Unix builtin-unwind boundary.

## Contract

Wine locates builtin-module FDEs in loaded ELF `.eh_frame` data and then
interprets the CIE/FDE call-frame instructions. Oxide keeps those layers
separate: `shared::elf::dwarf` validates and indexes bounded records, while a
future runtime owner applies CFA rules to a validated register context.

The reader is little-endian for the ELF targets supported by this project,
rejects truncated and overflowing ULEB/SLEB values, resolves absolute,
PC-relative, and data-relative encoded pointers, and never performs indirect
pointer loads. Indirect encodings and unsupported bases fail closed.

This is intentionally independent of PE `.pdata`/`UNWIND_INFO`: PE modules
continue through the native PE unwind owner in `shared::pe`; Wine builtin ELF
modules use this separate DWARF source.

## Implementation status

The shared owner now exposes `frame_program`: it validates the CIE and FDE
link, decodes the CIE alignment factors and augmentation records, skips the
encoded initial-location/range fields, and returns one bounded instruction
stream containing CIE initialization followed by FDE instructions. This is
the input contract for the runtime CFA owner; it does not load an ELF module,
touch user memory, or manufacture an unwind result.

The ELF execution loader publishes the resulting `.eh_frame` image metadata
through `exec::elf_modules` at the same point it publishes the selected load
bias for the main image and interpreter. Consumers query that owner by
address space and instruction pointer; no consumer reconstructs a module list.

## Verification

Hosted tests cover LEB decoding, malformed input, PC-relative addresses, and
CIE/FDE record links, and the CIE+FDE program join (including the required
zero-length FDE augmentation payload). Both x86-64 and aarch64 kernel checks
compile the same no-std parser. Runtime dispatch still needs to connect this
program to validated Wine Unix requests, loaded-image records, and a
fault-aware user-context owner. Until that owner exists, the validated
request returns Wine's `STATUS_UNSUCCESSFUL` (rather than
`STATUS_NOT_IMPLEMENTED`) so ntdll continues into the native PE unwind owner.
