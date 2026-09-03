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

## Verification

Hosted tests cover LEB decoding, malformed input, PC-relative addresses, and
CIE/FDE record links. Both x86-64 and aarch64 kernel checks compile the same
no-std parser. Register-rule execution and loaded-module section publication
remain the next runtime-owner work.
