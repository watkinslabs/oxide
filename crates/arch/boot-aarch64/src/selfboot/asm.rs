// Module manifest — the aarch64 boot assembly, split by section so no block
// depends on the order the assembly units are concatenated in:
//   header      arm64 Image header + PE32+/EFI header (`.text.boot.header`)
//   trampoline  MMU trampoline and the D-cache flush it calls (`.text.boot`)
//   tables      boot page tables reserved in BSS (`.bss`)

mod header;
mod tables;
mod trampoline;
