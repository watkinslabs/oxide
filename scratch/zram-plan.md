# ZRAM Completion Plan

| Status | Item | Branch | Closure evidence |
|---|---|---|---|
| [~] | Linux zcomp owner: descriptor-backed configured priorities, immutable initialized parameters, and per-CPU streams | `B1273-zram-zcomp-owner` | hosted lifecycle and per-priority tests; x86/aarch64 builds |
| [~] | Zstd `dict=`: configured dictionary must participate in compression and decompression | `B1273-zram-zcomp-owner` | raw and serialized dictionary frames; mismatch rejection |
| [ ] | Linux-produced LZO-RLE/LZ4HC/842 corpus interoperability | — | bidirectional fixture evidence |
| [~] | Exact Linux `debug_stat` formatting and direct sysfs contract test | `B1275-zram-debug-stat` | Linux-text fixture |
