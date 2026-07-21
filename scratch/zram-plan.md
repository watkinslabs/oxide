# ZRAM Completion Plan

| Status | Item | Branch | Closure evidence |
|---|---|---|---|
| [x] | Linux zcomp owner: descriptor-backed configured priorities, immutable initialized parameters, and per-CPU streams | `B1273-zram-zcomp-owner`, PR #3679, merge `59e968c43` | hosted lifecycle and per-priority tests; x86/aarch64 builds |
| [x] | Zstd `dict=`: configured dictionary must participate in compression and decompression | `B1273-zram-zcomp-owner`, PR #3679, merge `59e968c43` | raw and serialized dictionary frames; mismatch rejection |
| [x] | Linux-produced LZO-RLE/LZ4HC/842 corpus interoperability | `B1276-zram-codec-corpus`, PR #3681, merge `177daec21` | bidirectional fixture evidence |
| [x] | Exact Linux `debug_stat` formatting and direct sysfs contract test | `B1275-zram-debug-stat`, PR #3680, merge `8e1a9583b` | Linux-text fixture |
| [x] | Canonical block discard queue limits, user cap, splitting, and zram queue facts | `B1293-zram-discard-queue` | hosted block/sysfs/zram tests; foreground x86/aarch64 target builds |
