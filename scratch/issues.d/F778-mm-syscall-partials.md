# F778-mm-syscall-partials

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| OPEN | low | `cachestat`'s `nr_writeback` is structurally 0 on both page-cache backends. Not a missing counter: a flush copies frames to the device synchronously inside the requesting call, so no index is ever left tagged writeback-pending for another task to observe. It becomes a real gap only if writeback is ever made asynchronous — at which point the tag has to be added to the ext4 frame store and reported here. | F778; `crates/kernel/ext4/src/rootfs/framecache/cachestat.rs`. | — |
| OPEN | low | `cachestat` eviction shadows exist only for ext4 (the clean-page shrinker) and shmem (swapped indices). A page dropped by `truncate`/hole-punch correctly leaves no shadow, matching Linux, but there is no shadow-entry cap: a workload that repeatedly evicts and truncates a very large sparse file grows the shadow map without bound until the inode is dropped. Linux bounds this by reclaiming shadows with the inode's own shrinker. | F778; `Ext4FrameStore.shadows`. | — |
