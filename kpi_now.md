# KPI handoff - 2026-07-07

Latest lane: `F692-kpi-runtime-utility-glue`
Worktree used: `/home/nd/oxide/worktrees/F692-kpi-runtime-utility-glue`

F692 status:
- Runtime utility exports added in `crates/kernel/modules/src/linux_string/*` and `crates/kernel/modules/src/linux_alloc.rs`.
- KPI headers added/updated for parser, NLS, bitops, slab, string, kernel diagnostics, and compiler attributes.
- `kpi_fix.md` marks F692 `VERIFIED`.
- No arch-owned assembly was added; this lane stays in portable runtime glue.

F692 validation:
- `cargo test -q -p modules linux_string -- --test-threads=1`
- `cargo test -q -p modules -- --test-threads=1`
- `cc -std=gnu11 -Wall -Werror -nostdinc -Ikpi/include -c tools/kpi-header-smoke.c -o /tmp/kpi-header-smoke-host.o`
- `make x86`
- `make arm`
- `make smoke`: both arches completed after vendoring the fresh worktree ARM GRUB modules; arm reached `oxide login:` in 18s.
- `make smoke-x86`: x86 reached `oxide login:` in 12s.
- Fedora 6.16 sample audit now reports 150 missing symbols and no misses for the F692 targets.

Remaining KPI work:
- Biggest missing clusters are still netdev/device-model, DMA/scatterlist, virtqueue/virtio, PCI/resource, block/blk-mq, cpuhp/workqueue, xarray, badblocks, and VFS credential/file helpers.
- `crates/kernel/modules/src/linux_alloc.rs` is near the 500-line cap; split allocator glue before adding more allocator exports.

Publish flow for this lane:
- Commit implementation, fetch/merge fresh `origin/main`, push `F692-kpi-runtime-utility-glue`, open PR, merge with `gh pr merge --merge --delete-branch=true`, fast-forward `/home/nd/oxide/kernel`, then remove the worktree/local branch.
