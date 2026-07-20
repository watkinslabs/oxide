## B1268-zram-linux-owner

- `be75cfdb2` commits the ZRAM/swap/MM/block buildout; `feb058036` ignores local boot artifacts.
- Pending commit: resolve ZRAM `backing_dev` in the writer's real VFS context and preserve `ENOTBLK`.
- Builds, tests, QEMU, CI/CD, and pushes remain prohibited by user instruction.
- First task: continue the source-level ZRAM Linux ABI audit, then resume `scratch/network-plan.md`.
