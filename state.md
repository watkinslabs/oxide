## B1268-zram-linux-owner

- `be75cfdb2` commits the ZRAM/swap/MM/block buildout; `feb058036` ignores local boot artifacts; `88cee21fe` resolves `backing_dev` in the writer's real VFS context and preserves `ENOTBLK`.
- Builds, tests, QEMU, CI/CD, and pushes remain prohibited by user instruction.
- First task: continue the source-level swap activation/drain audit, then resume `scratch/network-plan.md`.
