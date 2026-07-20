## B1268-zram-linux-owner

- `be75cfdb2` commits the ZRAM/swap/MM/block buildout; `feb058036` ignores local boot artifacts; `88cee21fe` resolves `backing_dev` in the writer's real VFS context and preserves `ENOTBLK`; `15f205eba` rolls back stale swapin memcg charges; `c93cbe3f0` removes the production driver-side pathname re-resolution so VFS is the sole backing-device authority.
- `0428e8393` integrates Linux VSOCK DGRAM/SEQPACKET ownership; `4b04028cb` rejects TCP-only `SIOCOUTQNSD` for AF_VSOCK and updates every local `IoctlIntCmd` implementation.
- Builds, tests, QEMU, CI/CD, and pushes remain prohibited by user instruction.
- Network source audit: N27's queue/error/wait protocol is lock-coupled; N11/N23 still need receive-work-layer deadline/restart and compat-layout work, not syscall-shim fallback behavior. Next: continue the N24 ioctl owner/ABI audit or build the required mmsg receive work layer.
