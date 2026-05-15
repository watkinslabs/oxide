# state — hand-off

Branch: main (clean). K1 + K2 + K6 closed; K3 (fcntl honesty)
is the next batch.

## Closed in this stretch

- #1022 (F25) — K1 finished: ECHOE/ECHOK/ECHONL/ECHOCTL added
  to `tty::pty::lflag`; DEFAULT_LFLAG matches `stty sane`.
  Console VERASE / VKILL echo behavior gated correctly.
- #1023 (F26) — K6 substrate: `pub trait FileBacking` in
  mm-vmm; `VmaBacking::File` carries `Arc<dyn FileBacking>` + off;
  demand-page handler implements File arm via per-inode
  `PageCache` (`kernel/src/syscalls/mmap_file.rs::InodeFileBacking`).
  Unblocks K2 file-backed mmap and K5 core dumps.
- #1024 (D05) — audit refresh: K1/K2/K6 marked done.

## K3 punch list (fcntl + fd flag honesty)

`sys_fcntl` already handles F_DUPFD, F_DUPFD_CLOEXEC, F_GETFD,
F_SETFD, F_GETFL, F_SETFL, F_GETPIPE_SZ, F_SETPIPE_SZ, F_GETOWN,
F_SETOWN. Open gaps:

1. **O_NONBLOCK plumb-through.** F_SETFL stores the flag on the
   File but `File::read` doesn't pass it to `Inode::read`, so
   pipe / pty / tty / socket reads still block.
   - Add `Inode::read_nonblock(&self, off, buf) -> KResult<usize>`
     with default `self.read(off, buf)`.
   - Override in pipe, pty (master + slave), `dev::console::ConsoleInode`,
     socket impls — return `EAGAIN` when no data + no parking.
   - `File::read` dispatches based on `self.flags() & O_NONBLOCK`.
2. **Advisory locks** — F_SETLK / F_GETLK / F_OFD_SETLK / F_OFD_GETLK
   via per-inode range list. musl + tar + dpkg use these.

Hooks: `crates/kernel/vfs/src/inode.rs`, `vfs/src/file.rs`,
`crates/kernel/ipc/src/live/pipe.rs`, `tty/src/pty.rs`,
`kernel/src/dev/console.rs`, `kernel/src/syscalls/net.rs`.

## First task next session

`git checkout -b F27-k3a-nonblock-inode-plumb` then add
`Inode::read_nonblock` default impl in `vfs/src/inode.rs:50` and
thread the flag through `File::read`. Then override in each
blocking inode kind.
