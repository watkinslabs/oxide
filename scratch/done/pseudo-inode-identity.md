# Pseudo-inode identity + number-space collisions

Branch `B1610-pseudo-inode-identity`. Follows PR #4272 (`a66f3cf9a`), which fixed
one instance of the class at the cost of a total input outage.

## The class

A pseudo-filesystem mints its own inode numbers from a private `INO_BASE`, then
later answers "is this object mine, and which one?" by doing arithmetic on
`inode.ino()`. Nothing coordinated the bases, and an inode number is not proof
of ownership even when the bases are disjoint — `st_ino` is only unique within
an `st_dev`.

Linux does not do this. `is_file_epoll` compares `f_op` against the one
`eventpoll_fops`; an evdev file is one whose `f_op` is `evdev_fops`. Identity is
the object the inode owns.

Two failure modes, in increasing severity:

1. **Stolen dispatch.** An inode passing a foreign subsystem's numeric test has
   its ioctl consumed by that subsystem, which answers a wrong errno three
   stages before the real owner is consulted.
2. **Type confusion.** A handler that passes the numeric test then dereferences
   the inode's unrelated `private_data` as its own state.

## Collision matrix (pre-B1610)

Reachability is stated as of `96ef4d2d4`.

| Owners | Shared range | Reachable | Consequence |
|---|---|---|---|
| epoll / evdev | `0x7400_0000` (24-bit vs 8-bit mask) | **yes — fired in production** | every evdev ioctl EINVAL from `ep_eventpoll_ioctl`; `epoll_ctl` mutated an unrelated live instance; the evdev mirror gate would have read a foreign `private_data` as `EvdevOpen`. Fixed by #4272. |
| timerfd / bpf | `0x7300_0000` (bpf takes `\|0x01..0x05`, inside timerfd's 24-bit span) | numbers alias; both resolve via `i_private`, so no misresolution | `stat` reports the same `st_ino` for a timerfd and a bpf prog fd. Both are `CharDev` and both fall through to `handle_tty_ioctl`, which never declines — see the `route` row. |
| devpts / cgroup dir | `0x6000_0000` | **no — by luck** | `devpts::pair_for_inode(ino)` is number-only, so a cgroup2 directory inode with a small cgroup id decodes as a PTY master. Unreachable only because the tty ioctl path is gated `CharDev`-only and cgroup dirs are `Directory`. |
| devpts slave / devpts ptmx | `0x6000_FFFE`, `0x6000_FFFF` | needs 32766 ptys | slave index `0x7FFE`/`0x7FFF` alias `PTMX_MOUNT_INO`/`PTMX_ROOT_INO`. |
| procfs dynamic counter / procfs fixed identities | `0x3000_0000` counter vs `0x3000_0D01`, `0x3000_1000`, … | after ~3300 allocations | the runtime counter starts minting numbers that are already a live `/proc` file's identity. |
| `get_next_ino()` (pidfd, POSIX mq, io_uring low half) / console tty band | counter from 1 runs through `0x7400..0x74FF`, `0x7600`, `0x7700` | after ~29696 anon inodes | numeric aliasing with `/dev/console`, `/dev/tty*`, `/dev/vcs*`. |
| tmpfs / eventfd | both based at `0x4000_0000` | separate `st_dev` saves it | tmpfs was never registered anywhere; the two counters walk the same numbers. |
| eventfd counter / binfmt_misc | `0x4000_0000` counter vs `0x4249_0000` | needs ~38M eventfds | — |
| `make_static_file_inode` (`0x3100_0000`) and tracefs ring (`0x3700_0000`) / procfs | inside the procfs band, same `s_dev` | after enough allocations | neither was registered. |
| debugfs (`0x6D00_0000`) / debugfs automount (`0x6D10_0000`) | counter runs into the automount band after ~1M files | — | — |
| `/dev/console` / `/dev/tty1` | both `0x7401` | **yes, always** | the same `st_ino` on the same `st_dev`: nothing could tell the two nodes apart by inode identity. |
| every signalfd / every other signalfd | all shared `0x7200_0000` | **yes, always** | one constant for every instance. Same for inotify groups (`0x7100_0000`). |
| two live sockets | `TAG \| (Arc::as_ptr(sock) & 0xFFFF_FFFF)` | **yes** | a freed socket's address is reused, so two live sockets could carry one `st_ino` — and `ss`, `lsof` and `/proc/net/unix` key on it. |
| cgroup file / debugfs automount | `0x6100_0000 + (cgid<<8)` vs `0x6D10_0000` | needs ~786k cgroups | — |

## Identity-by-arithmetic sites (independent of whether a range collides)

| Site | Test | Verdict |
|---|---|---|
| `fbdev::handle_fbdev_ioctl`, `mmap_backing` | `(ino & 0xFFFF_0000) == 0xFB00_0000`, then `idx = ino & 0xFFFF` | **worst remaining.** Masks only bits 16..31 of the low 32, so the whole high half is ignored: any tagged-family inode whose low half happens to carry `0xFB00_xxxx` passes — a socket inode, whose id is derived from a heap pointer, does so roughly once per 65536 sockets. It runs BEFORE the `CharDev` gate, so a socket fd can reach it. `FbData` was already in `i_private` and unused. |
| `sound::handle_ioctl` | ino tag, then `private::<SndData>()` | tag gate CONSUMES the ioctl with EINVAL when the private state is absent, instead of declining. |
| `devpts::pair_for_inode`, `is_master_inode` | ino band + index | number-only; devpts inodes carried no `i_private` at all. |
| `tty_hangup::resolve` | a THIRD private copy of the devpts band constants, with a mask (`0xFFFF_0000`) that does not agree with devpts' own (`0xFFFF_8000`) | — |
| `console::route` | low byte of ino, final arm `n => Vt(n)` — **never declines** | `handle_tty_ioctl` is the unclaimed-`CharDev` fallback, so a signalfd / inotify / timerfd / bpf fd gets `TIOCGWINSZ`/`TCGETS` answered from a fabricated video VT where Linux answers ENOTTY. |
| `drm::drm_inode_parts_raw` | high-32 tag + card id | DRM inodes carried no `i_private`. |
| `perf::is_perf_inode` | `ino & !INO_ID_MASK == INO_TAG` | inconsistent with `event_of` directly above it, which uses `i_private`. |
| `016_ioctl/core.rs` uffd + perf gates | bare `0x5546_4644_0000_0000` / `0x5045_5246_0000_0000` literals | — |
| `io_uring::ring_of`, `io_uring/register.rs`, `socket/control.rs` | tag mask, with the constant duplicated into `socket/src/ids.rs` | — |
| `cgroup::cgid_from_dir_inode` | ino arithmetic, guarded by `fsid` | `fsid` is a real discriminator, so this one is sound; `CgDirData` was already in `i_private` and unused. |
| `net`/`netlink`/`vsock` socket ino | `TAG \| (Arc::as_ptr(sock) & 0xFFFF_FFFF)` | not an identity test (resolution goes through `i_private`), but a freed socket's address is reused, so two live sockets can carry the same `st_ino` — and `ss`, `lsof` and `/proc/net/unix` key on it. |
| `ext4::is_ext4_ino` | high-32 marker | sound — the low 32 bits are a real on-disk inode number, so nothing else can occupy them. Its doc comment hand-maintained a list of tags it "does not collide with"; that list is now the registry's const assertion. |
| `005_fstat.rs`, `009_mmap.rs`, `mm-*/fault*.rs` `0x6e54` tests | ext4 marker | `#[cfg(feature = "debug-*")] klog` filters only. Not identity. |

## Fix

`crates/kernel/vfs/src/pseudo_ino.rs` is the single owner of the number space:
every region declared in one table, `REGIONS_ARE_DISJOINT` asserted at compile
time, `RegionAllocator` for counter-based minters so a counter cannot run into
its neighbour. Regions reserve NUMBERS; identity stays with `i_private`.

Owners moved to break a collision — the numbers are user-visible via `stat`,
nothing keys off the values:

| Owner | Was | Now |
|---|---|---|
| evdev | `0x7400_0000` | `0x7600_0000` |
| bpf | `0x7300_0000` | `0x7500_0000` |
| devpts | `0x6000_0000` | `0x6900_0000`, with a 14-bit index and a kind field so the ptmx sentinels cannot alias a slave |
| binfmt_misc | `0x4249_0000` | `0x5000_0000` |
| eventfd | `0x4000_0000` | `0x5100_0000` |
| procfs dynamic counter | `0x3000_0000` | `0x3800_0000` |
| `get_next_ino()` | `1` | `0x0200_0000` |
| `/dev/console` | `0x7401` (same as `/dev/tty1`) | `0x74FB` |
| signalfd, inotify | one constant per family | one number per instance |
| AF_INET/UNIX/PACKET, AF_VSOCK, netlink | socket pointer bits | per-family allocator |

Unchanged: epoll, timerfd, pipe, cgroup, tmpfs, autofs, debugfs, ext4, and every
tag family.
