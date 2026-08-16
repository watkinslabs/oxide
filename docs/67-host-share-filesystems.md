# 67 Host-share filesystems (9P, virtiofs)

DRAFT —. Dep:`01`,`02`,`07`,`08`,`15`,`16`,`19`,`34`,`35`,`52`,`53`.

## 1 Purpose

Contract for the two filesystems that mount a directory belonging to the
HYPERVISOR HOST inside this guest: `9p` over the 9P2000 protocol family, and
`virtiofs` over FUSE-on-a-virtqueue. Both are server-backed: no block device,
no on-disk layout, every operation a round trip.

Second-order value: a host share is how a file reaches a running guest without
rebuilding an image, so it is development infrastructure as much as a feature.

## 2 Scope

| In | Out |
|---|---|
| 9P wire codec, all three dialects | RDMA transport |
| 9P client: tags, fids, flush, msize | 9P server (this kernel is a client only) |
| `trans=virtio`, `trans=fd`/`tcp`/`unix` | virtiofs DAX window (`67§9`) |
| 9P VFS: mount, inode, file, readdir, xattr, locks | |
| virtiofs device, queues, FUSE framing | |

## 3 Ownership

| Concern | Crate |
|---|---|
| 9P protocol, client, mount options | `crates/kernel/ninep` |
| 9P VFS glue | `crates/kernel/fs/src/ninep_fs` |
| 9P virtio transport | `crates/drivers/drv-virtio-9p` |
| FUSE transport seam (traits only) | `crates/shared/fuse-transport` |
| FUSE connection, virtiofs superblock | `crates/kernel/fs/src/fuse` |
| virtiofs device | `crates/drivers/drv-virtio-fs` |
| Type registration | `syscalls::fsmount_common::registry` |

Rule: a driver crate never depends on a filesystem crate and a filesystem crate
never depends on a driver crate. Each transport publishes itself into a
directory (`ninep::transport::registry`, `fuse_transport::registry`) that the
filesystem resolves a mount source through. `52§5` rule 22.

## 4 Frozen invariants

1. **One tag matches one reply.** A transaction tag is released only when its
   request can no longer be answered — reply received, or `Rflush`
   acknowledged. A tag freed while the server may still answer is reissued and
   the reply lands on an unrelated caller.
2. **A fid is clunked exactly once.** Clunk hangs off the handle's destructor,
   not off a call site. A handle the server already destroyed (`Tremove`, a
   failed `Tattach`/`Twalk`/`Txattrwalk`) is marked consumed and NOT clunked.
3. **`msize` only shrinks.** The client offers, the server may lower, the
   client adopts the lower. A server answer below the floor (`67§6`) fails the
   handshake; it is never clamped up, which would leave the two sides framing
   to different sizes.
4. **The transport ceiling is applied before the handshake.** A frame the
   transport cannot place in a descriptor chain is not recoverable at the
   protocol layer.
5. **A partial walk is `ENOENT`.** Fewer qids than names means the path does
   not exist. Succeeding on the resolved prefix leaves the handle naming an
   ancestor and every later operation addressing the wrong object.
6. **The dialect match is longest-first.** `9P2000.L` and `9P2000.u` both begin
   with `9P2000`.
7. **`iounit == 0` means no server limit**, not a limit of zero.
8. **The readdir cursor is the server's opaque cookie**, carried per open file
   description, reset only on a rewind to position zero. It is not a byte
   offset and not an entry index.
9. **Inode identity is `qid.path`**, not a reported `st_ino`, which need not be
   unique across the trees one server exports.
10. **An unpopulated attribute field takes the mount default, not zero.** A
    zeroed mode is a file nobody can open; a zeroed uid attributes the object
    to root.
11. **virtiofs is the FUSE connection with a different courier.** One
    `unique` allocator, one reply matcher, one set of `ENOSYS` latches, shared
    with `/dev/fuse`. A second FUSE implementation is forbidden (`02` rule 3).
12. **A virtiofs mount reports `virtiofs`**, not `fuse`, in `/proc/mounts`.

## 5 Message set

`9P2000.L` is what a Linux mount negotiates. Every opcode below is implemented;
`R<op> == T<op> + 1` for every pair.

| Family | Messages |
|---|---|
| Session | `Tversion` `Tauth` `Tattach` `Tflush` |
| Handles | `Twalk` `Tclunk` `Tremove` |
| Data | `Tread` `Twrite` `Treaddir` `Tfsync` |
| `.L` namespace | `Tlopen` `Tlcreate` `Tmkdir` `Tsymlink` `Tmknod` `Tlink` `Tunlinkat` `Trename` `Trenameat` `Treadlink` |
| `.L` metadata | `Tgetattr` `Tsetattr` `Tstatfs` |
| `.L` xattr | `Txattrwalk` `Txattrcreate` |
| `.L` locks | `Tlock` `Tgetlock` |
| Legacy | `Topen` `Tcreate` `Tstat` `Twstat` |

Errors: `Rlerror` carries a numeric errno (`.L`); `Rerror` carries a string
plus, in `.u`, a numeric code. A `.u` code at or above 512 is a Plan 9 error
number in a different namespace and the string is authoritative instead.

## 6 Sizes

| Quantity | Value |
|---|---|
| Header | `size[4] type[1] tag[2]` = 7 |
| I/O envelope | 24 |
| Readdir envelope | 24 |
| Walk elements per message | 16 |
| Default `msize` | 128 KiB + 24 |
| Minimum `msize` | 4096 |
| virtio frame ceiling | `page_size * (128 - 3)` |
| Reserved tag / fid | `0xFFFF` / `0xFFFFFFFF` |

## 7 Mount options (`9p`)

`trans=` `version=` `msize=` `access=` `cache=` `cachetag=` `aname=` `uname=`
`dfltuid=` `dfltgid=` `posixacl` `debug=` `nodevmap` `directio` `noxattr`
`ignoreqv` `afid=` `negtimeout=` `locktimeout=` `rfdno=` `wfdno=` `port=`
`privport` `noextend`.

Derived rules:

| Condition | Effect |
|---|---|
| `.L`, no explicit `access=` | `access=client` |
| `access=client`, dialect not `.L` | falls back to `access=user` |
| `posixacl` without `.L`+`client` | dropped |
| `cache=loose`, no `negtimeout=` | negative names expire after 24 h |
| `trans=fd` without both `rfdno=`/`wfdno=` | `ENOPROTOOPT` |
| unknown option | ignored (mount helpers rely on it) |
| known option, bad value | `EINVAL` |

`cache=` is a BIT SET, not an ordinal: `none`=0, `readahead`=FILE,
`mmap`=FILE|WRITEBACK, `loose`=FILE|META|WRITEBACK|LOOSE, `fscache`=`loose`|FSCACHE.

## 8 virtiofs device

| Item | Value |
|---|---|
| Virtio device ID | 26 |
| Queue 0 | hiprio (FORGET, INTERRUPT) |
| Queue 1 | requests |
| Config | `tag[36]` NUL-PADDED, then `num_request_queues[4]` |

The tag field is padded, not terminated: a 36-byte tag has no NUL and a
C-string read runs into the queue count.

A request is one descriptor chain: the encoded message device-READABLE, then
the reply buffer device-WRITABLE. A hiprio message is submitted with the
readable run only — offering a writable one invites a reply nobody collects.

## 9 Test contract

Hosted, ungated (`53`): every row must be able to fail.

| Area | Check |
|---|---|
| Codec | encode/decode round trip for every primitive and composite body; declared-size mismatch rejected both directions; non-UTF-8 name rejected; over-declared `count` clamped |
| Dirent stream | partial tail reported once, iterator terminates |
| Tags | no reuse while outstanding; exhaustion fails; `NOTAG` reserved and single |
| Fids | clunk exactly once on drop; consumed handle not clunked; number never `NOFID` |
| Version | longest-first dialect match; shrink-only `msize`; below-floor fails |
| Sizing | three-way bound; `iounit==0`; no envelope underflow |
| Errors | `Rlerror`, `Rerror` in both dialects, out-of-range code, wrong reply type |
| Options | every derived rule in `67§7` |
| End to end | attach/walk/open/read/write/readdir/statfs against a scripted server; deep-path chunking; split read and write; no leaked fid or reused tag across long sequences |

Acceptance: a guest mounts a QEMU `-virtfs` export and reads a file the host
wrote (`67§10`).

## 10 OQ

1. Zero-copy `Tread`/`Twrite`: the payload currently passes through a staging
   buffer. Direct page descriptors need a scatter-gather path the split-queue
   owner does not yet expose.
2. Request pipelining: the virtio transport serialises on one staging pair, so
   one request is in flight per mount. The protocol allows many; the tag table
   already supports it.
3. Interrupt-driven completion: both transports poll with a bounded budget
   rather than parking on a queue interrupt.
4. virtiofs DAX window: not taken. Requires a shared-memory region capability
   and an mmap path that maps host pages directly.
5. `trans=fd`/`tcp`/`unix`: the option set and the transport directory admit
   them; no factory registers them yet, so such a mount fails
   `ENOPROTOOPT`.
6. `cache=fscache`: parsed and reported; no persistent backing store exists to
   honour it.
